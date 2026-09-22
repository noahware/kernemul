#pragma once
#include "emu.hpp"
#include "object.hpp"
#include "../util/string.hpp"
#include <functional>
#include <tuple>
#include <type_traits>
#include <utility>

struct calling_conv
{
	virtual ~calling_conv() = default;

	template <typename T>
	T arg(vcpu& cpu, std::size_t index) const
	{
		T v{};
		arg_read(cpu, index, &v, sizeof(v));
		return v;
	}

	template <typename T>
	void ret(vcpu& cpu, const T& val) const
	{
		ret_write(cpu, &val, sizeof(val));
	}

	virtual void set_arg(vcpu& cpu, thread& t, std::size_t index, std::uint64_t value) const = 0;
	virtual void set_ret(vcpu& cpu, thread& t, std::uint64_t value) const = 0;
	virtual void write_arg(vcpu& cpu, std::size_t index, std::uint64_t value) const = 0;
	virtual std::uint64_t read_ret(vcpu& cpu) const = 0;

	// Against the thread's saved context, not the live cpu: an unscheduled thread holds its state.
	virtual void set_ret_addr(vcpu& cpu, thread& t, addr_t addr) const = 0;
	virtual std::uint64_t read_ret(vcpu& cpu, const thread& t) const = 0;

	// The shadow space: the bytes above a callee's return address that belong to the callee
	// rather than to whoever called it, since it may spill its register arguments there before
	// it does anything else. Building a call frame has to leave them clear of everything else
	// in it.
	[[nodiscard]] virtual std::size_t sp_spadow() const { return 0; }

protected:
	virtual void arg_read(vcpu& cpu, std::size_t index, void* buf, std::size_t size) const = 0;
	virtual void ret_write(vcpu& cpu, const void* buf, std::size_t size) const = 0;
};

template <typename T>
struct arg_reader
{
	static T read(vcpu& cpu, const calling_conv& conv, std::size_t index)
	{
		if constexpr (std::is_enum_v<T>)
			return static_cast<T>(conv.arg<std::uint64_t>(cpu, index));
		else
			return conv.arg<T>(cpu, index);
	}
};

template <typename T>
struct arg_reader<emu_object<T>>
{
	static emu_object<T> read(vcpu& cpu, const calling_conv& conv, std::size_t index)
	{
		const auto addr = conv.arg<addr_t>(cpu, index);
		return emu_object<T>(*cpu.curr_addr_space(), addr);
	}
};

template <>
struct arg_reader<std::string>
{
	static std::string read(vcpu& cpu, const calling_conv& conv, std::size_t index)
	{
		const auto addr = conv.arg<addr_t>(cpu, index);
		return guest::read_string(*cpu.curr_addr_space(), addr);
	}
};

template <>
struct arg_reader<std::u16string>
{
	static std::u16string read(vcpu& cpu, const calling_conv& conv, std::size_t index)
	{
		const auto addr = conv.arg<addr_t>(cpu, index);
		return guest::read_wstring(*cpu.curr_addr_space(), addr);
	}
};

template <typename T>
struct ret_writer
{
	static void write(vcpu& cpu, const calling_conv& conv, const T& val)
	{
		conv.ret(cpu, val);
	}
};

template <typename T>
struct ret_writer<emu_object<T>>
{
	static void write(vcpu& cpu, const calling_conv& conv, const emu_object<T>& val)
	{
		conv.ret(cpu, val.address());
	}
};

template <typename T>
struct function_traits;

template <typename R, typename... Args>
struct function_traits<R(*)(Args...)>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) const> : function_traits<R(*)(Args...)> {};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...)> : function_traits<R(*)(Args...)> {};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) const noexcept> : function_traits<R(*)(Args...)> {};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) noexcept> : function_traits<R(*)(Args...)> {};

template <typename T>
struct function_traits : function_traits<decltype(&T::operator())> {};

namespace detail
{

template <typename ArgsTuple>
constexpr bool first_is_vcpu()
{
	if constexpr (std::tuple_size_v<ArgsTuple> == 0)
		return false;
	else
		return std::is_same_v<std::remove_cvref_t<std::tuple_element_t<0, ArgsTuple>>, vcpu>
			&& std::is_lvalue_reference_v<std::tuple_element_t<0, ArgsTuple>>;
}

template <typename ArgsTuple, bool HasVcpu, typename F, std::size_t... I>
void call_with_conv(vcpu& cpu, const calling_conv& conv, F& fn, std::index_sequence<I...>)
{
	using R = typename function_traits<std::decay_t<F>>::return_type;
	constexpr std::size_t off = HasVcpu ? 1 : 0;

	auto conv_args = std::make_tuple(arg_reader<std::tuple_element_t<I + off, ArgsTuple>>::read(cpu, conv, I)...);
	auto all_args = [&]() {
		if constexpr (HasVcpu) return std::tuple_cat(std::tie(cpu), std::move(conv_args));
		else                   return std::move(conv_args);
	}();

	if constexpr (std::is_void_v<R>)
		std::apply(fn, all_args);
	else
		ret_writer<R>::write(cpu, conv, std::apply(fn, all_args));
}

}

// For a routine taking `...`; one handed a va_list uses guest::va_list_args instead.
inline auto varargs(vcpu& cpu, const std::size_t index)
{
	return [&cpu, i = index]() mutable -> std::uint64_t
	{
		return cpu.emu()->call_conv()->arg<std::uint64_t>(cpu, i++);
	};
}

template <typename F>
std::function<void(vcpu&)> make_redirect(std::shared_ptr<const calling_conv> conv, F&& fn)
{
	using traits = function_traits<std::decay_t<F>>;
	using args_tuple = typename traits::args;
	constexpr auto arity = traits::arity;
	constexpr bool has_vcpu = detail::first_is_vcpu<args_tuple>();
	constexpr auto conv_arity = has_vcpu ? arity - 1 : arity;

	return [c = std::move(conv), f = std::forward<F>(fn)](vcpu& cpu) mutable
	{
		detail::call_with_conv<args_tuple, has_vcpu>(
			cpu, *c, f, std::make_index_sequence<conv_arity>{});
	};
}
