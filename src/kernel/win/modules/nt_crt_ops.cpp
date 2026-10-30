#include "nt_crt_ops.hpp"
#include "../win_kernel.hpp"
#include "../../../emu/guest_call.hpp"
#include "../../../util/format.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <numeric>
#include <vector>

namespace
{

// Returned rather than thrown: a guest cannot be handed a host exception.
constexpr std::int32_t crt_einval = 22;
constexpr std::int32_t crt_erange = 34;

}

// The host CRT does the work; the pointer-returning ones return a guest address.
void modules::register_ntoskrnl_crt_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The stack probe only touches pages and preserves every register; guest stacks are already mapped.
	// Absent from ARM64, whose kernel exports only __chkstk.
	if (mod.find_symbol("_alloca_probe"))
		state.redirect(mod, "_alloca_probe", [](vcpu&)
		{
			THREAD_LOG_INFO("_alloca_probe");
		});

	state.redirect(mod, "wcslen", [](vcpu&, std::u16string str) -> std::uint64_t
	{
		THREAD_LOG_INFO("wcslen('{}') -> {}", narrow_wstring(str), str.size());
		return str.size();
	});

	state.redirect(mod, "strcmp",
		[](vcpu&, std::string str1, std::string str2) -> std::int32_t
		{
			const auto r = std::strcmp(str1.c_str(), str2.c_str());
			THREAD_LOG_INFO("strcmp('{}', '{}') -> {}", str1, str2, r);
			return r;
		});

	state.redirect(mod, "strncmp",
		[](vcpu&, std::string str1, std::string str2, const std::uint64_t count) -> std::int32_t
		{
			const auto r = std::strncmp(str1.c_str(), str2.c_str(), count);
			THREAD_LOG_INFO("strncmp('{}', '{}', {}) -> {}", str1, str2, count, r);
			return r;
		});

	state.redirect(mod, "_stricmp",
		[](vcpu&, std::string str1, std::string str2) -> std::int32_t
		{
			const auto r = compare_ascii_nocase<char>(str1, str2);
			THREAD_LOG_INFO("_stricmp('{}', '{}') -> {}", str1, str2, r);
			return r;
		});

	state.redirect(mod, "_strnicmp",
		[](vcpu&, std::string str1, std::string str2, const std::uint64_t count) -> std::int32_t
		{
			const auto r = compare_ascii_nocase(str1.c_str(), str2.c_str(),
				std::min<std::size_t>(count, std::min(str1.size(), str2.size()) + 1));
			THREAD_LOG_INFO("_strnicmp('{}', '{}', {}) -> {}", str1, str2, count, r);
			return r;
		});

	// strncpy pads to count with nulls and does not terminate on an exact fill; this does not.
	// The result is a pointer into the caller's own string, so the search runs over the guest's
	// bytes rather than a copy whose address would mean nothing to it.
	state.redirect(mod, "strchr",
		[](vcpu& cpu, const addr_t str, const std::int32_t c) -> addr_t
		{
			if (!str)
				return 0;

			auto& space = *cpu.curr_addr_space();
			const auto wanted = static_cast<char>(c);

			for (addr_t at = str; ; ++at)
			{
				const auto ch = space.read_mem<char>(at);

				if (ch == wanted)
					return at;

				if (!ch)
					return 0;
			}
		});

	state.redirect(mod, "strnlen",
		[](vcpu& cpu, const addr_t str, const std::uint64_t max_count) -> std::uint64_t
		{
			if (!str || !max_count)
				return 0;

			auto& space = *cpu.curr_addr_space();
			std::uint64_t n = 0;

			while (n < max_count && space.read_mem<char>(str + n))
				++n;

			THREAD_LOG_INFO("strnlen(0x{:X}, {}) -> {}", str, max_count, n);

			return n;
		});

	// The _s forms differ from the plain ones by refusing rather than overrunning, and by
	// returning an errno_t instead of the destination.
	state.redirect(mod, "strcpy_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size,
			std::string source) -> std::int32_t
		{
			if (!destination || !size)
				return crt_einval;

			if (source.size() + 1 > size)
			{
				cpu.curr_addr_space()->write_mem<char>(destination, '\0');
				return crt_erange;
			}

			cpu.curr_addr_space()->write_mem(destination, source.c_str(), source.size() + 1);

			THREAD_LOG_INFO("strcpy_s(0x{:X}, {}, '{}') -> 0", destination, size, source);

			return 0;
		});

	state.redirect(mod, "strncpy_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size,
			std::string source, const std::uint64_t count) -> std::int32_t
		{
			if (!destination || !size)
				return crt_einval;

			// _TRUNCATE asks for as much as fits, with room kept for the terminator.
			constexpr auto truncate = ~std::uint64_t{ 0 };
			const auto wanted = count == truncate ? source.size() : std::min(count, source.size());
			const auto room = size - 1;

			if (wanted > room && count != truncate)
			{
				cpu.curr_addr_space()->write_mem<char>(destination, '\0');
				return crt_erange;
			}

			const auto n = std::min(wanted, room);
			std::string out(source, 0, n);
			out.push_back('\0');

			cpu.curr_addr_space()->write_mem(destination, out.data(), out.size());

			THREAD_LOG_INFO("strncpy_s(0x{:X}, {}, '{}', {}) -> {}",
				destination, size, source, count, n < wanted ? crt_erange : 0);

			return n < wanted ? crt_erange : 0;
		});

	state.redirect(mod, "strncpy",
		[](vcpu& cpu, const addr_t destination, std::string source,
			const std::uint64_t count) -> addr_t
		{
			std::string out(count, '\0');
			source.copy(out.data(), std::min<std::size_t>(count, source.size()));

			cpu.curr_addr_space()->write_mem(destination, out.data(), count);

			THREAD_LOG_INFO("strncpy(dest=0x{:X}, '{}', {})", destination, source, count);

			return destination;
		});

	state.redirect(mod, "wcsncpy",
		[](vcpu& cpu, const addr_t destination, std::u16string source,
			const std::uint64_t count) -> addr_t
		{
			std::u16string out(count, u'\0');
			source.copy(out.data(), std::min<std::size_t>(count, source.size()));

			cpu.curr_addr_space()->write_mem(destination, out.data(), count * sizeof(char16_t));

			THREAD_LOG_INFO("wcsncpy(dest=0x{:X}, '{}', {})",
				destination, narrow_wstring(source), count);

			return destination;
		});

	state.redirect(mod, "strstr",
		[](vcpu& cpu, const addr_t str, std::string sub_str) -> addr_t
		{
			const auto haystack = guest::read_string(*cpu.curr_addr_space(), str);
			const auto pos = haystack.find(sub_str);

			const auto found = pos == std::string::npos ? 0 : str + pos;

			THREAD_LOG_INFO("strstr('{}', '{}') -> 0x{:X}", haystack, sub_str, found);

			return found;
		});

	state.redirect(mod, "wcscpy_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			if (source.size() + 1 > size_in_words)
			{
				cpu.curr_addr_space()->write_mem<char16_t>(destination, u'\0');
				return crt_erange;
			}

			guest::write_wstring_buffer(*cpu.curr_addr_space(), destination,
				size_in_words, source);

			THREAD_LOG_INFO("wcscpy_s(dest=0x{:X}, {}, '{}')",
				destination, size_in_words, narrow_wstring(source));

			return 0;
		});

	state.redirect(mod, "wcscat_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			auto& space = *cpu.curr_addr_space();
			const auto existing = guest::read_wstring(space, destination);

			if (existing.size() + source.size() + 1 > size_in_words)
			{
				space.write_mem<char16_t>(destination, u'\0');
				return crt_erange;
			}

			guest::write_wstring_buffer(space, destination, size_in_words, existing + source);

			THREAD_LOG_INFO("wcscat_s(dest=0x{:X}, {}, '{}') -> '{}'", destination,
				size_in_words, narrow_wstring(source), narrow_wstring(existing + source));

			return 0;
		});

	// Take and return an int so that EOF fits, which is why these are not unsigned.
	state.redirect(mod, "tolower", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("tolower({}) -> {}", c, std::tolower(c));
		return std::tolower(c);
	});

	state.redirect(mod, "towlower", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("towlower({}) -> {}", c, std::towlower(static_cast<std::wint_t>(c)));
		return std::towlower(static_cast<std::wint_t>(c));
	});

	state.redirect(mod, "towupper", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("towupper({}) -> {}", c, std::towupper(static_cast<std::wint_t>(c)));
		return std::towupper(static_cast<std::wint_t>(c));
	});

	auto write_formatted = [](vcpu& cpu, const addr_t destination,
		const std::uint64_t count, const std::u16string& text, const bool secure) -> std::int32_t
	{
		auto& space = *cpu.curr_addr_space();

		if (!destination || !count)
			return -1;

		if (text.size() >= count)
		{
			if (secure)
			{
				space.write_mem<char16_t>(destination, u'\0');
				return -1;
			}

			space.write_mem(destination, text.data(), count * sizeof(char16_t));
			return -1;
		}

		guest::write_wstring_buffer(space, destination, count, text);

		THREAD_LOG_INFO("wide format(dest=0x{:X}, count={}) -> '{}'",
			destination, count, narrow_wstring(text));

		return static_cast<std::int32_t>(text.size());
	};

	state.redirect(mod, "_snwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::u16string format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "swprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});

	state.redirect(mod, "_vsnwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "vswprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});

	auto write_counted = [](addr_space& space, const addr_t destination, const std::uint64_t count,
		const std::uint64_t max_count, const auto& text) -> std::int32_t
	{
		constexpr auto truncate = ~std::uint64_t{0};

		if (!destination || !count)
			return crt_einval;

		const auto wanted = max_count == truncate
			? text.size()
			: std::min<std::size_t>(text.size(), max_count);

		if (wanted + 1 <= count)
		{
			guest::write_basic_string_buffer(space, destination, count,
				std::basic_string_view(text).substr(0, wanted));

			return static_cast<std::int32_t>(wanted);
		}

		const auto kept = max_count == truncate ? count - 1 : 0;

		guest::write_basic_string_buffer(space, destination, count,
			std::basic_string_view(text).substr(0, kept));

		return -1;
	};

	state.redirect(mod, "_snprintf_s",
		[write_counted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_bytes,
			const std::uint64_t max_count, std::string format) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vsprintf(space, format, varargs(cpu, 4));
			const auto written = write_counted(space, destination, size_in_bytes, max_count, text);

			THREAD_LOG_INFO("_snprintf_s(dest=0x{:X}, {}, {}) -> '{}' ({})",
				destination, size_in_bytes, max_count, text, written);

			return written;
		});

	state.redirect(mod, "_vsnprintf_s",
		[write_counted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_bytes,
			const std::uint64_t max_count, std::string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vsprintf(space, format, guest::va_list_args(space, arg_list));
			const auto written = write_counted(space, destination, size_in_bytes, max_count, text);

			THREAD_LOG_INFO("_vsnprintf_s(dest=0x{:X}, {}, {}) -> '{}' ({})",
				destination, size_in_bytes, max_count, text, written);

			return written;
		});

	state.redirect(mod, "_vsnwprintf_s",
		[write_counted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			const std::uint64_t max_count, std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			const auto written = write_counted(space, destination, size_in_words, max_count, text);

			THREAD_LOG_INFO("_vsnwprintf_s(dest=0x{:X}, {}, {}) -> '{}' ({})",
				destination, size_in_words, max_count, narrow_wstring(text), written);

			return written;
		});

	// A merge sort: std::sort runs off the end on a comparator that is not a strict weak ordering.
	// The comparator is guest code, so the search calls back into the guest for every probe,
	// exactly as qsort does.
	state.redirect(mod, "bsearch",
		[st](vcpu& cpu, const addr_t key, const addr_t base, const std::uint64_t count,
			const std::uint64_t width, const addr_t comparator) -> addr_t
		{
			if (!key || !base || !width || !comparator || !count)
				return 0;

			std::uint64_t low = 0;
			std::uint64_t high = count;

			while (low < high)
			{
				const auto mid = low + (high - low) / 2;
				const auto at = base + mid * width;

				const std::uint64_t args[] = { key, at };
				const auto order = static_cast<std::int32_t>(
					st->calls.call(cpu, comparator, args));

				if (order == 0)
				{
					THREAD_LOG_INFO("bsearch(key=0x{:X}, base=0x{:X}, count={}, width={}) "
						"-> 0x{:X}", key, base, count, width, at);

					return at;
				}

				if (order < 0)
					high = mid;
				else
					low = mid + 1;
			}

			THREAD_LOG_INFO("bsearch(key=0x{:X}, base=0x{:X}, count={}, width={}) -> not found",
				key, base, count, width);

			return 0;
		});

	state.redirect(mod, "qsort",
		[st](vcpu& cpu, const addr_t base, const std::uint64_t count,
			const std::uint64_t width, const addr_t comparator)
		{
			THREAD_LOG_INFO("qsort(base=0x{:X}, count={}, width={}, comparator=0x{:X})",
				base, count, width, comparator);

			if (!base || !width || !comparator || count < 2)
				return;

			auto& space = *cpu.curr_addr_space();

			std::vector<std::uint8_t> elements(count * width);
			space.read_mem(base, elements.data(), elements.size());

			std::vector<std::size_t> order(count);
			std::iota(order.begin(), order.end(), 0);

			std::stable_sort(order.begin(), order.end(),
				[&](const std::size_t a, const std::size_t b)
				{
					const std::uint64_t args[] = { base + a * width, base + b * width };

					return static_cast<std::int32_t>(
						st->calls.call(cpu, comparator, args)) < 0;
				});

			std::vector<std::uint8_t> sorted(elements.size());

			for (std::size_t i = 0; i < count; ++i)
				std::memcpy(sorted.data() + i * width,
					elements.data() + order[i] * width, width);

			space.write_mem(base, sorted.data(), sorted.size());

			THREAD_LOG_INFO("qsort: {} elements sorted", count);
		});
}
