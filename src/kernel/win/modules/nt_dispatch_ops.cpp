#include "nt_dispatch_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../object_names.hpp"
#include "../objects.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <array>
#include <limits>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace
{

constexpr std::uint32_t notification_event = 0;

constexpr std::uint32_t event_basic_information = 0;

constexpr std::uint32_t semaphore_basic_information = 0;
constexpr std::uint32_t mutant_basic_information = 0;
constexpr std::uint32_t mutant_owner_information = 1;

#pragma pack(push, 4)
struct event_basic_information_t
{
	std::uint32_t event_type;
	std::int32_t  event_state;
};

struct semaphore_basic_information_t
{
	std::int32_t current_count;
	std::int32_t maximum_count;
};

struct mutant_basic_information_t
{
	std::int32_t current_count;
	std::uint8_t owned_by_caller;
	std::uint8_t abandoned_state;
	std::uint16_t padding;
};
#pragma pack(pop)

win::dispatcher_type kind_of(const win::dispatcher_type type)
{
	return type == win::event_synchronization_object ? win::event_notification_object : type;
}

struct created
{
	NTSTATUS status = STATUS_SUCCESS;
	std::uint64_t handle = 0;
	addr_t address = 0;

	bool existed() const { return status == STATUS_OBJECT_NAME_EXISTS; }
};

created open_named(win_kernel_state& state, const resolved_object_name& name,
	const addr_t existing, const win::dispatcher_type type, const std::uint32_t access)
{
	const auto host = state.objs.get_object<dispatcher_host>(existing);

	if (!host || kind_of(host->type) != kind_of(type))
		return { STATUS_OBJECT_TYPE_MISMATCH };

	const auto handle = state.sys_proc->handle_table().create_handle(existing, access,
		(name.attributes & obj_inherit) ? win_handle_table::flag_inherit : 0);

	if (!handle)
		return { STATUS_INSUFFICIENT_RESOURCES };

	return { STATUS_SUCCESS, handle, existing };
}

template <typename T>
created create_dispatcher(win_kernel_state& state, vcpu& cpu,
	const emu_object<_OBJECT_ATTRIBUTES>& object_attributes, const win::dispatcher_type type,
	const std::int32_t signal_state, const std::uint32_t access)
{
	const auto name = resolve_object_name(state, cpu, object_attributes);

	if (name.status != STATUS_SUCCESS)
		return { name.status };

	if (name.named())
	{
		if (const auto existing = state.objs.lookup_named_object(name.key))
		{
			if (!(name.attributes & obj_openif))
				return { STATUS_OBJECT_NAME_COLLISION };

			auto made = open_named(state, name, existing, type, access);

			if (made.status == STATUS_SUCCESS)
				made.status = STATUS_OBJECT_NAME_EXISTS;

			return made;
		}
	}

	const T zeroed{};
	const auto addr = state.objs.create_object(0, &zeroed, sizeof(T),
		std::make_shared<dispatcher_host>(type, name.name), prot_rw | prot_supervisor);

	if (!addr)
		return { STATUS_INSUFFICIENT_RESOURCES };

	emu_object<T> obj(*state.emulator()->emu().default_addr_space(), addr);
	win::init_dispatcher(obj, type, signal_state);

	if (name.named())
		state.objs.register_named_object(name.key, addr);

	const auto handle = state.sys_proc->handle_table().create_handle(addr, access,
		(name.attributes & obj_inherit) ? win_handle_table::flag_inherit : 0);

	if (!handle)
		return { STATUS_INSUFFICIENT_RESOURCES };

	return { STATUS_SUCCESS, handle, addr };
}

NTSTATUS open_dispatcher(win_kernel_state& state, vcpu& cpu, emu_object<std::uint64_t> out,
	const std::uint32_t access, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes,
	const win::dispatcher_type type)
{
	if (!out)
		return STATUS_INVALID_PARAMETER;

	out.write(0);

	const auto name = resolve_object_name(state, cpu, object_attributes);

	if (name.status != STATUS_SUCCESS)
		return name.status;

	if (!name.named())
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	const auto existing = state.objs.lookup_named_object(name.key);

	if (!existing)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	const auto opened = open_named(state, name, existing, type, access);

	if (opened.status == STATUS_SUCCESS)
		out.write(opened.handle);

	return opened.status;
}

struct resolved
{
	addr_t address = 0;
	std::shared_ptr<dispatcher_host> host;
};

resolved resolve(win_kernel_state& state, const std::uint64_t handle,
	const win::dispatcher_type expected, const std::string_view who)
{
	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, handle);
		return {};
	}

	auto host = state.objs.get_object<dispatcher_host>(entry->body_addr);

	if (!host)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not a dispatcher object", who, handle);
		return {};
	}

	const bool event_pair = (expected == win::event_notification_object
			|| expected == win::event_synchronization_object)
		&& (host->type == win::event_notification_object
			|| host->type == win::event_synchronization_object);

	if (host->type != expected && !event_pair)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} names a type {} object, not {}",
			who, handle, static_cast<int>(host->type), static_cast<int>(expected));
		return {};
	}

	return { entry->body_addr, std::move(host) };
}

constexpr std::size_t keyed_event_body_size = 0x40;

struct keyed_event_host final : win_object
{
	struct gate
	{
		addr_t arrivals = 0;
		addr_t releases = 0;
	};

	gate gate_for(win_kernel_state& state, const addr_t key)
	{
		std::scoped_lock lock(mtx_);

		auto& found = gates_[key];

		if (!found.arrivals)
			found = { make_semaphore(state), make_semaphore(state) };

		return found;
	}

private:
	static addr_t make_semaphore(win_kernel_state& state)
	{
		const _KSEMAPHORE zeroed{};
		const auto addr = state.objs.create_object(0, &zeroed, sizeof(zeroed),
			{}, prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		const emu_object<_KSEMAPHORE> obj(
			*state.emulator()->emu().default_addr_space(), addr);

		win::init_dispatcher(obj, win::semaphore_object, 0);
		obj.field(&_KSEMAPHORE::Limit).write(std::numeric_limits<std::int32_t>::max());

		return addr;
	}

	std::mutex mtx_;
	std::unordered_map<addr_t, gate> gates_;
};

// KEVENT_PAIR: a type and size, then two synchronization events, one for each side of the pair.
constexpr std::size_t event_pair_body_size = 0x38;
constexpr std::size_t event_pair_low_offset = 0x08;
constexpr std::size_t event_pair_high_offset = 0x20;

struct event_pair_host final : win_object
{
	std::string name;
};

std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// The body behind each handle is the real KEVENT, KSEMAPHORE or KMUTANT.
void modules::register_ntoskrnl_dispatch_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto create_event = [st](vcpu& cpu, emu_object<std::uint64_t> event_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint32_t event_type, const bool initial_state) -> NTSTATUS
	{
		if (!event_handle)
			return STATUS_INVALID_PARAMETER;

		const auto type = event_type == notification_event
			? win::event_notification_object : win::event_synchronization_object;

		const auto made = create_dispatcher<_KEVENT>(*st, cpu, object_attributes, type,
			initial_state ? 1 : 0, desired_access);

		if (!made.handle)
			return made.status;

		event_handle.write(made.handle);

		THREAD_LOG_INFO("NtCreateEvent({}, state={}) -> handle=0x{:X}",
			event_type == notification_event ? "notification" : "synchronization",
			initial_state, made.handle);

		return made.status;
	};

	state.redirect_ntzw(mod, "OpenEvent",
		[st](vcpu& cpu, emu_object<std::uint64_t> event_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			return open_dispatcher(*st, cpu, std::move(event_handle), desired_access,
				object_attributes, win::event_notification_object);
		});

	auto set_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object, "NtSetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 1);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtSetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), event.address());

		return STATUS_SUCCESS;
	};

	auto reset_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtResetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 0);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtResetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		return STATUS_SUCCESS;
	};

	auto clear_event = [st](vcpu& cpu, const std::uint64_t event_handle) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtClearEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		win::set_signal_state(event, 0);

		THREAD_LOG_INFO("NtClearEvent(0x{:X}, '{}')", event_handle, found.host->name);

		return STATUS_SUCCESS;
	};

	auto query_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		const std::uint32_t event_information_class, const addr_t event_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtQueryEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (event_information_class != event_basic_information)
		{
			THREAD_LOG_WARN("NtQueryEvent: unhandled class {}", event_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		if (return_length)
			return_length.write(sizeof(event_basic_information_t));

		if (length < sizeof(event_basic_information_t))
			return STATUS_INFO_LENGTH_MISMATCH;

		auto& space = *cpu.curr_addr_space();
		const emu_object<_KEVENT> event(space, found.address);

		event_basic_information_t info{};
		info.event_type = found.host->type == win::event_notification_object ? 0 : 1;
		info.event_state = win::signal_state(event);

		emu_object<event_basic_information_t>(space, event_information).write(info);

		THREAD_LOG_INFO("NtQueryEvent(0x{:X}, '{}') -> type={}, state={}",
			event_handle, found.host->name, info.event_type, info.event_state);

		return STATUS_SUCCESS;
	};

	auto create_semaphore = [st](vcpu& cpu, emu_object<std::uint64_t> semaphore_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::int32_t initial_count, const std::int32_t maximum_count) -> NTSTATUS
	{
		if (!semaphore_handle)
			return STATUS_INVALID_PARAMETER;

		if (maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count)
			return STATUS_INVALID_PARAMETER;

		const auto made = create_dispatcher<_KSEMAPHORE>(*st, cpu, object_attributes,
			win::semaphore_object, initial_count, desired_access);

		if (!made.handle)
			return made.status;

		// The limit lives past the dispatcher header, and KeReleaseSemaphore checks against it.
		if (!made.existed())
			emu_object<_KSEMAPHORE>(*cpu.curr_addr_space(), made.address)
				.field(&_KSEMAPHORE::Limit).write(maximum_count);

		semaphore_handle.write(made.handle);

		THREAD_LOG_INFO("NtCreateSemaphore(initial={}, maximum={}) -> handle=0x{:X}",
			initial_count, maximum_count, made.handle);

		return made.status;
	};

	auto release_semaphore = [st](vcpu& cpu, const std::uint64_t semaphore_handle,
		const std::int32_t release_count, emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, semaphore_handle, win::semaphore_object,
			"NtReleaseSemaphore");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (release_count <= 0)
			return STATUS_INVALID_PARAMETER;

		emu_object<_KSEMAPHORE> semaphore(*cpu.curr_addr_space(), found.address);

		const auto previous = win::signal_state(semaphore);
		const auto limit = semaphore.field(&_KSEMAPHORE::Limit).read();

		if (previous + release_count > limit)
		{
			THREAD_LOG_WARN("NtReleaseSemaphore(0x{:X}, '{}'): {} + {} is past the limit of {}",
				semaphore_handle, found.host->name, previous, release_count, limit);

			return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
		}

		win::set_signal_state(semaphore, previous + release_count);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseSemaphore(0x{:X}, '{}', release={}) -> was {}",
			semaphore_handle, found.host->name, release_count, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), semaphore.address());

		return STATUS_SUCCESS;
	};

	// A mutant is signalled when nobody holds it: unowned starts at one, owned at zero.
	auto create_mutant = [st](vcpu& cpu, emu_object<std::uint64_t> mutant_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const bool initial_owner) -> NTSTATUS
	{
		if (!mutant_handle)
			return STATUS_INVALID_PARAMETER;

		const auto made = create_dispatcher<_KMUTANT>(*st, cpu, object_attributes,
			win::mutant_object, initial_owner ? 0 : 1, desired_access);

		if (!made.handle)
			return made.status;

		if (initial_owner && !made.existed())
		{
			const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
			const auto ethread = t ? t->ethread().address() : 0;

			emu_object<_KMUTANT>(*cpu.curr_addr_space(), made.address)
				.field(&_KMUTANT::OwnerThread)
				.write(guest_ptr<_KTHREAD>(ethread));
		}

		mutant_handle.write(made.handle);

		THREAD_LOG_INFO("NtCreateMutant(initial_owner={}) -> handle=0x{:X}", initial_owner,
			made.handle);

		return made.status;
	};

	auto release_mutant = [st](vcpu& cpu, const std::uint64_t mutant_handle,
		emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, mutant_handle, win::mutant_object, "NtReleaseMutant");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KMUTANT> mutant(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(mutant);

		if (previous > 0)
		{
			THREAD_LOG_WARN("NtReleaseMutant(0x{:X}, '{}'): nobody holds it",
				mutant_handle, found.host->name);

			return STATUS_MUTANT_NOT_OWNED;
		}

		win::set_signal_state(mutant, previous + 1);
		mutant.field(&_KMUTANT::OwnerThread).write(nullptr);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseMutant(0x{:X}, '{}') -> was {}",
			mutant_handle, found.host->name, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), mutant.address());

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateEvent", create_event);
	state.redirect_ntzw(mod, "SetEvent", set_event);
	state.redirect_ntzw(mod, "ResetEvent", reset_event);
	state.redirect_ntzw(mod, "ClearEvent", clear_event);
	state.redirect_ntzw(mod, "QueryEvent", query_event);
	state.redirect_ntzw(mod, "CreateSemaphore", create_semaphore);
	state.redirect_ntzw(mod, "ReleaseSemaphore", release_semaphore);
	state.redirect_ntzw(mod, "CreateMutant", create_mutant);
	state.redirect_ntzw(mod, "ReleaseMutant", release_mutant);

	state.redirect_ntzw(mod, "OpenSemaphore",
		[st](vcpu& cpu, emu_object<std::uint64_t> semaphore_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			return open_dispatcher(*st, cpu, std::move(semaphore_handle), desired_access,
				object_attributes, win::semaphore_object);
		});

	state.redirect_ntzw(mod, "OpenMutant",
		[st](vcpu& cpu, emu_object<std::uint64_t> mutant_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			return open_dispatcher(*st, cpu, std::move(mutant_handle), desired_access,
				object_attributes, win::mutant_object);
		});

	state.redirect_ntzw(mod, "QuerySemaphore",
		[st](vcpu& cpu, const std::uint64_t semaphore_handle,
			const std::uint32_t semaphore_information_class, const addr_t semaphore_information,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto found = resolve(*st, semaphore_handle, win::semaphore_object,
				"NtQuerySemaphore");

			if (!found.address)
				return STATUS_INVALID_HANDLE;

			if (semaphore_information_class != semaphore_basic_information)
				return STATUS_INVALID_INFO_CLASS;

			if (length < sizeof(semaphore_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			auto& space = *cpu.curr_addr_space();
			const emu_object<_KSEMAPHORE> semaphore(space, found.address);

			semaphore_basic_information_t info{};
			info.current_count = win::signal_state(semaphore);
			info.maximum_count = semaphore.field(&_KSEMAPHORE::Limit).read();

			emu_object<semaphore_basic_information_t>(space, semaphore_information).write(info);

			if (return_length)
				return_length.write(sizeof(info));

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "QueryMutant",
		[st](vcpu& cpu, const std::uint64_t mutant_handle,
			const std::uint32_t mutant_information_class, const addr_t mutant_information,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto found = resolve(*st, mutant_handle, win::mutant_object, "NtQueryMutant");

			if (!found.address)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();
			const emu_object<_KMUTANT> mutant(space, found.address);

			const auto owner = guest_va(mutant.field(&_KMUTANT::OwnerThread).read());

			switch (mutant_information_class)
			{
			case mutant_basic_information:
			{
				if (length < sizeof(mutant_basic_information_t))
					return STATUS_INFO_LENGTH_MISMATCH;

				const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

				mutant_basic_information_t info{};
				info.current_count = win::signal_state(mutant);
				info.owned_by_caller = owner && t && t->ethread().address() == owner;
				info.abandoned_state = mutant.field(&_KMUTANT::MutantFlags).read() & 1;

				emu_object<mutant_basic_information_t>(space, mutant_information).write(info);

				if (return_length)
					return_length.write(sizeof(info));

				return STATUS_SUCCESS;
			}

			case mutant_owner_information:
			{
				if (length < sizeof(_CLIENT_ID))
					return STATUS_INFO_LENGTH_MISMATCH;

				if (!owner)
					return STATUS_INVALID_PARAMETER;

				const auto t = st->find_ethread(emu_object<_ETHREAD>(space, owner));

				if (!t)
					return STATUS_INVALID_PARAMETER;

				emu_object<_CLIENT_ID>(space, mutant_information).write(t->client_id().read());

				if (return_length)
					return_length.write(sizeof(_CLIENT_ID));

				return STATUS_SUCCESS;
			}

			default:
				return STATUS_INVALID_INFO_CLASS;
			}
		});

	auto default_keyed_event = std::make_shared<keyed_event_host>();

	auto keyed_event_from_handle = [st, default_keyed_event](const std::uint64_t handle)
		-> std::shared_ptr<keyed_event_host>
	{
		if (!handle)
			return default_keyed_event;

		return st->sys_proc->handle_table().get_object<keyed_event_host>(handle);
	};

	auto create_keyed_event = [st](vcpu& cpu, emu_object<std::uint64_t> keyed_event_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint32_t flags) -> NTSTATUS
	{
		if (!keyed_event_handle)
			return STATUS_INVALID_PARAMETER;

		if (flags)
			return STATUS_INVALID_PARAMETER_4;

		const auto name = attribute_name(cpu, object_attributes);

		// Opaque: a keyed event is reached only by handle.
		const std::array<std::uint8_t, keyed_event_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(),
			std::make_shared<keyed_event_host>(), prot_rw | prot_supervisor);

		if (!addr)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (!name.empty())
			st->objs.register_named_object(name, addr);

		const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
		keyed_event_handle.write(handle);

		THREAD_LOG_INFO("NtCreateKeyedEvent('{}') -> handle=0x{:X}", name, handle);

		return STATUS_SUCCESS;
	};

	auto rendezvous = [st, keyed_event_from_handle](vcpu& cpu, const std::uint64_t handle,
		const addr_t key, const bool alertable, const emu_object<std::int64_t>& timeout,
		const bool releasing) -> NTSTATUS
	{
		const auto host = keyed_event_from_handle(handle);

		if (!host)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not a keyed event",
				releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent", handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
			return STATUS_INVALID_PARAMETER;

		const auto gate = host->gate_for(*st, key);

		if (!gate.arrivals || !gate.releases)
			return STATUS_INSUFFICIENT_RESOURCES;

		auto& space = *cpu.curr_addr_space();

		const auto post = releasing ? gate.releases : gate.arrivals;
		const auto wait_on = releasing ? gate.arrivals : gate.releases;

		win::set_state_at(space, post, win::state_at(space, post) + 1);
		st->sys_proc->wake_waiters(space, post);

		if (alertable)
			THREAD_LOG_WARN("{}: nothing delivers an APC, so an alertable wait runs its course",
				releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent");

		const auto when = win::read_timeout(timeout);

		win_thread::wait_state wait{};
		wait.objects = { wait_on };
		wait.deadline = when.deadline;
		wait.timed = when.timed;

		THREAD_LOG_INFO("{}(handle=0x{:X}, key=0x{:X}): posted 0x{:X}, waiting on 0x{:X}",
			releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent",
			handle, key, post, wait_on);

		t->begin_wait(std::move(wait));
		t->try_satisfy(space);

		thread_scheduler::yield_current(cpu);

		// Overwritten by the scheduler once it decides the wait.
		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateKeyedEvent", create_keyed_event);

	state.redirect_ntzw(mod, "WaitForKeyedEvent",
		[rendezvous](vcpu& cpu, const std::uint64_t handle, const addr_t key,
			const bool alertable, emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			return rendezvous(cpu, handle, key, alertable, timeout, false);
		});

	state.redirect_ntzw(mod, "ReleaseKeyedEvent",
		[rendezvous](vcpu& cpu, const std::uint64_t handle, const addr_t key,
			const bool alertable, emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			return rendezvous(cpu, handle, key, alertable, timeout, true);
		});

	// Named the same way a keyed event is made, so the name it was made under finds it.
	state.redirect_ntzw(mod, "OpenKeyedEvent",
		[st](vcpu& cpu, emu_object<std::uint64_t> keyed_event_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!keyed_event_handle)
				return STATUS_INVALID_PARAMETER;

			keyed_event_handle.write(0);

			const auto name = attribute_name(cpu, object_attributes);

			if (name.empty())
				return STATUS_OBJECT_PATH_SYNTAX_BAD;

			const auto existing = st->objs.lookup_named_object(name);

			if (!existing)
				return STATUS_OBJECT_NAME_NOT_FOUND;

			if (!st->objs.get_object<keyed_event_host>(existing))
				return STATUS_OBJECT_TYPE_MISMATCH;

			const auto handle = st->sys_proc->handle_table().create_handle(existing, desired_access);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			keyed_event_handle.write(handle);

			THREAD_LOG_INFO("NtOpenKeyedEvent('{}') -> handle=0x{:X}", name, handle);

			return STATUS_SUCCESS;
		});

	// Sets the event and lets go whoever is waiting, then takes the signal back: a thread that
	// starts waiting afterwards is not released. A notification event frees every waiter it has;
	// a synchronization event frees one.
	state.redirect_ntzw(mod, "PulseEvent",
		[st](vcpu& cpu, const std::uint64_t event_handle,
			emu_object<std::int32_t> previous_state) -> NTSTATUS
		{
			const auto found = resolve(*st, event_handle, win::event_notification_object,
				"NtPulseEvent");

			if (!found.address)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();
			const emu_object<_KEVENT> event(space, found.address);

			const auto previous = win::signal_state(event);

			win::set_signal_state(event, 1);
			st->sys_proc->wake_waiters(space, event.address());
			win::set_signal_state(event, 0);

			if (previous_state)
				previous_state.write(previous);

			THREAD_LOG_INFO("NtPulseEvent(0x{:X}, '{}') -> was {}",
				event_handle, found.host->name, previous);

			return STATUS_SUCCESS;
		});

	auto make_event_pair = [st](vcpu& cpu, emu_object<std::uint64_t> event_pair_handle,
		const std::uint32_t desired_access,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
	{
		if (!event_pair_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = resolve_object_name(*st, cpu, object_attributes);

		if (name.status != STATUS_SUCCESS)
			return name.status;

		const auto inherit = (name.attributes & obj_inherit) ? win_handle_table::flag_inherit : 0;

		if (name.named())
		{
			if (const auto existing = st->objs.lookup_named_object(name.key))
			{
				if (!(name.attributes & obj_openif))
					return STATUS_OBJECT_NAME_COLLISION;

				if (!st->objs.get_object<event_pair_host>(existing))
					return STATUS_OBJECT_TYPE_MISMATCH;

				event_pair_handle.write(st->sys_proc->handle_table().create_handle(existing,
					desired_access, inherit));

				return STATUS_OBJECT_NAME_EXISTS;
			}
		}

		const std::array<std::uint8_t, event_pair_body_size> zeroed{};
		auto host = std::make_shared<event_pair_host>();
		host->name = name.name;

		const auto addr = st->objs.create_object(0, zeroed.data(), zeroed.size(), std::move(host),
			prot_rw | prot_supervisor);

		if (!addr)
			return STATUS_INSUFFICIENT_RESOURCES;

		auto& space = *st->emulator()->emu().default_addr_space();

		win::init_dispatcher(emu_object<_KEVENT>(space, addr + event_pair_low_offset),
			win::event_synchronization_object, 0);
		win::init_dispatcher(emu_object<_KEVENT>(space, addr + event_pair_high_offset),
			win::event_synchronization_object, 0);

		if (name.named())
			st->objs.register_named_object(name.key, addr);

		const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access, inherit);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		event_pair_handle.write(handle);

		THREAD_LOG_INFO("NtCreateEventPair('{}') -> handle=0x{:X}", name.name, handle);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateEventPair", make_event_pair);

	state.redirect_ntzw(mod, "OpenEventPair",
		[st](vcpu& cpu, emu_object<std::uint64_t> event_pair_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!event_pair_handle)
				return STATUS_INVALID_PARAMETER;

			event_pair_handle.write(0);

			const auto name = resolve_object_name(*st, cpu, object_attributes);

			if (name.status != STATUS_SUCCESS)
				return name.status;

			if (!name.named())
				return STATUS_OBJECT_PATH_SYNTAX_BAD;

			const auto existing = st->objs.lookup_named_object(name.key);

			if (!existing)
				return STATUS_OBJECT_NAME_NOT_FOUND;

			if (!st->objs.get_object<event_pair_host>(existing))
				return STATUS_OBJECT_TYPE_MISMATCH;

			event_pair_handle.write(st->sys_proc->handle_table().create_handle(existing,
				desired_access, (name.attributes & obj_inherit) ? win_handle_table::flag_inherit : 0));

			return STATUS_SUCCESS;
		});

	// The two events of the pair a handle names, as addresses.
	struct pair_events
	{
		NTSTATUS status = STATUS_SUCCESS;
		addr_t low = 0;
		addr_t high = 0;
	};

	const auto find_pair = [st](const std::uint64_t handle, const std::string_view who) -> pair_events
	{
		const auto entry = st->sys_proc->handle_table().lookup_handle(handle);

		if (!entry)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, handle);
			return { STATUS_INVALID_HANDLE };
		}

		if (!st->objs.get_object<event_pair_host>(entry->body_addr))
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not an event pair", who, handle);
			return { STATUS_OBJECT_TYPE_MISMATCH };
		}

		return { STATUS_SUCCESS, entry->body_addr + event_pair_low_offset,
			entry->body_addr + event_pair_high_offset };
	};

	const auto signal_event = [st](vcpu& cpu, const addr_t event)
	{
		auto& space = *cpu.curr_addr_space();

		win::set_state_at(space, event, 1);
		st->sys_proc->wake_waiters(space, event);
	};

	// Nothing bounds the wait, as for the real call, and the scheduler overwrites the status once
	// it decides the wait.
	const auto wait_for_event = [](vcpu& cpu, const addr_t event) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
			return STATUS_INVALID_PARAMETER;

		win_thread::wait_state wait{};
		wait.objects = { event };

		t->begin_wait(std::move(wait));
		t->try_satisfy(*cpu.curr_addr_space());

		thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "SetLowEventPair",
		[find_pair, signal_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtSetLowEventPair");

			if (pair.status == STATUS_SUCCESS)
				signal_event(cpu, pair.low);

			return pair.status;
		});

	state.redirect_ntzw(mod, "SetHighEventPair",
		[find_pair, signal_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtSetHighEventPair");

			if (pair.status == STATUS_SUCCESS)
				signal_event(cpu, pair.high);

			return pair.status;
		});

	state.redirect_ntzw(mod, "WaitLowEventPair",
		[find_pair, wait_for_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtWaitLowEventPair");

			return pair.status == STATUS_SUCCESS ? wait_for_event(cpu, pair.low) : pair.status;
		});

	state.redirect_ntzw(mod, "WaitHighEventPair",
		[find_pair, wait_for_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtWaitHighEventPair");

			return pair.status == STATUS_SUCCESS ? wait_for_event(cpu, pair.high) : pair.status;
		});

	// The signal and the wait are one call, so nothing can come between them.
	state.redirect_ntzw(mod, "SetLowWaitHighEventPair",
		[find_pair, signal_event, wait_for_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtSetLowWaitHighEventPair");

			if (pair.status != STATUS_SUCCESS)
				return pair.status;

			signal_event(cpu, pair.low);

			return wait_for_event(cpu, pair.high);
		});

	state.redirect_ntzw(mod, "SetHighWaitLowEventPair",
		[find_pair, signal_event, wait_for_event](vcpu& cpu, const std::uint64_t handle) -> NTSTATUS
		{
			const auto pair = find_pair(handle, "NtSetHighWaitLowEventPair");

			if (pair.status != STATUS_SUCCESS)
				return pair.status;

			signal_event(cpu, pair.high);

			return wait_for_event(cpu, pair.low);
		});
}
