#include "nt_timer_ops.hpp"
#include "../win_kernel.hpp"
#include "../defs.hpp"
#include "../dispatcher.hpp"
#include "../object_names.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

// KDPC::Type.
constexpr std::uint8_t dpc_object_type = 19;

// KDPC::Importance.
constexpr std::uint8_t medium_importance = 1;

// TIMER_TYPE.
constexpr std::uint32_t notification_timer = 0;
constexpr std::uint32_t synchronization_timer = 1;

constexpr std::uint32_t timer_query_state = 0x1;
constexpr std::uint32_t timer_modify_state = 0x2;

constexpr std::uint32_t generic_read_access = 0x80000000;
constexpr std::uint32_t generic_write_access = 0x40000000;
constexpr std::uint32_t generic_all_access = 0x10000000;
constexpr std::uint32_t maximum_allowed_access = 0x02000000;

constexpr std::uint32_t timer_basic_information = 0;

#pragma pack(push, 8)
struct timer_basic_information_t
{
	std::int64_t remaining_time;
	std::uint8_t timer_state;
	std::uint8_t padding[7];
};
#pragma pack(pop)

static_assert(sizeof(timer_basic_information_t) == 0x10);

// A handle's access is kept as it was asked for, generic bits included, so those count too.
bool allows(const std::uint32_t access, const std::uint32_t needed)
{
	if ((access & needed) == needed)
		return true;

	if ((access & (generic_all_access | maximum_allowed_access)) != 0)
		return true;

	return ((access & generic_read_access) && needed == timer_query_state)
		|| ((access & generic_write_access) && needed == timer_modify_state);
}

bool is_timer(const win::dispatcher_type type)
{
	return type == win::timer_notification_object || type == win::timer_synchronization_object;
}

// Nothing else walks a list of timers, so this does: a thread of its own sleeps until the next one
// is due, makes it signalled and lets whoever waits on it go. A timer is just an address here --
// the dispatcher object in guest memory is the only other place it is recorded.
class timer_service
{
public:
	struct armed
	{
		// Absolute guest time, and the interval in 100ns ticks (zero for a timer that fires once).
		std::int64_t due = 0;
		std::int64_t period = 0;
	};

	explicit timer_service(win_kernel_state& state)
		: state_(state), worker_([this](std::stop_token stop) { run(stop); })
	{
	}

	~timer_service()
	{
		worker_.request_stop();
		cv_.notify_all();
	}

	timer_service(const timer_service&) = delete;
	timer_service& operator=(const timer_service&) = delete;

	void arm(const addr_t object, const std::int64_t due, const std::int64_t period)
	{
		{
			std::scoped_lock lock(mtx_);
			timers_[object] = { due, period };
			++generation_;
		}

		cv_.notify_all();
	}

	// Whether it was waiting to go off.
	bool cancel(const addr_t object)
	{
		std::scoped_lock lock(mtx_);

		++generation_;

		return timers_.erase(object) > 0;
	}

	[[nodiscard]] std::optional<armed> find(const addr_t object) const
	{
		std::scoped_lock lock(mtx_);

		const auto it = timers_.find(object);

		return it != timers_.end() ? std::optional<armed>(it->second) : std::nullopt;
	}

	// Signals every timer that is due. The caller's thread does it, so a timer set to a time that
	// has already gone is signalled by the time the set returns.
	void expire_due()
	{
		std::vector<addr_t> fired;

		{
			std::scoped_lock lock(mtx_);

			const auto now = win_system_time();

			for (auto it = timers_.begin(); it != timers_.end();)
			{
				if (it->second.due > now)
				{
					++it;
					continue;
				}

				fired.push_back(it->first);

				if (it->second.period > 0)
				{
					// A period that went by while nobody looked is not signalled twice.
					const auto behind = now - it->second.due;
					it->second.due += (behind / it->second.period + 1) * it->second.period;
					++it;
					continue;
				}

				it = timers_.erase(it);
			}
		}

		for (const auto object : fired)
		{
			auto& space = state_.kernel_space();

			win::set_state_at(space, object, 1);
			state_.sys_proc->wake_waiters(space, object);
		}
	}

private:
	void run(const std::stop_token stop)
	{
		std::unique_lock lock(mtx_);

		while (!stop.stop_requested())
		{
			std::optional<std::int64_t> next;

			for (const auto& [object, timer] : timers_)
			{
				if (!next || timer.due < *next)
					next = timer.due;
			}

			const auto seen = generation_;
			const auto changed = [&] { return generation_ != seen; };

			if (!next)
			{
				cv_.wait(lock, stop, changed);
				continue;
			}

			const auto remaining = *next - win_system_time();

			if (remaining > 0)
			{
				// Capped, so a timer set far ahead does not overflow the host clock; the loop comes round.
				const auto wait = std::min(
					std::chrono::ceil<std::chrono::milliseconds>(win_ticks(remaining)),
					std::chrono::milliseconds(3'600'000));

				cv_.wait_for(lock, stop, wait, changed);
				continue;
			}

			lock.unlock();
			expire_due();
			lock.lock();
		}
	}

	win_kernel_state& state_;
	mutable std::mutex mtx_;
	std::condition_variable_any cv_;
	std::map<addr_t, armed> timers_;
	std::uint64_t generation_ = 0;

	// Last, so it is stopped and joined before anything it uses goes.
	std::jthread worker_;
};

}

// A DPC is started on a thread of its own. A timer goes off when its time comes, by way of the
// timer service -- except for the kernel's own, which have a DPC to run and nothing to run it on.
void modules::register_ntoskrnl_timer_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	const auto timers = std::make_shared<timer_service>(state);

	state.redirect(mod, "KeInitializeDpc",
		[](vcpu&, emu_object<_KDPC> dpc, const addr_t deferred_routine,
			const addr_t deferred_context)
		{
			if (!dpc)
				return;

			_KDPC out{};
			out.Type = dpc_object_type;
			out.Importance = medium_importance;
			out.DeferredRoutine = guest_ptr<void>(deferred_routine);
			out.DeferredContext = guest_ptr<void>(deferred_context);

			dpc.write(out);

			THREAD_LOG_INFO("KeInitializeDpc(0x{:X}, routine=0x{:X}, context=0x{:X})",
				dpc.address(), deferred_routine, deferred_context);
		});

	state.redirect(mod, "KeInsertQueueDpc",
		[st](vcpu& cpu, emu_object<_KDPC> dpc, const addr_t system_argument1,
			const addr_t system_argument2) -> bool
		{
			if (!dpc)
				return false;

			auto entry = dpc.read();
			const auto routine = guest_va(entry.DeferredRoutine);

			if (!routine)
			{
				THREAD_LOG_WARN("KeInsertQueueDpc: 0x{:X} has no deferred routine",
					dpc.address());
				return false;
			}

			if (guest_va(entry.DpcData))
			{
				THREAD_LOG_INFO("KeInsertQueueDpc(0x{:X}): already queued", dpc.address());
				return false;
			}

			entry.SystemArgument1 = guest_ptr<void>(system_argument1);
			entry.SystemArgument2 = guest_ptr<void>(system_argument2);
			entry.DpcData = guest_ptr<void>(dpc.address());
			dpc.write(entry);

			const std::uint64_t args[] = {
				dpc.address(),
				guest_va(entry.DeferredContext),
				system_argument1,
				system_argument2,
			};

			auto t = st->sys_proc->create_thread(cpu, routine, args);

			THREAD_LOG_INFO("KeInsertQueueDpc(0x{:X}, 0x{:X}, 0x{:X}): routine 0x{:X} runs as tid={}",
				dpc.address(), system_argument1, system_argument2, routine, t->id());

			return true;
		});

	// Nothing sits on a queue waiting to be drained, so there is nothing to wait for.
	state.redirect(mod, "KeFlushQueuedDpcs", [](vcpu&)
	{
		THREAD_LOG_INFO("KeFlushQueuedDpcs(): a DPC runs when it is inserted, so none are queued");
	});

	const auto init_timer = [](const emu_object<_KTIMER>& timer, const win::dispatcher_type type)
	{
		win::init_dispatcher(timer, type, 0);

		timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart).write(0);
		timer.field(&_KTIMER::Dpc).write(nullptr);
		timer.field(&_KTIMER::Period).write(0);
	};

	state.redirect(mod, "KeInitializeTimer", [init_timer](vcpu&, emu_object<_KTIMER> timer)
	{
		if (!timer)
			return;

		init_timer(timer, win::timer_notification_object);

		THREAD_LOG_INFO("KeInitializeTimer(0x{:X})", timer.address());
	});

	state.redirect(mod, "KeInitializeTimerEx",
		[init_timer](vcpu&, emu_object<_KTIMER> timer, const std::uint32_t type)
		{
			if (!timer)
				return;

			const bool synchronization = type == synchronization_timer;

			init_timer(timer, synchronization
				? win::timer_synchronization_object : win::timer_notification_object);

			THREAD_LOG_INFO("KeInitializeTimerEx(0x{:X}, {})", timer.address(),
				synchronization ? "SynchronizationTimer" : "NotificationTimer");
		});

	const auto set_timer = [](emu_object<_KTIMER> timer, const std::int64_t due_time,
		const std::int32_t period, const emu_object<_KDPC>& dpc, const std::string_view who)
	{
		auto entry = timer.read();
		const bool was_set = entry.DueTime.QuadPart != 0;

		const auto absolute = due_time < 0
			? win_system_time() + static_cast<std::uint64_t>(-due_time)
			: static_cast<std::uint64_t>(due_time);

		entry.DueTime.QuadPart = absolute;
		entry.Dpc = guest_ptr<_KDPC>(dpc.address());
		entry.Header.SignalState = 0;
		entry.Period = static_cast<std::uint32_t>(period);

		timer.write(entry);

		const auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
			win_ticks(due_time < 0 ? -due_time : due_time));

		THREAD_LOG_WARN("{}(0x{:X}, due={} ({} {} ms) -> absolute 0x{:X}, period={} ms, "
			"dpc=0x{:X}): nothing here walks a timer list, so it will not go off",
			who, timer.address(), due_time, due_time < 0 ? "in" : "at", interval.count(),
			absolute, period, dpc.address());

		return was_set;
	};

	state.redirect(mod, "KeSetTimer",
		[set_timer](vcpu&, emu_object<_KTIMER> timer, const std::int64_t due_time,
			emu_object<_KDPC> dpc) -> bool
		{
			return timer && set_timer(timer, due_time, 0, dpc, "KeSetTimer");
		});

	state.redirect(mod, "KeSetTimerEx",
		[set_timer](vcpu&, emu_object<_KTIMER> timer, const std::int64_t due_time,
			const std::int32_t period, emu_object<_KDPC> dpc) -> bool
		{
			if (period < 0)
			{
				// Real NT bugchecks on a negative period; the guest is left standing instead.
				THREAD_LOG_ERR("KeSetTimerEx: 0x{:X} was given period {}",
					timer.address(), period);

				return false;
			}

			return timer && set_timer(timer, due_time, period, dpc, "KeSetTimerEx");
		});

	state.redirect(mod, "KeCancelTimer", [](vcpu&, emu_object<_KTIMER> timer) -> bool
	{
		if (!timer)
			return false;

		auto entry = timer.read();
		const bool was_set = entry.DueTime.QuadPart != 0;

		entry.DueTime.QuadPart = 0;
		entry.Dpc = nullptr;
		timer.write(entry);

		THREAD_LOG_INFO("KeCancelTimer(0x{:X}) -> {}", timer.address(), was_set);

		return was_set;
	});

	// Never signalled, because nothing fires a timer.
	state.redirect(mod, "KeReadStateTimer", [](vcpu&, emu_object<_KTIMER> timer) -> bool
	{
		if (!timer)
			return false;

		const auto signalled = timer.field(&_KTIMER::Header)
			.field(&_DISPATCHER_HEADER::SignalState).read() != 0;

		THREAD_LOG_INFO("KeReadStateTimer(0x{:X}) -> {}", timer.address(), signalled);

		return signalled;
	});

	state.redirect_ntzw(mod, "CreateTimer2",
		[st](vcpu& cpu, emu_object<std::uint64_t> timer_handle,
			[[maybe_unused]] const addr_t reserved1, [[maybe_unused]] const addr_t reserved2,
			const std::uint32_t attributes, const std::uint32_t desired_access) -> NTSTATUS
		{
			if (!timer_handle)
				return STATUS_INVALID_PARAMETER;

			const _KTIMER zeroed{};
			const auto addr = st->objs.create_object(0, &zeroed, sizeof(zeroed),
				{}, prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), addr);

			// TIMER_TYPE is the low bit of the attributes.
			win::init_dispatcher(timer, (attributes & 1)
				? win::timer_synchronization_object : win::timer_notification_object, 0);

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
			timer_handle.write(handle);

			THREAD_LOG_INFO("NtCreateTimer2(attributes=0x{:X}) -> handle=0x{:X}",
				attributes, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "SetTimer2",
		[st, timers](vcpu& cpu, const std::uint64_t timer_handle, emu_object<std::int64_t> due_time,
			emu_object<std::int64_t> period, const addr_t parameters) -> NTSTATUS
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(timer_handle);

			if (!entry)
			{
				THREAD_LOG_WARN("NtSetTimer2: handle 0x{:X} is not open", timer_handle);
				return STATUS_INVALID_HANDLE;
			}

			if (!due_time)
				return STATUS_INVALID_PARAMETER;

			const auto when = win::read_timeout(due_time);
			const auto interval = period ? period.read() : 0;

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), entry->body_addr);

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart)
				.write(static_cast<std::uint64_t>(when.deadline));
			timer.field(&_KTIMER::Period).write(static_cast<std::uint32_t>(
				interval / 10000));

			// A timer that is set starts out not signalled, and is signalled when its time comes.
			win::set_signal_state(timer, 0);
			timers->arm(entry->body_addr, when.deadline, interval > 0 ? interval : 0);
			timers->expire_due();

			THREAD_LOG_INFO("NtSetTimer2(0x{:X}, due={}, period={}, parameters=0x{:X})",
				timer_handle, due_time.read(), interval, parameters);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "CancelTimer2",
		[st, timers](vcpu& cpu, const std::uint64_t timer_handle, const addr_t parameters) -> NTSTATUS
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(timer_handle);

			if (!entry)
			{
				THREAD_LOG_WARN("NtCancelTimer2: handle 0x{:X} is not open", timer_handle);
				return STATUS_INVALID_HANDLE;
			}

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), entry->body_addr);
			const auto due = timer.field(&_KTIMER::DueTime)
				.field(&_ULARGE_INTEGER::QuadPart).read();

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart).write(0);
			timer.field(&_KTIMER::Period).write(0);

			const bool was_pending = timers->cancel(entry->body_addr);

			THREAD_LOG_INFO("NtCancelTimer2(0x{:X}, parameters=0x{:X}) -> was {}",
				timer_handle, parameters, (due || was_pending) ? "set" : "not set");

			return STATUS_SUCCESS;
		});

	// The classic timer: a timer object named by handle, signalled when it comes due, whose
	// APC routine nothing here can deliver.
	struct timer_ref
	{
		NTSTATUS status = STATUS_SUCCESS;
		addr_t address = 0;
		std::uint32_t access = 0;
	};

	const auto find_timer = [st](const std::uint64_t handle, const std::uint32_t needed,
		const std::string_view who) -> timer_ref
	{
		const auto entry = st->sys_proc->handle_table().lookup_handle(handle);

		if (!entry)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, handle);
			return { STATUS_INVALID_HANDLE };
		}

		const auto host = st->objs.get_object<dispatcher_host>(entry->body_addr);

		if (!host || !is_timer(host->type))
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not a timer", who, handle);
			return { STATUS_OBJECT_TYPE_MISMATCH };
		}

		if (!allows(entry->access, needed))
			return { STATUS_ACCESS_DENIED };

		return { STATUS_SUCCESS, entry->body_addr, entry->access };
	};

	state.redirect_ntzw(mod, "CreateTimer",
		[st](vcpu& cpu, emu_object<std::uint64_t> timer_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes, const std::uint32_t timer_type)
			-> NTSTATUS
		{
			if (!timer_handle)
				return STATUS_INVALID_PARAMETER;

			if (timer_type != notification_timer && timer_type != synchronization_timer)
				return STATUS_INVALID_PARAMETER_4;

			const auto type = timer_type == synchronization_timer
				? win::timer_synchronization_object : win::timer_notification_object;

			const auto name = resolve_object_name(*st, cpu, object_attributes);

			if (name.status != STATUS_SUCCESS)
				return name.status;

			const auto inherit = (name.attributes & obj_inherit)
				? win_handle_table::flag_inherit : 0;

			if (name.named())
			{
				if (const auto existing = st->objs.lookup_named_object(name.key))
				{
					if (!(name.attributes & obj_openif))
						return STATUS_OBJECT_NAME_COLLISION;

					const auto host = st->objs.get_object<dispatcher_host>(existing);

					if (!host || !is_timer(host->type))
						return STATUS_OBJECT_TYPE_MISMATCH;

					timer_handle.write(st->sys_proc->handle_table().create_handle(existing,
						desired_access, inherit));

					return STATUS_OBJECT_NAME_EXISTS;
				}
			}

			const _KTIMER zeroed{};
			const auto addr = st->objs.create_object(0, &zeroed, sizeof(zeroed),
				std::make_shared<dispatcher_host>(type, name.name), prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			win::init_dispatcher(emu_object<_KTIMER>(st->kernel_space(), addr), type, 0);

			if (name.named())
				st->objs.register_named_object(name.key, addr);

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access,
				inherit);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			timer_handle.write(handle);

			THREAD_LOG_INFO("NtCreateTimer({}) -> handle=0x{:X}",
				timer_type == synchronization_timer ? "synchronization" : "notification", handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "OpenTimer",
		[st](vcpu& cpu, emu_object<std::uint64_t> timer_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!timer_handle)
				return STATUS_INVALID_PARAMETER;

			timer_handle.write(0);

			const auto name = resolve_object_name(*st, cpu, object_attributes);

			if (name.status != STATUS_SUCCESS)
				return name.status;

			if (!name.named())
				return STATUS_OBJECT_PATH_SYNTAX_BAD;

			const auto existing = st->objs.lookup_named_object(name.key);

			if (!existing)
				return STATUS_OBJECT_NAME_NOT_FOUND;

			const auto host = st->objs.get_object<dispatcher_host>(existing);

			if (!host || !is_timer(host->type))
				return STATUS_OBJECT_TYPE_MISMATCH;

			timer_handle.write(st->sys_proc->handle_table().create_handle(existing, desired_access,
				(name.attributes & obj_inherit) ? win_handle_table::flag_inherit : 0));

			return STATUS_SUCCESS;
		});

	// A timer that is set again is cancelled first, and starts out not signalled.
	state.redirect_ntzw(mod, "SetTimer",
		[timers, find_timer](vcpu& cpu, const std::uint64_t timer_handle,
			emu_object<std::int64_t> due_time, const addr_t timer_apc_routine,
			const addr_t timer_context, [[maybe_unused]] const bool resume_timer,
			const std::int32_t period, emu_object<std::uint8_t> previous_state) -> NTSTATUS
		{
			const auto found = find_timer(timer_handle, timer_modify_state, "NtSetTimer");

			if (found.status != STATUS_SUCCESS)
				return found.status;

			if (!due_time)
				return STATUS_INVALID_PARAMETER;

			if (period < 0)
				return STATUS_INVALID_PARAMETER_6;

			auto& space = *cpu.curr_addr_space();
			const emu_object<_KTIMER> timer(space, found.address);

			const auto when = win::read_timeout(due_time);
			const std::int64_t interval = std::int64_t{period} * 10000;

			if (previous_state)
				previous_state.write(win::signal_state(timer) != 0 ? 1 : 0);

			timers->cancel(found.address);
			win::set_signal_state(timer, 0);

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart)
				.write(static_cast<std::uint64_t>(when.deadline));
			timer.field(&_KTIMER::Period).write(static_cast<std::uint32_t>(period));

			timers->arm(found.address, when.deadline, interval);
			timers->expire_due();

			if (timer_apc_routine)
				THREAD_LOG_WARN("NtSetTimer(0x{:X}): the APC routine at 0x{:X} (context 0x{:X}) is "
					"not run, because nothing delivers an APC; the timer is still signalled",
					timer_handle, timer_apc_routine, timer_context);

			THREAD_LOG_INFO("NtSetTimer(0x{:X}, due={}, period={} ms)", timer_handle,
				due_time.read(), period);

			return STATUS_SUCCESS;
		});

	// Cancelling stops a timer that has yet to go off; one that already has stays signalled.
	state.redirect_ntzw(mod, "CancelTimer",
		[timers, find_timer](vcpu& cpu, const std::uint64_t timer_handle,
			emu_object<std::uint8_t> current_state) -> NTSTATUS
		{
			const auto found = find_timer(timer_handle, timer_modify_state, "NtCancelTimer");

			if (found.status != STATUS_SUCCESS)
				return found.status;

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), found.address);

			const bool pending = timers->cancel(found.address);

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart).write(0);
			timer.field(&_KTIMER::Period).write(0);

			if (current_state)
				current_state.write(win::signal_state(timer) != 0 ? 1 : 0);

			THREAD_LOG_INFO("NtCancelTimer(0x{:X}) -> {}", timer_handle,
				pending ? "was pending" : "was not pending");

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "QueryTimer",
		[timers, find_timer](vcpu& cpu, const std::uint64_t timer_handle,
			const std::uint32_t timer_information_class, const addr_t timer_information,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto found = find_timer(timer_handle, timer_query_state, "NtQueryTimer");

			if (found.status != STATUS_SUCCESS)
				return found.status;

			if (timer_information_class != timer_basic_information)
			{
				THREAD_LOG_WARN("NtQueryTimer: unhandled class {}", timer_information_class);
				return STATUS_INVALID_INFO_CLASS;
			}

			if (return_length)
				return_length.write(sizeof(timer_basic_information_t));

			if (length < sizeof(timer_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			// A timer already due is signalled whether or not the service has got round to it.
			timers->expire_due();

			auto& space = *cpu.curr_addr_space();

			timer_basic_information_t info{};
			info.timer_state = win::signal_state(emu_object<_KTIMER>(space, found.address)) != 0;

			if (const auto armed = timers->find(found.address))
				info.remaining_time = std::max<std::int64_t>(0, armed->due - win_system_time());

			emu_object<timer_basic_information_t>(space, timer_information).write(info);

			THREAD_LOG_INFO("NtQueryTimer(0x{:X}) -> remaining={}, signalled={}", timer_handle,
				info.remaining_time, info.timer_state);

			return STATUS_SUCCESS;
		});
}
