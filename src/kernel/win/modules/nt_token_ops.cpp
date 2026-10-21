#include "nt_token_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../security.hpp"
#include "../status.hpp"
#include "../thread.hpp"
#include "../token.hpp"
#include "../../../util/log.hpp"
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace
{

using namespace win::sec;

constexpr std::uint64_t current_process_pseudo_handle = ~std::uint64_t{0};
constexpr std::uint64_t current_thread_pseudo_handle = ~std::uint64_t{1};
constexpr std::uint64_t current_process_token_pseudo_handle = ~std::uint64_t{3};
constexpr std::uint64_t current_thread_token_pseudo_handle = ~std::uint64_t{4};
constexpr std::uint64_t current_effective_token_pseudo_handle = ~std::uint64_t{5};

constexpr std::uint32_t obj_inherit_attribute = 0x2;
constexpr std::uint32_t max_privilege_count = 0x100;
constexpr std::size_t luid_and_attributes_size = 12;
constexpr std::size_t privilege_set_header = 8;

struct token_state
{
	std::mutex mtx;
	std::unordered_map<std::uint64_t, std::shared_ptr<token_host>> primary;
	std::unordered_map<addr_t, descriptor> descriptors;
	std::atomic<std::uint64_t> next_token_id{0x10000};

	std::shared_ptr<token_host> for_process(const std::uint64_t pid)
	{
		std::scoped_lock lock(mtx);

		auto& slot = primary[pid];

		if (!slot)
			slot = std::make_shared<token_host>(make_default_token(next_token_id++));

		return slot;
	}

	std::shared_ptr<token_host> thread_token(win_thread& t)
	{
		auto token = std::dynamic_pointer_cast<token_host>(t.impersonation_token());

		if (token || !t.teb() || !t.teb().field(&_TEB64::IsImpersonating).read())
			return token;

		const auto base = for_process(t.proc()->id());

		std::scoped_lock lock(base->mtx);

		token = std::make_shared<token_host>(duplicate_token(base->data, token_impersonation,
			security_impersonation, false, next_token_id++));

		t.set_impersonation_token(token);

		return token;
	}
};

struct token_lookup
{
	NTSTATUS status = STATUS_SUCCESS;
	std::shared_ptr<token_host> token;
	std::uint32_t access = 0;
};

token_lookup resolve_token(win_kernel_state& state, token_state& tokens, vcpu& cpu,
	const std::uint64_t handle, const std::uint32_t required)
{
	if (handle != current_process_token_pseudo_handle
		&& handle != current_thread_token_pseudo_handle
		&& handle != current_effective_token_pseudo_handle)
	{
		const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

		if (!entry)
			return { STATUS_INVALID_HANDLE };

		auto token = state.objs.get_object<token_host>(entry->body_addr);

		if (!token)
			return { STATUS_OBJECT_TYPE_MISMATCH };

		if ((entry->access & required) != required)
			return { STATUS_ACCESS_DENIED };

		return { STATUS_SUCCESS, std::move(token), entry->access };
	}

	const auto self = cpu.thread();
	const auto thread = std::dynamic_pointer_cast<win_thread>(self);

	std::shared_ptr<token_host> token;

	if (handle != current_process_token_pseudo_handle && thread)
		token = tokens.thread_token(*thread);

	if (!token && handle != current_thread_token_pseudo_handle && self)
		token = tokens.for_process(self->proc()->id());

	if (!token)
		return { STATUS_NO_TOKEN };

	return { STATUS_SUCCESS, std::move(token), token_all_access };
}

NTSTATUS publish_token(win_kernel_state& state, std::shared_ptr<token_host> token,
	const std::uint32_t access, const std::uint32_t attributes, emu_object<std::uint64_t> out)
{
	const std::uint8_t body[sizeof(addr_t)] = {};

	const auto addr = state.objs.create_object(0, body, sizeof(body), std::move(token),
		prot_rw | prot_supervisor);

	if (!addr)
		return STATUS_INSUFFICIENT_RESOURCES;

	const auto handle = state.sys_proc->handle_table().create_handle(addr, access,
		(attributes & obj_inherit_attribute) ? win_handle_table::flag_inherit : 0);

	if (!handle)
		return STATUS_INSUFFICIENT_RESOURCES;

	out.write(handle);

	return STATUS_SUCCESS;
}

std::vector<privilege_entry> read_privileges(addr_space& space, const addr_t address,
	const std::uint32_t count)
{
	std::vector<privilege_entry> out;

	for (std::uint32_t i = 0; i < count; ++i)
	{
		const auto at = address + i * luid_and_attributes_size;
		const auto high = space.read_mem<std::uint32_t>(at + 4);

		out.push_back({ high ? ~std::uint32_t{0} : space.read_mem<std::uint32_t>(at),
			space.read_mem<std::uint32_t>(at + 8) });
	}

	return out;
}

descriptor default_descriptor()
{
	const auto token = make_default_token(0);

	return { token.owner, token.primary_group, token.default_dacl };
}

}

void modules::register_ntoskrnl_token_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	const auto tokens = std::make_shared<token_state>();

	state.privilege_enabled = [st, tokens](vcpu& cpu, const std::uint32_t luid) -> bool
	{
		const auto enabled_in = [luid](token_host& token)
		{
			std::scoped_lock lock(token.mtx);

			return std::ranges::any_of(token.data.privileges,
				[luid](const privilege_entry& p)
				{
					return p.luid == luid && (p.attributes & se_privilege_enabled);
				});
		};

		const auto found = resolve_token(*st, *tokens, cpu, current_effective_token_pseudo_handle, 0);

		if (found.status != STATUS_SUCCESS)
			return false;

		if (enabled_in(*found.token))
			return true;

		// Every thread starts out flagged as impersonating, which gives it a snapshot of the
		// process token the first time anyone asks. A privilege enabled on the process token
		// afterwards is not in that snapshot, but it is the one callers adjust.
		const auto self = cpu.thread();

		if (!self)
			return false;

		const auto process_token = tokens->for_process(self->proc()->id());

		return process_token != found.token && enabled_in(*process_token);
	};

	const auto open_process_token = [st, tokens](vcpu& cpu, const std::uint64_t process_handle,
		const std::uint32_t desired_access, const std::uint32_t handle_attributes,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		if (!token_handle)
			return STATUS_INVALID_PARAMETER;

		token_handle.write(0);

		std::optional<std::uint64_t> pid;

		if (process_handle == current_process_pseudo_handle)
		{
			if (const auto self = cpu.thread())
				pid = self->proc()->id();
		}
		else if (const auto process = st->sys_proc->handle_table().get_object<process_object>(process_handle))
		{
			pid = process->pid;
		}

		if (!pid)
			return STATUS_INVALID_HANDLE;

		const auto status = publish_token(*st, tokens->for_process(*pid),
			map_token_access(desired_access), handle_attributes, token_handle);

		THREAD_LOG_INFO("NtOpenProcessToken(pid={}, access=0x{:X}) -> 0x{:X}", *pid, desired_access, status);

		return status;
	};

	state.redirect_ntzw(mod, "OpenProcessToken",
		[open_process_token](vcpu& cpu, const std::uint64_t process_handle,
			const std::uint32_t desired_access, emu_object<std::uint64_t> token_handle) -> NTSTATUS
		{
			return open_process_token(cpu, process_handle, desired_access, 0, std::move(token_handle));
		});

	state.redirect_ntzw(mod, "OpenProcessTokenEx", open_process_token);

	const auto open_thread_token = [st, tokens](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t desired_access, const std::uint32_t handle_attributes,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		if (!token_handle)
			return STATUS_INVALID_PARAMETER;

		token_handle.write(0);

		std::shared_ptr<win_thread> t;

		if (thread_handle == current_thread_pseudo_handle)
		{
			t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
		}
		else if (const auto entry = st->sys_proc->handle_table().lookup_handle(thread_handle))
		{
			if (const auto obj = st->objs.get_object<thread_object>(entry->body_addr))
				t = std::dynamic_pointer_cast<win_thread>(obj->thread);
		}

		if (!t)
			return STATUS_INVALID_HANDLE;

		const auto token = tokens->thread_token(*t);

		if (!token)
			return STATUS_NO_TOKEN;

		const auto status = publish_token(*st, token, map_token_access(desired_access),
			handle_attributes, token_handle);

		THREAD_LOG_INFO("NtOpenThreadToken(tid={}, access=0x{:X}) -> 0x{:X}", t->id(), desired_access, status);

		return status;
	};

	state.redirect_ntzw(mod, "OpenThreadToken",
		[open_thread_token](vcpu& cpu, const std::uint64_t thread_handle,
			const std::uint32_t desired_access, const bool,
			emu_object<std::uint64_t> token_handle) -> NTSTATUS
		{
			return open_thread_token(cpu, thread_handle, desired_access, 0, std::move(token_handle));
		});

	state.redirect_ntzw(mod, "OpenThreadTokenEx",
		[open_thread_token](vcpu& cpu, const std::uint64_t thread_handle,
			const std::uint32_t desired_access, const bool,
			const std::uint32_t handle_attributes,
			emu_object<std::uint64_t> token_handle) -> NTSTATUS
		{
			return open_thread_token(cpu, thread_handle, desired_access, handle_attributes,
				std::move(token_handle));
		});

	state.redirect_ntzw(mod, "QueryInformationToken",
		[st, tokens](vcpu& cpu, const std::uint64_t token_handle, const std::uint32_t information_class,
			const addr_t token_information, const std::uint32_t length,
			emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto found = resolve_token(*st, *tokens, cpu, token_handle,
				information_class == token_source ? (token_query | token_query_source) : token_query);

			if (found.status != STATUS_SUCCESS)
				return found.status;

			bytes data;
			NTSTATUS status;

			{
				std::scoped_lock lock(found.token->mtx);
				status = query_token_information(found.token->data, information_class,
					token_information, data);
			}

			if (status != STATUS_SUCCESS)
				return status;

			if (return_length)
				return_length.write(static_cast<std::uint32_t>(data.size()));

			if (length < data.size())
				return STATUS_BUFFER_TOO_SMALL;

			cpu.curr_addr_space()->write_mem(token_information, data.data(), data.size());

			THREAD_LOG_INFO("NtQueryInformationToken(0x{:X}, class={}) -> {} bytes",
				token_handle, information_class, data.size());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "DuplicateToken",
		[st, tokens](vcpu& cpu, const std::uint64_t existing_token, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes, const bool effective_only,
			const std::uint32_t token_type, emu_object<std::uint64_t> new_token) -> NTSTATUS
		{
			if (!new_token)
				return STATUS_INVALID_PARAMETER;

			new_token.write(0);

			const auto found = resolve_token(*st, *tokens, cpu, existing_token, token_duplicate);

			if (found.status != STATUS_SUCCESS)
				return found.status;

			if (token_type != token_primary && token_type != token_impersonation)
				return STATUS_INVALID_PARAMETER;

			std::optional<std::uint32_t> requested_level;
			std::uint32_t attributes = 0;

			if (object_attributes)
			{
				attributes = object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read();

				if (const auto qos = guest_va(
					object_attributes.field(&_OBJECT_ATTRIBUTES::SecurityQualityOfService).read()))
				{
					requested_level = cpu.curr_addr_space()->read_mem<std::uint32_t>(qos + 4);
				}
			}

			token_data duplicate;

			{
				std::scoped_lock lock(found.token->mtx);
				const auto& source = found.token->data;
				const bool impersonating = source.type == token_impersonation;

				const auto level = requested_level.value_or(
					impersonating ? source.impersonation_level : security_impersonation);

				if (impersonating && (token_type == token_impersonation
					? level > source.impersonation_level
					: source.impersonation_level < security_impersonation))
				{
					return STATUS_BAD_IMPERSONATION_LEVEL;
				}

				duplicate = duplicate_token(source, token_type, level, effective_only,
					tokens->next_token_id++);
			}

			const auto status = publish_token(*st, std::make_shared<token_host>(std::move(duplicate)),
				desired_access ? map_token_access(desired_access) : found.access, attributes, new_token);

			THREAD_LOG_INFO("NtDuplicateToken(0x{:X}, type={}, effective_only={}) -> 0x{:X}",
				existing_token, token_type, effective_only, status);

			return status;
		});

	state.redirect_ntzw(mod, "AdjustPrivilegesToken",
		[st, tokens](vcpu& cpu, const std::uint64_t token_handle, const bool disable_all_privileges,
			const addr_t new_state, const std::uint32_t buffer_length, const addr_t previous_state,
			emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto found = resolve_token(*st, *tokens, cpu, token_handle,
				previous_state ? (token_adjust_privileges | token_query) : token_adjust_privileges);

			if (found.status != STATUS_SUCCESS)
				return found.status;

			auto& space = *cpu.curr_addr_space();

			std::vector<privilege_entry> requested;

			if (!disable_all_privileges)
			{
				if (!new_state)
					return STATUS_INVALID_PARAMETER;

				const auto count = space.read_mem<std::uint32_t>(new_state);

				if (count > max_privilege_count)
					return STATUS_INVALID_PARAMETER;

				requested = read_privileges(space, new_state + sizeof(std::uint32_t), count);
			}

			std::scoped_lock lock(found.token->mtx);

			auto adjusted = found.token->data;
			std::vector<privilege_entry> previous;

			const auto status = adjust_privileges(adjusted, disable_all_privileges, requested, previous);

			if (previous_state)
			{
				const auto list = encode_privileges(previous);

				if (return_length)
					return_length.write(static_cast<std::uint32_t>(list.size()));

				if (buffer_length < list.size())
					return STATUS_BUFFER_TOO_SMALL;

				space.write_mem(previous_state, list.data(), list.size());
			}

			found.token->data = std::move(adjusted);

			THREAD_LOG_INFO("NtAdjustPrivilegesToken(0x{:X}, disable_all={}) -> {} changed, 0x{:X}",
				token_handle, disable_all_privileges, previous.size(), status);

			return status;
		});

	state.redirect_ntzw(mod, "PrivilegeCheck",
		[st, tokens](vcpu& cpu, const std::uint64_t client_token, const addr_t required_privileges,
			emu_object<std::uint8_t> result) -> NTSTATUS
		{
			if (!required_privileges || !result)
				return STATUS_INVALID_PARAMETER;

			const auto found = resolve_token(*st, *tokens, cpu, client_token, token_query);

			if (found.status != STATUS_SUCCESS)
				return found.status;

			auto& space = *cpu.curr_addr_space();

			const auto count = space.read_mem<std::uint32_t>(required_privileges);
			const auto control = space.read_mem<std::uint32_t>(required_privileges + 4);

			if (count > max_privilege_count)
				return STATUS_INVALID_PARAMETER;

			const auto entries = required_privileges + privilege_set_header;
			const auto list = read_privileges(space, entries, count);

			std::scoped_lock lock(found.token->mtx);

			if (found.token->data.type != token_impersonation)
				return STATUS_NO_IMPERSONATION_TOKEN;

			std::uint32_t held = 0;

			for (std::uint32_t i = 0; i < count; ++i)
			{
				const bool has = std::ranges::any_of(found.token->data.privileges,
					[&](const privilege_entry& p)
					{
						return p.luid == list[i].luid && (p.attributes & se_privilege_enabled);
					});

				held += has;

				space.write_mem<std::uint32_t>(entries + i * luid_and_attributes_size + 8,
					has ? list[i].attributes | se_privilege_used_for_access
						: list[i].attributes & ~se_privilege_used_for_access);
			}

			const bool passed = (control & privilege_set_all_necessary) ? held == count : held != 0;

			result.write(passed ? 1 : 0);

			THREAD_LOG_INFO("NtPrivilegeCheck(0x{:X}, {} privilege(s)) -> {}", client_token, count, passed);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AccessCheck",
		[st, tokens](vcpu& cpu, const addr_t security_descriptor, const std::uint64_t client_token,
			const std::uint32_t desired_access, emu_object<generic_mapping> generic_mapping_ptr,
			const addr_t privilege_set, emu_object<std::uint32_t> privilege_set_length,
			emu_object<std::uint32_t> granted_access, emu_object<std::uint32_t> access_status)
			-> NTSTATUS
		{
			if (!generic_mapping_ptr || !granted_access || !access_status)
				return STATUS_INVALID_PARAMETER;

			if (desired_access & access_generic_bits)
				return STATUS_GENERIC_NOT_MAPPED;

			const auto found = resolve_token(*st, *tokens, cpu, client_token, token_query);

			if (found.status != STATUS_SUCCESS)
				return found.status;

			auto& space = *cpu.curr_addr_space();

			const auto sd = read_descriptor(space, security_descriptor);

			if (!sd || !sd->owner || !sd->group)
				return STATUS_INVALID_SECURITY_DESCR;

			std::uint32_t granted = 0;
			NTSTATUS status;

			{
				std::scoped_lock lock(found.token->mtx);

				if (found.token->data.type != token_impersonation)
					return STATUS_NO_IMPERSONATION_TOKEN;

				if (found.token->data.impersonation_level < security_identification)
					return STATUS_BAD_IMPERSONATION_LEVEL;

				status = check_access(*sd, found.token->data, desired_access,
					generic_mapping_ptr.read(), granted);
			}

			if (privilege_set && privilege_set_length)
			{
				if (privilege_set_length.read() < privilege_set_header)
					return STATUS_BUFFER_TOO_SMALL;

				space.write_mem<std::uint64_t>(privilege_set, 0);
			}

			granted_access.write(granted);
			access_status.write(status);

			THREAD_LOG_INFO("NtAccessCheck(token=0x{:X}, desired=0x{:X}) -> granted=0x{:X}, status=0x{:X}",
				client_token, desired_access, granted, status);

			return STATUS_SUCCESS;
		});

	const auto security_key = [st](const std::uint64_t handle) -> std::optional<addr_t>
	{
		if (handle == current_process_pseudo_handle || handle == current_thread_pseudo_handle)
			return handle;

		if (const auto entry = st->sys_proc->handle_table().lookup_handle(handle))
			return entry->body_addr;

		return std::nullopt;
	};

	state.redirect_ntzw(mod, "QuerySecurityObject",
		[tokens, security_key](vcpu& cpu, const std::uint64_t handle,
			const std::uint32_t security_information, const addr_t security_descriptor,
			const std::uint32_t length, emu_object<std::uint32_t> length_needed) -> NTSTATUS
		{
			const auto key = security_key(handle);

			if (!key)
				return STATUS_INVALID_HANDLE;

			bytes out;

			{
				std::scoped_lock lock(tokens->mtx);

				const auto it = tokens->descriptors.find(*key);

				out = compose_self_relative(
					it != tokens->descriptors.end() ? it->second : default_descriptor(),
					security_information);
			}

			if (length_needed)
				length_needed.write(static_cast<std::uint32_t>(out.size()));

			if (length < out.size())
				return STATUS_BUFFER_TOO_SMALL;

			cpu.curr_addr_space()->write_mem(security_descriptor, out.data(), out.size());

			THREAD_LOG_INFO("NtQuerySecurityObject(0x{:X}, information=0x{:X}) -> {} bytes",
				handle, security_information, out.size());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "SetSecurityObject",
		[tokens, security_key](vcpu& cpu, const std::uint64_t handle,
			const std::uint32_t security_information, const addr_t security_descriptor) -> NTSTATUS
		{
			const auto key = security_key(handle);

			if (!key)
				return STATUS_INVALID_HANDLE;

			const auto incoming = read_descriptor(*cpu.curr_addr_space(), security_descriptor);

			if (!incoming)
				return STATUS_INVALID_SECURITY_DESCR;

			if (((security_information & owner_security_information) && !incoming->owner)
				|| ((security_information & group_security_information) && !incoming->group))
			{
				return STATUS_INVALID_SECURITY_DESCR;
			}

			std::scoped_lock lock(tokens->mtx);

			auto& current = tokens->descriptors.try_emplace(*key, default_descriptor()).first->second;

			if (security_information & owner_security_information)
				current.owner = incoming->owner;

			if (security_information & group_security_information)
				current.group = incoming->group;

			if (security_information & dacl_security_information)
				current.dacl = incoming->dacl;

			THREAD_LOG_INFO("NtSetSecurityObject(0x{:X}, information=0x{:X})", handle, security_information);

			return STATUS_SUCCESS;
		});
}
