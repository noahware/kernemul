#include "nt_io_ops.hpp"
#include "../win_kernel.hpp"
#include "../file_common.hpp"
#include "../filesystem.hpp"
#include "../mdl.hpp"
#include "../objects.hpp"
#include "../pipe.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <string_view>
#include <vector>

namespace
{

// CreateDisposition, and what IO_STATUS_BLOCK::Information reports for each.
enum create_disposition : std::uint32_t
{
	file_supersede    = 0,
	file_open         = 1,
	file_create       = 2,
	file_open_if      = 3,
	file_overwrite    = 4,
	file_overwrite_if = 5,
};

enum create_result : std::uint64_t
{
	file_superseded = 0,
	file_opened     = 1,
	file_created    = 2,
	file_overwritten = 3,
};

// The FILE_INFORMATION_CLASS values answerable about a file in this store.
enum file_information_class : std::uint32_t
{
	file_directory_information      = 1,
	file_full_directory_information = 2,
	file_both_directory_information = 3,
	file_basic_information          = 4,
	file_standard_information       = 5,
	file_internal_information       = 6,
	file_rename_information         = 10,
	file_link_information           = 11,
	file_disposition_information    = 13,
	file_position_information       = 14,
	file_mode_information           = 16,
	file_allocation_information     = 19,
	file_end_of_file_information    = 20,
	file_network_open_information   = 34,
	file_attribute_tag_information  = 35,
	file_io_completion_notification_information = 41,
	file_disposition_information_ex = 64,
	file_rename_information_ex      = 65,
	file_link_information_ex        = 72,
};

constexpr std::uint32_t file_disposition_delete = 0x1;
constexpr std::uint32_t file_disposition_posix_semantics = 0x2;

constexpr std::uint32_t file_fs_device_information = 4;
constexpr std::uint32_t file_device_disk = 0x07;

// FILE_TYPE_CHAR keeps the crt unbuffered; a disk stream would never be flushed here.
constexpr std::uint32_t file_device_console = 0x50;

constexpr std::uint32_t file_directory_file = 0x00000001;
constexpr std::uint32_t file_non_directory_file = 0x00000040;
constexpr std::uint32_t file_delete_on_close = 0x00001000;

#pragma pack(push, 4)
struct file_basic_information_t
{
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::uint32_t file_attributes;
	std::uint32_t padding;
};

struct file_standard_information_t
{
	std::int64_t  allocation_size;
	std::int64_t  end_of_file;
	std::uint32_t number_of_links;
	std::uint8_t  delete_pending;
	std::uint8_t  directory;
	std::uint16_t padding;
};

struct file_network_open_information_t
{
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::int64_t  allocation_size;
	std::int64_t  end_of_file;
	std::uint32_t file_attributes;
	std::uint32_t padding;
};

struct file_directory_information_t
{
	std::uint32_t next_entry_offset;
	std::uint32_t file_index;
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::int64_t  end_of_file;
	std::int64_t  allocation_size;
	std::uint32_t file_attributes;
	std::uint32_t file_name_length;
};

struct file_fs_device_information_t
{
	std::uint32_t device_type;
	std::uint32_t characteristics;
};
#pragma pack(pop)

static_assert(sizeof(file_basic_information_t) == 0x28);
static_assert(sizeof(file_standard_information_t) == 0x18);
static_assert(sizeof(file_network_open_information_t) == 0x38);
static_assert(sizeof(file_directory_information_t) == 0x40);

// Opening a device is a request of its own rather than a lookup: the driver is sent IRP_MJ_CREATE
// and may refuse, and the file object built for it is the per-open context every later request on
// the handle carries.
open_result open_device(vcpu& cpu, win_kernel_state& state, const addr_t device,
	const std::string& path, emu_object<std::uint64_t> file_handle)
{
	auto* const emulator = state.emulator();
	const auto file_object = emulator
		? state.pool.allocate(sizeof(_FILE_OBJECT), pool_tag("File"), true)
		: 0;

	if (!file_object)
		return { STATUS_INSUFFICIENT_RESOURCES, 0 };

	_FILE_OBJECT body{};
	body.Type = io_type_file;
	body.Size = static_cast<short>(sizeof(_FILE_OBJECT));
	body.DeviceObject = reinterpret_cast<_DEVICE_OBJECT*>(static_cast<std::uintptr_t>(device));

	emu_object<_FILE_OBJECT>(*cpu.curr_addr_space(), file_object).write(body);

	const auto result = emulator->dispatch_irp(cpu, {
		.major = irp_mj_create,
		.device_object = device,
		.file_object = file_object,
	});

	auto host = std::make_shared<file_host>();
	host->path = path;
	host->device_object = device;
	host->file_object = file_object;

	const std::uint8_t placeholder[sizeof(addr_t)] = {};
	const auto addr = result.status >= 0
		? state.objs.create_object(0, placeholder, sizeof(placeholder), std::move(host),
			prot_rw | prot_supervisor)
		: 0;

	if (!addr)
	{
		state.pool.free(file_object);
		THREAD_LOG_WARN("open_device('{}') refused, status=0x{:X}", path,
			static_cast<std::uint32_t>(result.status));
		return { result.status < 0 ? result.status : STATUS_INSUFFICIENT_RESOURCES, 0 };
	}

	if (file_handle)
		file_handle.write(state.sys_proc->handle_table().create_handle(addr, 0));

	THREAD_LOG_INFO("open_device('{}') -> device=0x{:X}, file object at 0x{:X}",
		path, device, file_object);

	return { STATUS_SUCCESS, file_opened };
}

open_result write_file_information(addr_space& space, const file_host& host,
	const std::uint32_t info_class, const addr_t buffer, const std::uint32_t length)
{
	const auto size = static_cast<std::int64_t>(host.file->size());

	switch (info_class)
	{
	case file_standard_information:
	{
		if (length < sizeof(file_standard_information_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		file_standard_information_t info{};
		info.allocation_size = size;
		info.end_of_file = size;
		info.number_of_links = 1;

		emu_object<file_standard_information_t>(space, buffer).write(info);

		return {STATUS_SUCCESS, sizeof(info)};
	}

	case file_basic_information:
	{
		if (length < sizeof(file_basic_information_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		file_basic_information_t info{};
		info.file_attributes = file_attribute_normal;

		emu_object<file_basic_information_t>(space, buffer).write(info);

		return {STATUS_SUCCESS, sizeof(info)};
	}

	case file_position_information:
	{
		if (length < sizeof(std::int64_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		emu_object<std::int64_t>(space, buffer)
			.write(static_cast<std::int64_t>(host.position));

		return {STATUS_SUCCESS, sizeof(std::int64_t)};
	}

	case file_attribute_tag_information:
	{
		if (length < 2 * sizeof(std::uint32_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		const std::uint32_t info[2] = {
			host.directory ? file_attribute_directory : file_attribute_normal, 0 };

		space.write_mem(buffer, info, sizeof(info));

		return {STATUS_SUCCESS, sizeof(info)};
	}

	case file_internal_information:
	{
		if (length < sizeof(std::int64_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		emu_object<std::int64_t>(space, buffer)
			.write(static_cast<std::int64_t>(std::hash<std::string>{}(host.path)));

		return {STATUS_SUCCESS, sizeof(std::int64_t)};
	}

	default:
		return {STATUS_INVALID_INFO_CLASS, 0};
	}
}

open_result open_file(win_kernel_state& state, const std::string& path,
	const std::uint32_t disposition, const std::uint32_t create_options,
	const std::uint32_t desired_access, emu_object<std::uint64_t> file_handle)
{
	if (path.empty() || disposition > file_overwrite_if)
		return { STATUS_OBJECT_NAME_INVALID, 0 };

	bool is_directory = state.fs.dir_exists(path);
	const bool existed = state.fs.exists(path) || is_directory;
	std::uint64_t information = file_opened;

	if (!existed && (create_options & file_directory_file)
		&& (disposition == file_create || disposition == file_open_if))
	{
		const auto slash = path.find_last_of('/');

		if (slash != std::string::npos && path.find('/') != slash
			&& !state.fs.dir_exists(path.substr(0, slash)))
		{
			return { STATUS_OBJECT_PATH_NOT_FOUND, 0 };
		}

		state.fs.create_directory(path);
		is_directory = true;
		information = file_created;
	}

	if (existed && is_directory && (create_options & file_non_directory_file))
		return { STATUS_FILE_IS_A_DIRECTORY, 0 };

	if (existed && !is_directory && (create_options & file_directory_file))
		return { STATUS_NOT_A_DIRECTORY, 0 };

	if (existed && disposition == file_create)
		return { STATUS_OBJECT_NAME_COLLISION, 0 };

	if (!existed && (disposition == file_open || disposition == file_overwrite))
		return { STATUS_OBJECT_NAME_NOT_FOUND, 0 };

	auto host = std::make_shared<file_host>();
	host->path = path;
	host->directory = is_directory;
	host->delete_on_close = (create_options & file_delete_on_close) != 0;

	if (is_directory)
	{
		host->file = std::make_shared<win_file>();
	}
	else
	{
		const bool keep = existed && (disposition == file_open || disposition == file_open_if);

		host->file = keep ? state.fs.open(path) : state.fs.create(path);
		information = !existed ? file_created : keep ? file_opened
			: disposition == file_supersede ? file_superseded : file_overwritten;
	}

	const auto handle = make_file_handle(state, std::move(host), file_handle_access(desired_access));

	if (!handle)
		return { STATUS_INSUFFICIENT_RESOURCES, 0 };

	if (file_handle)
		file_handle.write(handle);

	return { STATUS_SUCCESS, information };
}

std::optional<open_result> open_pipe(vcpu& cpu, win_kernel_state& state, const std::string& path,
	const std::uint32_t options, const std::uint32_t desired_access,
	emu_object<std::uint64_t> file_handle)
{
	const auto key = pipe_manager::pipe_key(path);

	if (!key)
		return std::nullopt;

	std::shared_ptr<pipe_host> host;
	open_result result;

	if (key->empty())
	{
		host = pipe_manager::open_root(options);
	}
	else
	{
		const auto opened = state.pipes->open_client(cpu, *key, options, host);
		result = { opened.status, opened.information };
	}

	if (result.status == STATUS_SUCCESS && file_handle)
		file_handle.write(make_file_handle(state, std::move(host), file_handle_access(desired_access)));

	return result;
}

NTSTATUS rename_target(win_kernel_state& state, addr_space& space, const addr_t buffer,
	const std::uint32_t length, std::string& out)
{
	constexpr std::size_t name_offset = 0x14;

	if (length < name_offset)
		return STATUS_INFO_LENGTH_MISMATCH;

	const auto root = space.read_mem<std::uint64_t>(buffer + 0x08);
	const auto name_length = space.read_mem<std::uint32_t>(buffer + 0x10);

	if (name_length % sizeof(char16_t) || name_offset + std::size_t{name_length} > length)
		return STATUS_INVALID_PARAMETER;

	std::u16string wide(name_length / sizeof(char16_t), u'\0');

	if (name_length)
		space.read_mem(buffer + name_offset, wide.data(), name_length);

	out = win_filesystem::normalize(narrow_wstring(wide));

	if (out.empty())
		return STATUS_OBJECT_NAME_INVALID;

	if (!root)
		return STATUS_SUCCESS;

	const auto directory = state.sys_proc->handle_table().get_object<file_host>(root);

	if (!directory)
		return STATUS_INVALID_HANDLE;

	if (!directory->directory)
		return STATUS_OBJECT_TYPE_MISMATCH;

	out = directory->path + "/" + out;

	return STATUS_SUCCESS;
}

NTSTATUS rename_status_to_ntstatus(const win_filesystem::rename_status status)
{
	switch (status)
	{
	case win_filesystem::rename_status::renamed:        return STATUS_SUCCESS;
	case win_filesystem::rename_status::not_found:      return STATUS_OBJECT_NAME_NOT_FOUND;
	case win_filesystem::rename_status::collision:      return STATUS_OBJECT_NAME_COLLISION;
	case win_filesystem::rename_status::path_not_found: return STATUS_OBJECT_PATH_NOT_FOUND;
	case win_filesystem::rename_status::unsupported:    return STATUS_NOT_SUPPORTED;
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS set_disposition(win_kernel_state& state, file_host& host, const bool remove,
	const bool immediately)
{
	if (remove && host.directory)
	{
		if (!state.fs.dir_exists(host.path))
			return STATUS_OBJECT_NAME_NOT_FOUND;

		if (state.fs.directory_has_entries(host.path))
			return STATUS_DIRECTORY_NOT_EMPTY;
	}

	if (remove && immediately)
		delete_host(state, host);

	host.delete_on_close = remove && !immediately;

	return STATUS_SUCCESS;
}

open_result set_file_information(win_kernel_state& state, vcpu& cpu,
	const std::uint64_t file_handle, const addr_t buffer, const std::uint32_t length,
	const std::uint32_t info_class)
{
	auto& handles = state.sys_proc->handle_table();

	if (const auto pipe = handles.get_object<pipe_host>(file_handle))
	{
		const auto result = state.pipes->set_information(cpu, *pipe, info_class, buffer, length);
		return { result.status, result.information };
	}

	const auto host = handles.get_object<file_host>(file_handle);

	if (!host)
		return { STATUS_INVALID_HANDLE, 0 };

	auto& space = *cpu.curr_addr_space();

	if (info_class == file_mode_information || info_class == file_io_completion_notification_information)
		return { length < sizeof(std::uint32_t) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS, 0 };

	if (host->is_device() || host->console)
		return { STATUS_INVALID_DEVICE_REQUEST, 0 };

	switch (info_class)
	{
	case file_basic_information:
		return { length < sizeof(file_basic_information_t) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS, 0 };

	case file_position_information:
	case file_end_of_file_information:
	case file_allocation_information:
	{
		if (length < sizeof(std::int64_t))
			return { STATUS_INFO_LENGTH_MISMATCH, 0 };

		const auto value = space.read_mem<std::int64_t>(buffer);

		if (value < 0)
			return { STATUS_INVALID_PARAMETER, 0 };

		if (info_class == file_position_information)
		{
			host->position = static_cast<std::uint64_t>(value);
		}
		else if (host->directory)
		{
			return { STATUS_FILE_IS_A_DIRECTORY, 0 };
		}
		else if (info_class == file_end_of_file_information || static_cast<std::size_t>(value) < host->file->size())
		{
			host->file->resize(static_cast<std::size_t>(value));
		}

		return { STATUS_SUCCESS, 0 };
	}

	case file_disposition_information:
	case file_disposition_information_ex:
	{
		const bool ex = info_class == file_disposition_information_ex;

		if (length < (ex ? sizeof(std::uint32_t) : sizeof(std::uint8_t)))
			return { STATUS_INFO_LENGTH_MISMATCH, 0 };

		const auto flags = ex ? space.read_mem<std::uint32_t>(buffer)
			: space.read_mem<std::uint8_t>(buffer) ? file_disposition_delete : 0;

		return { set_disposition(state, *host, flags & file_disposition_delete,
			flags & file_disposition_posix_semantics), 0 };
	}

	case file_rename_information:
	case file_rename_information_ex:
	case file_link_information:
	case file_link_information_ex:
	{
		const bool ex = info_class == file_rename_information_ex || info_class == file_link_information_ex;
		const bool linking = info_class == file_link_information || info_class == file_link_information_ex;

		if (length < sizeof(std::uint32_t))
			return { STATUS_INFO_LENGTH_MISMATCH, 0 };

		const bool replace = ex ? space.read_mem<std::uint32_t>(buffer) & 1
			: space.read_mem<std::uint8_t>(buffer) != 0;

		std::string target;

		if (const auto status = rename_target(state, space, buffer, length, target); status != STATUS_SUCCESS)
			return { status, 0 };

		if (!linking)
		{
			const auto status = rename_status_to_ntstatus(state.fs.rename(host->path, target, replace));

			if (status == STATUS_SUCCESS)
				host->path = target;

			return { status, 0 };
		}

		if (host->directory)
			return { STATUS_FILE_IS_A_DIRECTORY, 0 };

		if (state.fs.exists(target) || state.fs.dir_exists(target))
		{
			if (!replace || state.fs.dir_exists(target))
				return { STATUS_OBJECT_NAME_COLLISION, 0 };

			state.fs.unlink(target);
		}

		const auto slash = target.find_last_of('/');

		if (slash != std::string::npos && target.find('/') != slash
			&& !state.fs.dir_exists(target.substr(0, slash)))
		{
			return { STATUS_OBJECT_PATH_NOT_FOUND, 0 };
		}

		return { state.fs.link(host->path, target) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND, 0 };
	}

	default:
		THREAD_LOG_WARN("NtSetInformationFile('{}'): unhandled class {}", host->path, info_class);
		return { STATUS_INVALID_INFO_CLASS, 0 };
	}
}

}

// The io manager beyond the device object.
void modules::register_ntoskrnl_io_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// IO_WORKITEM is opaque to a driver, so the only thing it has to hold is what queueing
	// needs: the object the routine is called with.
	constexpr std::size_t io_work_item_size = 0x40;

	state.redirect(mod, "IoSizeofWorkItem", [](vcpu&) -> std::uint32_t
	{
		return static_cast<std::uint32_t>(io_work_item_size);
	});

	state.redirect(mod, "IoAllocateWorkItem",
		[st](vcpu& cpu, const addr_t device_object) -> addr_t
		{
			const auto item = st->pool.allocate(io_work_item_size, pool_tag("IoWi"), true);

			if (!item)
			{
				THREAD_LOG_ERR("IoAllocateWorkItem: out of pool");
				return 0;
			}

			cpu.curr_addr_space()->write_mem<addr_t>(item, device_object);

			THREAD_LOG_INFO("IoAllocateWorkItem(device=0x{:X}) -> 0x{:X}", device_object, item);

			return item;
		});

	state.redirect(mod, "IoFreeWorkItem", [st](vcpu&, const addr_t io_work_item)
	{
		if (io_work_item && !st->pool.free(io_work_item))
			THREAD_LOG_ERR("IoFreeWorkItem: 0x{:X} was not allocated here", io_work_item);
		else
			THREAD_LOG_INFO("IoFreeWorkItem(0x{:X})", io_work_item);
	});

	state.redirect(mod, "IoInitializeWorkItem",
		[](vcpu& cpu, const addr_t io_object, const addr_t io_work_item)
		{
			if (!io_work_item)
				return;

			cpu.curr_addr_space()->write_mem<addr_t>(io_work_item, io_object);

			THREAD_LOG_INFO("IoInitializeWorkItem(object=0x{:X}, item=0x{:X})",
				io_object, io_work_item);
		});

	state.redirect(mod, "IoUninitializeWorkItem", [](vcpu&, const addr_t io_work_item)
	{
		THREAD_LOG_INFO("IoUninitializeWorkItem(0x{:X})", io_work_item);
	});

	// No worker pool here, so the routine gets a thread of its own, as ExQueueWorkItem does.
	state.redirect(mod, "IoQueueWorkItem",
		[st](vcpu& cpu, const addr_t io_work_item, const addr_t worker_routine,
			const std::uint32_t queue_type, const addr_t context)
		{
			if (!io_work_item || !worker_routine)
			{
				THREAD_LOG_ERR("IoQueueWorkItem: item 0x{:X} has no routine", io_work_item);
				return;
			}

			const auto io_object = cpu.curr_addr_space()->read_mem<addr_t>(io_work_item);
			const std::uint64_t args[] = { io_object, context };
			const auto t = st->sys_proc->create_thread(cpu, worker_routine, args);

			THREAD_LOG_INFO("IoQueueWorkItem(item=0x{:X}, queue={}): routine 0x{:X}(0x{:X}, "
				"0x{:X}) runs as tid={}",
				io_work_item, queue_type, worker_routine, io_object, context, t->id());
		});

	// The page frame array stays empty until something fills it, as in the real one.
	state.redirect(mod, "IoAllocateMdl",
		[st](vcpu& cpu, const addr_t virtual_address, const std::uint32_t length,
			const bool secondary_buffer, const bool charge_quota,
			emu_object<_IRP> irp) -> addr_t
		{
			const auto size = mdl_size(virtual_address, length);
			const auto addr = st->pool.allocate(size, pool_tag("Mdl "), true);

			if (!addr)
			{
				THREAD_LOG_ERR("IoAllocateMdl: out of pool for {} bytes", size);
				return 0;
			}

			mdl_t mdl{};
			mdl.size = static_cast<std::int16_t>(size);
			mdl.start_va = mdl_page_base(virtual_address);
			mdl.byte_offset = static_cast<std::uint32_t>(mdl_page_offset(virtual_address));
			mdl.byte_count = length;

			emu_object<mdl_t>(*cpu.curr_addr_space(), addr).write(mdl);

			if (irp)
				THREAD_LOG_WARN("IoAllocateMdl: not chaining onto irp 0x{:X} ({}), because "
					"nothing dispatches IRPs", irp.address(),
					secondary_buffer ? "secondary" : "primary");

			THREAD_LOG_INFO("IoAllocateMdl(va=0x{:X}, {} bytes, charge_quota={}) -> 0x{:X} "
				"({} page(s))", virtual_address, length, charge_quota, addr,
				mdl_page_count(virtual_address, length));

			return addr;
		});

	state.redirect(mod, "IoFreeMdl", [st](vcpu&, const addr_t mdl)
	{
		const auto freed = st->pool.free(mdl);

		if (!freed)
		{
			THREAD_LOG_ERR("IoFreeMdl: 0x{:X} was not allocated here", mdl);
			return;
		}

		THREAD_LOG_INFO("IoFreeMdl(0x{:X}): {} bytes", mdl, freed->size);
	});

	state.redirect(mod, "IoDeleteSymbolicLink",
		[](vcpu&, emu_object<_UNICODE_STRING> symbolic_link_name) -> NTSTATUS
		{
			THREAD_LOG_INFO("IoDeleteSymbolicLink('{}')",
				narrow_wstring(win::read_unicode_string(symbolic_link_name)));

			return STATUS_SUCCESS;
		});

	// A create really opens a win_filesystem file, so a section over the handle reads real bytes.
	state.redirect(mod, "IoCreateFileEx",
		[st](vcpu& cpu, emu_object<std::uint64_t> file_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t allocation_size,
			const std::uint32_t file_attributes, const std::uint32_t share_access,
			const std::uint32_t disposition, const std::uint32_t create_options,
			const addr_t ea_buffer, const std::uint32_t ea_length,
			const std::uint32_t create_file_type, const addr_t extra_create_parameters,
			const std::uint32_t options, const addr_t driver_context) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			const emu_object<_UNICODE_STRING> name_obj(space, object_attributes
				? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
				: 0);

			const auto path = win_filesystem::normalize(
				narrow_wstring(win::read_unicode_string(name_obj)));

			THREAD_LOG_INFO("IoCreateFileEx('{}', access=0x{:X}, attributes=0x{:X}, share=0x{:X}, "
				"disposition={}, create_options=0x{:X}, ea=0x{:X}/{}, type={}, extra=0x{:X}, "
				"options=0x{:X}, context=0x{:X}, allocation_size=0x{:X})",
				path, desired_access, file_attributes, share_access, disposition, create_options,
				ea_buffer, ea_length, create_file_type, extra_create_parameters, options,
				driver_context, allocation_size);

			if (file_handle)
				file_handle.write(0);

			const auto device = st->find_device(path);

			const auto result = device
				? open_device(cpu, *st, device, path, file_handle)
				: open_file(*st, path, disposition, create_options, desired_access, file_handle);

			write_status_block(io_status_block, result);

			return result.status;
		});

	// Nothing gives a device a DOS name, so the answer is the path the file was opened by.
	state.redirect(mod, "IoQueryFileDosDeviceName",
		[st](vcpu& cpu, const addr_t file_object,
			emu_object<addr_t> object_name_information) -> NTSTATUS
		{
			if (!object_name_information)
				return STATUS_INVALID_PARAMETER;

			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host)
			{
				object_name_information.write(0);

				THREAD_LOG_WARN("IoQueryFileDosDeviceName: 0x{:X} is not a file object",
					file_object);

				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			auto& space = *cpu.curr_addr_space();
			const auto wide = widen_string(host->path);
			const auto bytes = static_cast<std::uint16_t>(wide.size() * sizeof(char16_t));
			const auto size = sizeof(_UNICODE_STRING) + bytes + sizeof(char16_t);

			const auto addr = st->pool.allocate(size, pool_tag("IoNm"), true);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto buffer = addr + sizeof(_UNICODE_STRING);

			_UNICODE_STRING name{};
			name.Length = bytes;
			name.MaximumLength = static_cast<std::uint16_t>(bytes + sizeof(char16_t));
			name.Buffer = guest_ptr<char16_t>(buffer);

			emu_object<_UNICODE_STRING>(space, addr).write(name);
			space.write_mem(buffer, wide.data(), bytes);

			object_name_information.write(addr);

			THREAD_LOG_INFO("IoQueryFileDosDeviceName(0x{:X}) -> '{}' at 0x{:X}",
				file_object, host->path, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoQueryFileInformation",
		[st](vcpu& cpu, const addr_t file_object, const std::uint32_t file_information_class,
			const std::uint32_t length, const addr_t file_information,
			emu_object<std::uint32_t> returned_length) -> NTSTATUS
		{
			if (returned_length)
				returned_length.write(0);

			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host)
			{
				THREAD_LOG_WARN("IoQueryFileInformation: 0x{:X} is not a file object", file_object);
				return STATUS_INVALID_PARAMETER;
			}

			const auto result = write_file_information(*cpu.curr_addr_space(), *host,
				file_information_class, file_information, length);

			if (returned_length)
				returned_length.write(static_cast<std::uint32_t>(result.information));

			THREAD_LOG_INFO("IoQueryFileInformation(0x{:X}, '{}', class={}) -> 0x{:X}",
				file_object, host->path, file_information_class, result.status);

			return result.status;
		});

	auto create_file = [st](vcpu& cpu, emu_object<std::uint64_t> file_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		emu_object<_IO_STATUS_BLOCK> io_status_block,
		[[maybe_unused]] emu_object<std::int64_t> allocation_size,
		const std::uint32_t file_attributes, const std::uint32_t share_access,
		const std::uint32_t create_disposition, const std::uint32_t create_options,
		const addr_t ea_buffer, const std::uint32_t ea_length) -> NTSTATUS
	{
		const auto path = object_path(*st, cpu, object_attributes);

		if (file_handle)
			file_handle.write(0);

		if (const auto piped = open_pipe(cpu, *st, path, create_options, desired_access, file_handle))
		{
			write_status_block(io_status_block, *piped);
			return piped->status;
		}

		// A device name is not in the filesystem, so it is resolved before it can be missed.
		const auto device = st->find_device(path);

		ea_parse_result extended;

		if (!device && ea_buffer && ea_length)
		{
			std::vector<std::uint8_t> raw(ea_length);
			cpu.curr_addr_space()->read_mem(ea_buffer, raw.data(), raw.size());

			extended = parse_ea_chain(raw);

			if (extended.status != STATUS_SUCCESS)
				return finish(io_status_block, extended.status);
		}

		const auto result = device
			? open_device(cpu, *st, device, path, file_handle)
			: open_file(*st, path, create_disposition, create_options, desired_access, file_handle);

		if (!extended.items.empty() && result.status == STATUS_SUCCESS && result.information != file_opened)
		{
			if (const auto host = st->sys_proc->handle_table().get_object<file_host>(
				file_handle.read()); host && host->file && !host->directory)
			{
				for (auto& item : extended.items)
					set_extended_attribute(*host->file, std::move(item));
			}
		}

		write_status_block(io_status_block, result);

		THREAD_LOG_INFO("NtCreateFile('{}', access=0x{:X}, attributes=0x{:X}, share=0x{:X}, "
			"disposition={}, options=0x{:X}, ea=0x{:X}/{}) -> 0x{:X}",
			path, desired_access, file_attributes, share_access, create_disposition,
			create_options, ea_buffer, ea_length, result.status);

		return result.status;
	};

	state.redirect_ntzw(mod, "OpenFile",
		[st](vcpu& cpu, emu_object<std::uint64_t> file_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t share_access,
			const std::uint32_t open_options) -> NTSTATUS
		{
			const auto path = object_path(*st, cpu, object_attributes);

			if (file_handle)
				file_handle.write(0);

			if (const auto piped = open_pipe(cpu, *st, path, open_options, desired_access,
				file_handle))
			{
				write_status_block(io_status_block, *piped);
				return piped->status;
			}

			const auto device = st->find_device(path);

			const auto result = device
				? open_device(cpu, *st, device, path, file_handle)
				: open_file(*st, path, file_open, open_options, desired_access, file_handle);

			write_status_block(io_status_block, result);

			THREAD_LOG_INFO("NtOpenFile('{}', access=0x{:X}, share=0x{:X}, options=0x{:X}) -> 0x{:X}",
				path, desired_access, share_access, open_options, result.status);

			return result.status;
		});

	auto read_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		const std::uint64_t event,
		[[maybe_unused]] const addr_t apc_routine, [[maybe_unused]] const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t buffer,
		const std::uint32_t length, emu_object<std::int64_t> byte_offset,
		[[maybe_unused]] emu_object<std::uint32_t> key) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (const auto pipe = st->sys_proc->handle_table().get_object<pipe_host>(file_handle))
		{
			if (!buffer || !length)
				return finish(io_status_block, STATUS_INVALID_PARAMETER);

			const auto result = st->pipes->read(cpu, *pipe,
				{ buffer, length, io_status_block.address(), event });

			if (result.pending)
				return result.status;

			signal_io_event(*st, cpu, event);

			return finish(io_status_block, result.status, result.information);
		}

		if (!host || !host->file)
		{
			THREAD_LOG_WARN("NtReadFile: handle 0x{:X} is not an open file", file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (!buffer || !length)
		{
			write_status_block(io_status_block, {STATUS_INVALID_PARAMETER, 0});
			return STATUS_INVALID_PARAMETER;
		}

		const auto data = host->file->data();
		const auto offset = file_offset(byte_offset, host->position);

		if (offset >= data.size())
		{
			THREAD_LOG_INFO("NtReadFile('{}'): offset {} is at or past the end ({} bytes)",
				host->path, offset, data.size());

			write_status_block(io_status_block, {STATUS_END_OF_FILE, 0});
			return STATUS_END_OF_FILE;
		}

		const auto copied = std::min<std::uint64_t>(length, data.size() - offset);

		if (lock_blocks(*host->file, offset, copied, host.get(), false))
			return finish(io_status_block, STATUS_FILE_LOCK_CONFLICT);

		cpu.curr_addr_space()->write_mem(buffer, data.data() + offset, copied);

		host->position = offset + copied;

		write_status_block(io_status_block, {STATUS_SUCCESS, copied});
		signal_io_event(*st, cpu, event);

		THREAD_LOG_INFO("NtReadFile('{}', offset={}, {} bytes asked) -> {} bytes",
			host->path, offset, length, copied);

		return STATUS_SUCCESS;
	};

	auto write_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		const std::uint64_t event,
		[[maybe_unused]] const addr_t apc_routine, [[maybe_unused]] const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t buffer,
		const std::uint32_t length, emu_object<std::int64_t> byte_offset,
		[[maybe_unused]] emu_object<std::uint32_t> key) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (const auto pipe = st->sys_proc->handle_table().get_object<pipe_host>(file_handle))
		{
			if (!buffer || !length)
				return finish(io_status_block, STATUS_INVALID_PARAMETER);

			std::vector<std::uint8_t> data(length);
			cpu.curr_addr_space()->read_mem(buffer, data.data(), length);

			const auto result = st->pipes->write(cpu, *pipe, data);

			signal_io_event(*st, cpu, event);

			return finish(io_status_block, result.status, result.information);
		}

		if (!host || (!host->file && !host->console))
		{
			THREAD_LOG_WARN("NtWriteFile: handle 0x{:X} is not an open file", file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (!buffer || !length)
		{
			write_status_block(io_status_block, {STATUS_INVALID_PARAMETER, 0});
			return STATUS_INVALID_PARAMETER;
		}

		std::vector<std::uint8_t> bytes(length);
		cpu.curr_addr_space()->read_mem(buffer, bytes.data(), length);

		// Unbuffered, so guest output and emulator logs stay in the order they happened.
		if (host->console)
		{
			std::fwrite(bytes.data(), 1, bytes.size(), stdout);
			std::fflush(stdout);

			write_status_block(io_status_block, {STATUS_SUCCESS, length});

			return STATUS_SUCCESS;
		}

		const auto offset = write_offset(*host, byte_offset);

		if (lock_blocks(*host->file, offset, length, host.get(), true))
			return finish(io_status_block, STATUS_FILE_LOCK_CONFLICT);

		write_file_bytes(*host->file, offset, bytes);

		host->position = offset + length;

		write_status_block(io_status_block, {STATUS_SUCCESS, length});
		signal_io_event(*st, cpu, event);

		THREAD_LOG_INFO("NtWriteFile('{}', offset={}, {} bytes)", host->path, offset, length);

		return STATUS_SUCCESS;
	};

	auto query_information_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t file_information,
		const std::uint32_t length, const std::uint32_t file_information_class) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (const auto pipe = st->sys_proc->handle_table().get_object<pipe_host>(file_handle))
		{
			const auto result = st->pipes->query_information(cpu, *pipe, file_information_class,
				file_information, length);

			return finish(io_status_block, result.status, result.information);
		}

		if (!host || !host->file)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();
		const auto status = write_file_information(space, *host, file_information_class,
			file_information, length);

		write_status_block(io_status_block, status);

		THREAD_LOG_INFO("NtQueryInformationFile('{}', class={}) -> 0x{:X}",
			host->path, file_information_class, status.status);

		return status.status;
	};

	auto flush_buffers_file = [st](vcpu&, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		write_status_block(io_status_block, {STATUS_SUCCESS, 0});

		THREAD_LOG_INFO("NtFlushBuffersFile('{}'): the store is memory, so there is nothing to "
			"flush", host->path);

		return STATUS_SUCCESS;
	};


	auto query_attributes_file = [st](vcpu& cpu,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes, const addr_t file_information,
		const bool full) -> NTSTATUS
	{
		const auto path = object_path(cpu, object_attributes);
		const auto file = st->fs.open(path);
		const bool directory = !file && st->fs.dir_exists(path);

		if (!file && !directory)
		{
			THREAD_LOG_WARN("NtQueryAttributesFile: '{}' is not there", path);
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		const auto size = static_cast<std::int64_t>(file ? file->size() : 0);
		const auto attributes = directory ? file_attribute_directory : file_attribute_normal;

		auto& space = *cpu.curr_addr_space();

		if (full)
		{
			file_network_open_information_t info{};
			info.allocation_size = size;
			info.end_of_file = size;
			info.file_attributes = attributes;

			emu_object<file_network_open_information_t>(space, file_information).write(info);
		}
		else
		{
			file_basic_information_t info{};
			info.file_attributes = attributes;

			emu_object<file_basic_information_t>(space, file_information).write(info);
		}

		THREAD_LOG_INFO("NtQuery{}AttributesFile('{}') -> {} bytes, attributes=0x{:X}",
			full ? "Full" : "", path, size, attributes);

		return STATUS_SUCCESS;
	};

	auto query_volume_information_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t fs_information,
		const std::uint32_t length, const std::uint32_t fs_information_class) -> NTSTATUS
	{
		auto& handles = st->sys_proc->handle_table();
		const auto host = handles.get_object<file_host>(file_handle);
		const bool pipe = handles.get_object<pipe_host>(file_handle) != nullptr;

		if (!host && !pipe)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		if (fs_information_class == file_fs_device_information)
		{
			if (length < sizeof(file_fs_device_information_t))
			{
				write_status_block(io_status_block, {STATUS_INFO_LENGTH_MISMATCH, 0});
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			const file_fs_device_information_t info{
				pipe ? file_device_named_pipe : host->console ? file_device_console : file_device_disk,
				0};
			emu_object<file_fs_device_information_t>(space, fs_information).write(info);

			write_status_block(io_status_block, {STATUS_SUCCESS, sizeof(info)});

			return STATUS_SUCCESS;
		}

		THREAD_LOG_WARN("NtQueryVolumeInformationFile: unhandled class {}", fs_information_class);

		write_status_block(io_status_block, {STATUS_INVALID_INFO_CLASS, 0});

		return STATUS_INVALID_INFO_CLASS;
	};

	state.redirect_ntzw(mod, "CreateFile", create_file);
	state.redirect_ntzw(mod, "ReadFile", read_file);
	state.redirect_ntzw(mod, "WriteFile", write_file);
	state.redirect_ntzw(mod, "QueryInformationFile", query_information_file);

	state.redirect_ntzw(mod, "SetInformationFile",
		[st](vcpu& cpu, const std::uint64_t file_handle,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t file_information,
			const std::uint32_t length, const std::uint32_t file_information_class) -> NTSTATUS
		{
			const auto result = set_file_information(*st, cpu, file_handle, file_information,
				length, file_information_class);

			write_status_block(io_status_block, result);

			return result.status;
		});
	state.redirect_ntzw(mod, "FlushBuffersFile", flush_buffers_file);

	// The store is memory, so every flavour of flush is the same nothing; what is left of the call
	// is the argument checking, which is the part a caller can observe.
	state.redirect_ntzw(mod, "FlushBuffersFileEx",
		[st](vcpu&, const std::uint64_t file_handle, const std::uint32_t flags,
			const addr_t parameters, const std::uint32_t parameters_size,
			emu_object<_IO_STATUS_BLOCK> io_status_block) -> NTSTATUS
		{
			constexpr std::uint32_t flush_file_data_only = 0x1;
			constexpr std::uint32_t flush_no_sync = 0x2;
			constexpr std::uint32_t flush_file_data_sync_only = 0x4;
			constexpr std::uint32_t file_write_data = 0x2;
			constexpr std::uint32_t file_append_data = 0x4;

			if (!io_status_block)
				return STATUS_INVALID_PARAMETER;

			// Nothing is defined for the parameter block yet, so any is refused.
			if (parameters || parameters_size
				|| (flags & ~(flush_file_data_only | flush_no_sync | flush_file_data_sync_only)))
				return finish(io_status_block, STATUS_INVALID_PARAMETER);

			const auto entry = st->sys_proc->handle_table().lookup_handle(file_handle);

			if (!entry)
				return finish(io_status_block, STATUS_INVALID_HANDLE);

			if (st->sys_proc->handle_table().get_object<pipe_host>(file_handle))
				return finish(io_status_block, STATUS_SUCCESS);

			const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

			if (!host)
				return finish(io_status_block, STATUS_INVALID_HANDLE);

			// The console is handed out with no access recorded, and is not a file to write back.
			if (!host->console && !(entry->access & (file_write_data | file_append_data)))
				return finish(io_status_block, STATUS_ACCESS_DENIED);

			// Flushing only what is needed to read the data back has no meaning for a directory.
			if ((flags & flush_file_data_sync_only) && host->directory)
				return finish(io_status_block, STATUS_INVALID_PARAMETER);

			THREAD_LOG_INFO("NtFlushBuffersFileEx('{}', flags=0x{:X}): the store is memory, so "
				"there is nothing to flush", host->path, flags);

			return finish(io_status_block, STATUS_SUCCESS);
		});
	state.redirect_ntzw(mod, "QueryVolumeInformationFile", query_volume_information_file);

	state.redirect_ntzw(mod, "QueryAttributesFile",
		[query_attributes_file](vcpu& cpu, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const addr_t file_information) -> NTSTATUS
		{
			return query_attributes_file(cpu, object_attributes, file_information, false);
		});

	state.redirect_ntzw(mod, "QueryFullAttributesFile",
		[query_attributes_file](vcpu& cpu, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const addr_t file_information) -> NTSTATUS
		{
			return query_attributes_file(cpu, object_attributes, file_information, true);
		});

	// A control on a device handle becomes an irp the driver's dispatch routine is called with.
	// The call is synchronous, so an event or an apc has nothing left to signal by the time it
	// returns -- a driver that completes a request later is reported as pending instead.
	auto control_file = [st](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
		const addr_t apc_routine, const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
		const addr_t input_buffer, const std::uint32_t input_length,
		const addr_t output_buffer, const std::uint32_t output_length,
		const std::string_view who) -> NTSTATUS
	{
		if (const auto pipe = st->sys_proc->handle_table().get_object<pipe_host>(file_handle))
		{
			const auto result = st->pipes->control(cpu, *pipe, control_code, input_buffer,
				input_length, output_buffer, output_length,
				{ output_buffer, output_length, io_status_block.address(), event });

			if (result.pending)
				return result.status;

			signal_io_event(*st, cpu, event);

			return finish(io_status_block, result.status, result.information);
		}

		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (!host->is_device())
		{
			THREAD_LOG_WARN("{}('{}', code=0x{:X}): not a device, so no driver handles it",
				who, host->path, control_code);
			write_status_block(io_status_block, {STATUS_INVALID_DEVICE_REQUEST, 0});
			return STATUS_INVALID_DEVICE_REQUEST;
		}

		auto* const emulator = st->emulator();

		if (!emulator)
		{
			write_status_block(io_status_block, {STATUS_INVALID_DEVICE_REQUEST, 0});
			return STATUS_INVALID_DEVICE_REQUEST;
		}

		const auto result = emulator->dispatch_irp(cpu, {
			.major = irp_mj_device_control,
			.device_object = host->device_object,
			.file_object = host->file_object,
			.control_code = control_code,
			.input_buffer = input_buffer,
			.input_length = input_length,
			.output_buffer = output_buffer,
			.output_length = output_length,
		});

		write_status_block(io_status_block, {result.status, result.information});

		if (event || apc_routine)
			THREAD_LOG_WARN("{}('{}'): handled synchronously, so the event at 0x{:X} and the apc "
				"at 0x{:X}/0x{:X} are not signalled", who, host->path, event, apc_routine,
				apc_context);

		THREAD_LOG_INFO("{}('{}', code=0x{:X}, in=0x{:X}/{}, out=0x{:X}/{}) -> 0x{:X}, {} byte(s)",
			who, host->path, control_code, input_buffer, input_length,
			output_buffer, output_length, static_cast<std::uint32_t>(result.status),
			result.information);

		return result.status;
	};

	state.redirect_ntzw(mod, "DeviceIoControlFile",
		[control_file](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
			const addr_t apc_routine, const addr_t apc_context,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
			const addr_t input_buffer, const std::uint32_t input_length,
			const addr_t output_buffer, const std::uint32_t output_length) -> NTSTATUS
		{
			return control_file(cpu, file_handle, event, apc_routine, apc_context,
				std::move(io_status_block), control_code, input_buffer, input_length,
				output_buffer, output_length, "NtDeviceIoControlFile");
		});

	state.redirect_ntzw(mod, "FsControlFile",
		[control_file](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
			const addr_t apc_routine, const addr_t apc_context,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
			const addr_t input_buffer, const std::uint32_t input_length,
			const addr_t output_buffer, const std::uint32_t output_length) -> NTSTATUS
		{
			return control_file(cpu, file_handle, event, apc_routine, apc_context,
				std::move(io_status_block), control_code, input_buffer, input_length,
				output_buffer, output_length, "NtFsControlFile");
		});
}
