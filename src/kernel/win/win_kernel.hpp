#pragma once
#include "../kernel.hpp"
#include "../../sym/symbol.hpp"
#include "process.hpp"
#include "exception.hpp"
#include "defs.hpp"
#include "modules/ntoskrnl.hpp"
#include "boot_seed.hpp"
#include "registry.hpp"
#include "filesystem.hpp"
#include "ethread.hpp"
#include "thread.hpp"
#include "driver.hpp"
#include "irp.hpp"
#include "mdl.hpp"
#include "per_cpu.hpp"
#include "objects.hpp"
#include "modules/fltmgr.hpp"
#include "modules/cng.hpp"
#include "modules/ci.hpp"
#include "modules/ndis.hpp"
#include "modules/tbs.hpp"
#include "modules/tdi.hpp"
#include "modules/win32k.hpp"
#include "pool.hpp"
#include "syscalls.hpp"
#include "status.hpp"
#include "../../emu/guest_call.hpp"
#include "../../target.hpp"
#include <cstring>
#include <filesystem>
#include <functional>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>

struct win_kernel_state : kernel_state
{
	win_obj_manager objs;
	win_pool pool;
	win_registry reg;
	win_filesystem fs;
	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;
	active_process_list_t active_process_list;
	emu_object<_KUSER_SHARED_DATA> kuser_shared_data;

	std::unique_ptr<win_syscall> syscalls = make_win_syscall();

	std::shared_ptr<class pipe_manager> pipes;

	// One per machine: the trampoline it returns through is a single address.
	guest_caller calls;

	std::unordered_map<addr_t, std::uint64_t> views;

	// Whether the calling thread's effective token holds a privilege, by LUID, and has it
	// enabled. Installed by the token module, which owns the tokens.
	std::function<bool(vcpu&, std::uint32_t)> privilege_enabled;

	std::int64_t boot_time = static_cast<std::int64_t>(win_system_time());

	// Read out of the mapped ntoskrnl rather than hardcoded: guest_fs_dir is a build time switch
	// across image sets that are already different builds, so the image is the only authority.
	std::uint32_t nt_build_number = default_build_number;

	// ntoskrnl globals whose value is not knowable until every cpu exists. Resolved in the
	// constructor because the module is not kept anywhere after that; written later.
	struct late_global_addrs
	{
		addr_t ki_processor_block = 0;
		addr_t ke_number_processors = 0;
		addr_t ke_active_processors = 0;
	};

	late_global_addrs late_globals;

	// ntoskrnl's own non paged pool lock, which is what KPCR.LockArray points one entry at.
	addr_t non_paged_pool_lock = 0;

	// The guest's lists live in guest memory; a push rewrites the head and the old tail.
	std::mutex list_mtx_;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	objs(*emu->default_addr_space()),
			pool(*emu->default_addr_space()),
			sys_proc(std::make_shared<win_kernel_proc>(objs.allocate_id(), *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc->id()] = sys_proc;
		auto& space = *emu->default_addr_space();

		// First, before a single image maps. From here the mmu writes a pfn entry for every
		// page it maps and every table that maps it, so the database is never behind and
		// nothing has to go back over what already exists.
		modules::init_pfn_database(space);

		// The host tree is laid out as the guest's drive, so a file sits where the guest names it.
		fs.load_dir(target::guest_fs_dir, root_dir_narrow);

		const auto ntoskrnl = map_redirect_module("ntoskrnl.exe", modules::register_ntoskrnl);

		if (ntoskrnl)
		{
			// Before any other module maps, not after. module_add_cb returns early while this
			// list has no address, so a module mapped ahead of it is simply never recorded --
			// which used to leave PsLoadedModuleList holding ntoskrnl alone.
			if (const auto ps_list = ntoskrnl->find_export("PsLoadedModuleList"))
			{
				loaded_module_list = loaded_module_list_t(space, *ps_list,
					"PsLoadedModuleList", true);
				loaded_module_list.init();
				sys_proc->module_add_cb(*ntoskrnl);
			}

			map_redirect_module("fltmgr.sys", modules::register_fltmgr);
			map_redirect_module("cng.sys", modules::register_cng);
			map_redirect_module("ci.dll", modules::register_ci);
			map_redirect_module("ndis.sys", modules::register_ndis);
			map_redirect_module("tbs.sys", modules::register_tbs);
			map_redirect_module("tdi.sys", modules::register_tdi);
			map_redirect_module("win32k.sys", modules::register_win32k);

			for (const auto name : { "hal.dll", "kd.dll", "wdfldr.sys" })
			{
				if (const auto file = sys_proc->open_system_image(name))
					krnl::map_img(*sys_proc, name, file->data(), true, true);
				else
					LOG_WARN("{} is not in {}", name, target::guest_fs_dir);
			}

			if (const auto ps_active = ntoskrnl->find_symbol("PsActiveProcessHead"))
			{
				active_process_list = active_process_list_t(space, *ps_active,
					"PsActiveProcessHead", true);
				active_process_list.init();
			}

			if (active_process_list.address())
			{
				const auto sys_eproc = insert_process(space, sys_proc->id(), "System");
				sys_proc->set_eprocess(sys_eproc);

				if (const auto ps_init = ntoskrnl->find_export("PsInitialSystemProcess"))
					space.write_mem(*ps_init, sys_eproc.address());

				seed_process_list(space);
			}

			build_syscall_table(*ntoskrnl);

			// Last in the block: it reads NtBuildNumber, which both the KUSER_SHARED_DATA write
			// below and the registry's CurrentBuildNumber then have to agree with.
			modules::init_ntoskrnl_globals(*this, *ntoskrnl);
		}

		win::seed_registry(*this);
		win::seed_filesystem(*this);

		space.mmu_->map_virt(space, kuser_shared_data_kernel_va,
			sizeof(_KUSER_SHARED_DATA), prot_rw | prot_supervisor);
		kuser_shared_data = emu_object<_KUSER_SHARED_DATA>(space, kuser_shared_data_kernel_va,
			"KUSER_SHARED_DATA", true);
		kuser_shared_data.write(make_default_kuser_shared_data(1));
		kuser_shared_data.field(&_KUSER_SHARED_DATA::NtBuildNumber).write(nt_build_number);
	}

	// Nothing in a mapped module is ever executed, so the imports are not resolved either.
	template <typename F>
	std::shared_ptr<proc_module> map_redirect_module(const std::string_view name, F&& registrar)
	{
		const auto file = sys_proc->open_system_image(name);

		if (!file)
		{
			LOG_WARN("{} is not in {}, so nothing importing from it will map",
				name, target::guest_fs_dir);
			return nullptr;
		}

		const auto mod = kernel_state::map_redirect_module(*sys_proc, name, file->data(), true);

		if (!mod)
		{
			LOG_ERR("failed to map {}", name);
			return nullptr;
		}

		registrar(*this, *mod);

		return mod;
	}

	// Which of the two ntoskrnl exports varies per function, so both spellings are bound.
	template <typename F>
	void redirect_ntzw(proc_module& mod, const std::string_view base, F&& fn)
	{
		const auto nt = "Nt" + std::string(base);
		const auto zw = "Zw" + std::string(base);
		const auto conv = emu_->call_conv();

		const bool bound_nt = try_redirect(mod, nt, make_redirect(conv, fn));
		const bool bound_zw = try_redirect(mod, zw, make_redirect(conv, fn));

		if (!bound_nt && !bound_zw)
			LOG_ERR("neither {} nor {} is in {}", nt, zw, mod.name);
	}

	std::shared_ptr<windows_process> create_dummy_process(addr_space& space,
		const std::string_view name)
	{
		const auto id = objs.allocate_id();

		auto proc = std::make_shared<windows_process>(
			id, emu_->default_addr_space(), objs, fs);

		proc->set_eprocess(insert_process(space, id, name));

		std::unique_lock lock(proc_mtx_);
		processes[id] = proc;

		return proc;
	}

	// Named for the half it covers rather than for its type: 'addr_space' is also a type this
	// class takes by reference, and a member function of that name would shadow it.
	[[nodiscard]] addr_space& kernel_space() const { return *emu_->default_addr_space(); }

	void set_emulator(windows_emulator* e) { emulator_ = e; }
	[[nodiscard]] windows_emulator* emulator() const noexcept { return emulator_; }

	// KUSER_SHARED_DATA is built before any cpu exists, so its count starts as a placeholder.
	// So do ntoskrnl's two copies of the same fact, which is why they are finished here too.
	void publish_processor_count(const std::size_t processors)
	{
		if (kuser_shared_data)
			kuser_shared_data.field(&_KUSER_SHARED_DATA::ActiveProcessorCount)
				.write(static_cast<std::uint32_t>(processors));

		auto& space = kernel_space();

		// One byte, deliberately. Whether this global is a CCHAR or a ULONG has moved between
		// wdk versions, and the image zero initialises it either way -- so writing just the low
		// byte is correct under both readings, and the count is never above 255.
		if (late_globals.ke_number_processors)
		{
			space.write_mem<std::uint8_t>(late_globals.ke_number_processors,
				static_cast<std::uint8_t>(std::min<std::size_t>(processors, 255)));

			LOG_INFO("KeNumberProcessors at 0x{:X} = {}",
				late_globals.ke_number_processors, processors);
		}

		if (late_globals.ke_active_processors)
		{
			space.write_mem<std::uint64_t>(late_globals.ke_active_processors,
				affinity_mask(processors));

			LOG_INFO("KeActiveProcessors at 0x{:X} = 0x{:X}",
				late_globals.ke_active_processors, affinity_mask(processors));
		}
	}

	void build_syscall_table(const proc_module& ntoskrnl)
	{
		if (!syscalls)
			return;

		add_stub_services("ntdll.dll", ntoskrnl);

		if (const auto win32k = sys_proc->find_module("win32k.sys"))
			add_stub_services("win32u.dll", *win32k);
	}

	// Nothing ever runs these stubs, so the guest has no reason to have them.
	void add_stub_services(const std::string_view name, const proc_module& impl)
	{
		const auto file = fs.open(std::string(system32_dir_narrow) + std::string(name));

		if (!file)
		{
			LOG_WARN("{} is not in the guest filesystem, so its services have no numbers",
				name);
			return;
		}

		const auto image = krnl::pe_virtual_image(file->data());

		if (image.empty())
		{
			LOG_WARN("{} is not a pe image, so its services have no numbers", name);
			return;
		}

		syscalls->add(name, image, impl);
	}

	// Nothing changes mode: the handler is native, so the guest stays in ring 3.
	bool dispatch_syscall(vcpu& cpu)
	{
		const auto saved_pc = cpu.pc();
		const auto id = syscalls ? syscalls->id(cpu) : 0;
		const auto handler = syscalls ? syscalls->find(id) : std::nullopt;
		const auto* fn = handler ? find_redirect(*handler) : nullptr;

		if (!fn)
		{
			const auto name = syscalls ? syscalls->name(id) : std::string_view();

			THREAD_LOG_WARN("unimplemented syscall 0x{:X} ({})", id,
				name.empty() ? std::string_view("unknown") : name);
			emu_->call_conv()->ret(cpu, static_cast<NTSTATUS>(STATUS_NOT_IMPLEMENTED));
			return false;
		}

		try
		{
			(*fn)(cpu);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_ERR("syscall 0x{:X} faulted: {}", id, e.what());
		}

		// A handler that moved the pc has said where to go, and stepping past would undo it.
		return cpu.pc() != saved_pc;
	}

	[[nodiscard]] std::shared_ptr<win_thread> find_ethread(const emu_object<_ETHREAD>& ethread)
	{
		if (!ethread)
			return {};

		std::shared_lock lock(proc_mtx_);

		for (const auto& [id, proc] : processes)
		{
			const auto win_proc = std::dynamic_pointer_cast<windows_process>(proc);

			if (!win_proc)
				continue;

			if (auto t = win_proc->find_ethread(ethread))
				return t;
		}

		return {};
	}

	void set_ldr_entry(const addr_t base, const addr_t entry) { ldr_entries_[base] = entry; }

	[[nodiscard]] addr_t ldr_entry(const addr_t base) const
	{
		const auto it = ldr_entries_.find(base);
		return it != ldr_entries_.end() ? it->second : 0;
	}

	struct driver_entry_args
	{
		emu_object<_DRIVER_OBJECT> driver_object;
		emu_object<_UNICODE_STRING> registry_path;
	};

	driver_entry_args create_driver(proc_module& mod, const std::u16string_view service_name)
	{
		auto& space = *emu_->default_addr_space();

		const auto drv = make_default_driver_object({
			.driver_name = win::init_unicode_string(space,
				std::u16string(driver_name_prefix) + std::u16string(service_name),
				prot_rw | prot_supervisor),
			.driver_start = mod.addr,
			.driver_size = mod.size,
			.driver_section = ldr_entry(mod.addr),
			.driver_init = mod.entry_point,
		});

		const auto body = objs.create_object(0, &drv, sizeof(drv),
			{}, prot_rw | prot_supervisor);

		emu_object<_DRIVER_OBJECT> obj(space, body,
			std::format("DRIVER_OBJECT[{}]", mod.name), true);

		const std::u16string reg_path_str =
			std::u16string(driver_services_key) + std::u16string(service_name);

		auto reg_path = win::allocate_unicode_string(space, reg_path_str, "RegistryPath",
			prot_rw | prot_supervisor);
		reg_path.monitor();

		// DriverEntry is handed this path, so the key behind it has to exist -- otherwise the
		// first thing a driver does with its own argument is fail to open it.
		{
			const auto key = reg.create_key(win_registry::normalize_path(reg_path_str));
			const auto image = std::string(system32_dir_narrow) + std::string(mod.name);

			key->set_string("ImagePath", image);
			key->set_string("DisplayName", std::string(mod.name));
			key->set_dword("Type", service_kernel_driver);
			key->set_dword("Start", service_demand_start);
			key->set_dword("ErrorControl", service_error_normal);

			// Where a minifilter looks for its altitude. Empty of instances is fine; absent is
			// not, because FltRegisterFilter treats a missing key as a setup failure.
			static_cast<void>(reg.create_key(
				win_registry::normalize_path(reg_path_str) + "/instances"));
		}

		// A kernel driver lives in System32\drivers on a real machine, and one that verifies
		// itself opens its own image back from there. Everything under the guest filesystem root
		// is loaded at the root, so the image is reachable by its bare name and nowhere else --
		// which is a path no driver looks in. The link costs nothing: both names reach the one
		// file, so a driver that reads its image gets the bytes it was actually mapped from.
		if (!fs.link(std::string(root_dir_narrow) + std::string(mod.name),
			std::string(drivers_dir_narrow) + std::string(mod.name)))
		{
			LOG_WARN("{} is not in the guest filesystem root, so a driver that opens its own "
				"image from System32\\drivers will not find it", mod.name);
		}

		LOG_INFO("driver object for {} at 0x{:X} (section=0x{:X}, registry path at 0x{:X})",
			mod.name, obj.address(), ldr_entry(mod.addr), reg_path.address());

		return { std::move(obj), std::move(reg_path) };
	}

	// A named device goes in the object manager's namespace rather than one of its own: the same
	// names an app reaches through NtOpenSymbolicLinkObject are the ones a driver creates here,
	// and only one of the two can be the namespace if they are to agree.
	void register_device(const std::string_view name, const addr_t device)
	{
		if (!name.empty() && device)
			objs.register_named_object(object_namespace_key(name), device);
	}

	// A link is an object in its own right, so NtQuerySymbolicLinkObject can read back what a
	// driver pointed it at rather than only what an app created itself.
	void register_device_link(const std::string_view link, const std::string_view target)
	{
		if (link.empty() || target.empty())
			return;

		auto host = std::make_shared<symbolic_link_host>();
		host->target = std::string(target);

		const std::uint8_t placeholder[sizeof(addr_t)] = {};
		const auto addr = objs.create_object(0, placeholder, sizeof(placeholder),
			std::move(host), prot_rw | prot_supervisor);

		if (addr)
			objs.register_named_object(object_namespace_key(link), addr);
		else
			LOG_ERR("out of memory for the symbolic link '{}'", link);
	}

	void unregister_device_name(const std::string_view name)
	{
		if (!name.empty())
			objs.unregister_named_object(object_namespace_key(name));
	}

	// A name in the device namespace, which is a device object or a link standing for one. Links
	// are followed rather than resolved once, so a link to a link still lands on the device; the
	// depth is bounded because nothing stops two links pointing at each other.
	[[nodiscard]] addr_t find_device(const std::string_view path)
	{
		auto name = object_namespace_key(path);

		for (int depth = 0; depth < 8; ++depth)
		{
			const auto addr = objs.lookup_named_object(name);

			// Anything else sharing the namespace is an event or a section, which a file open
			// has no business resolving to.
			if (!addr || objs.get_object<device_host>(addr))
				return addr;

			const auto link = objs.get_object<symbolic_link_host>(addr);

			if (!link)
				return 0;

			name = object_namespace_key(link->target);
		}

		LOG_WARN("device link '{}' resolves in a circle", path);

		return 0;
	}

	// The pdb records no size for a data symbol, so the array bound is not discoverable. One
	// processor group is the cap, and nothing here creates anywhere near that many cpus.
	static constexpr std::size_t ki_processor_block_max = processor_group_size;

	// Called in the order cpus are added: that order makes a block's index the cpu's own id.
	win_per_cpu& init_per_cpu(vcpu& cpu)
	{
		auto& space = kernel_space();

		auto& pcpu = per_cpu_.emplace_back(space, static_cast<std::uint32_t>(cpu.id()),
			non_paged_pool_lock);

		kuser_shared_data.field(&_KUSER_SHARED_DATA::ActiveProcessorCount)
			.write(static_cast<std::uint32_t>(per_cpu_.size()));

		// The array the guest walks to reach a cpu other than the one it is on.
		if (late_globals.ki_processor_block && cpu.id() < ki_processor_block_max)
		{
			const auto slot = late_globals.ki_processor_block + cpu.id() * sizeof(addr_t);

			space.write_mem<addr_t>(slot, pcpu.prcb());

			LOG_INFO("KiProcessorBlock[{}] at 0x{:X} = 0x{:X} (read back 0x{:X})",
				cpu.id(), slot, pcpu.prcb(), space.read_mem<addr_t>(slot));
		}

		return pcpu;
	}

	win_per_cpu* per_cpu(const std::size_t cpu_id)
	{
		return cpu_id < per_cpu_.size() ? &per_cpu_[cpu_id] : nullptr;
	}

	// Defined below, where windows_emulator -- which prepares the new address space -- is a
	// complete type.
	std::shared_ptr<process> create_process(std::string_view name) override;

private:
	windows_emulator* emulator_ = nullptr;

	[[nodiscard]] win_handle_table::handle_t open_console()
	{
		auto host = std::make_shared<file_host>();
		host->console = true;
		host->path = "\\Device\\ConDrv";

		const std::uint8_t body[sizeof(addr_t)] = {};
		const auto addr = objs.create_object(0, body, sizeof(body),
			std::move(host), prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		return sys_proc->handle_table().create_handle(addr, 0);
	}

	// A deque rather than a vector because each block is handed out by pointer as its cpu is added.
	std::deque<win_per_cpu> per_cpu_;

	std::unordered_map<addr_t, addr_t> ldr_entries_;

	emu_object<_EPROCESS> insert_process(addr_space& space, process::id_type id,
		std::string_view name, addr_t peb_address = 0)
	{
		_EPROCESS ep{};
		ep.UniqueProcessId = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id));
		ep.Peb = reinterpret_cast<_PEB*>(static_cast<std::uintptr_t>(peb_address));
		std::memcpy(ep.ImageFileName, name.data(), std::min(name.size(), sizeof(ep.ImageFileName)));

		std::scoped_lock lock(list_mtx_);
		auto obj = active_process_list.push_back(ep);

		kprocess_thread_list(space, obj.address(),
			std::format("KPROCESS.ThreadListHead[pid={}]", id), true).init();
		eprocess_thread_list(space, obj.address(),
			std::format("EPROCESS.ThreadListHead[pid={}]", id), true).init();

		return obj;
	}

	void seed_process_list(addr_space& space)
	{
		static constexpr std::string_view names[] = {
			"Registry",       "smss.exe",       "csrss.exe",      "wininit.exe",
			"csrss.exe",      "winlogon.exe",   "services.exe",   "lsass.exe",
			"svchost.exe",    "svchost.exe",    "svchost.exe",    "svchost.exe",
			"svchost.exe",    "svchost.exe",    "svchost.exe",    "svchost.exe",
			"fontdrvhost.ex", "fontdrvhost.ex", "dwm.exe",        "svchost.exe",
			"svchost.exe",    "svchost.exe",    "svchost.exe",    "svchost.exe",
			"svchost.exe",    "svchost.exe",    "WmiPrvSE.exe",   "spoolsv.exe",
			"MsMpEng.exe",    "NisSrv.exe",     "SearchIndexer.", "explorer.exe",
			"RuntimeBroker.", "sihost.exe",     "taskhostw.exe",  "ctfmon.exe",
			"conhost.exe",    "dllhost.exe",    "SearchHost.exe", "StartMenuExper",
		};

		for (const auto name : names)
			create_dummy_process(space, name);

		LOG_INFO("PsActiveProcessHead: seeded {} process(es) behind System",
			std::size(names));
	}

};

class windows_emulator : public os_emulator
{
public:
	explicit windows_emulator(std::shared_ptr<class emu> emu)
		: os_emulator(std::move(emu)), kernel_(emu_)
	{
		kernel_.sys_proc->set_scheduler(&scheduler_);
		kernel_.sys_proc->set_emulator(this);
		kernel_.set_emulator(this);
		excp_ = std::make_shared<win::win_exception>(kernel_);

		emu_->hook_insn(0, std::numeric_limits<addr_t>::max(), hook_insn_t::syscall,
			[this](vcpu& cpu) { return kernel_.dispatch_syscall(cpu); });
	}

	void create_vcpus(const std::size_t count) override
	{
		os_emulator::create_vcpus(count);
		kernel_.publish_processor_count(cpus().size());
	}

	win_kernel_state& kernel() { return kernel_; }

	[[nodiscard]] win_per_cpu* per_cpu(const vcpu& cpu) { return kernel_.per_cpu(cpu.id()); }

	// What a freshly created address space needs before anything is mapped into it. The self map
	// is the one top-half slot that is not shared: it names the root it sits in, so a copy of
	// the kernel's is a space claiming to be the kernel. Arches without one do nothing here.
	virtual void prepare_addr_space(::addr_space&) {}

	// Which register that is belongs to the arch: the GS base on x86-64, TPIDR_EL1 on ARM64.
	virtual void set_pcr(vcpu&, addr_t) {}

	// ARM64 has nothing of the sort, so there the KPCR is the only copy and this does nothing.
	virtual void set_hw_irql(vcpu&, irql_t) {}

	// `flags` is what was asked for; ContextFlags comes back saying what was filled in.
	virtual void capture_context(const reg_view& regs, emu_object<_CONTEXT> out,
		context_flags flags) = 0;

	static constexpr context_flags context_all{ ~0u };

	virtual void apply_context(const reg_view& regs, emu_object<_CONTEXT> in) = 0;

	// Every handler that moves the IRQL goes through here, so the two copies cannot drift.
	irql_t set_irql(vcpu& cpu, const irql_t irql)
	{
		const auto* pcpu = per_cpu(cpu);

		if (!pcpu)
			return passive_level;

		const auto old = pcpu->irql();
		pcpu->set_irql(irql);
		set_hw_irql(cpu, irql);

		return old;
	}

	[[nodiscard]] irql_t irql(vcpu& cpu)
	{
		const auto* pcpu = per_cpu(cpu);
		return pcpu ? pcpu->irql() : passive_level;
	}

	std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, const addr_t start_addr) override
	{
		return kernel_.sys_proc->create_thread(cpu, start_addr);
	}

	// ARM64 services the system registers that report cpu features; x86-64 needs none of it.
	virtual bool emulate_privileged_insn(vcpu&) { return false; }

	virtual void init_thread_teb(thread&, vcpu&, addr_t) {}

	virtual void setup_loader_frame(thread&, vcpu&, addr_t, addr_t, addr_t) {}

	// A thread the guest asked for, started the way Windows starts one: in ntdll's loader, on a
	// context that continues into RtlUserThreadStart(start_addr, argument). It belongs to the
	// process that asked for it -- its start address is a user va, and only that process's
	// address space maps it, so a thread of the system process would fault on the first fetch.
	std::shared_ptr<thread> create_user_thread(vcpu& cpu, win_user_proc& proc,
		const addr_t start_addr, const addr_t argument, const std::size_t stack_size,
		const bool suspended)
	{
		const auto ntdll = proc.find_module(ntdll_name);

		if (!ntdll)
		{
			LOG_ERR("{} is not mapped in pid={}, so it has no loader to start a thread in",
				ntdll_name, proc.id());
			return {};
		}

		const auto ldr_init = ntdll->find_symbol(loader_thread_startup);

		if (!ldr_init)
		{
			LOG_ERR("{}!{} not found", ntdll_name, loader_thread_startup);
			return {};
		}

		auto t = proc.create_suspended_thread(cpu, *ldr_init, {}, stack_size);

		if (!t)
			return {};

		setup_loader_frame(*t, cpu, start_addr, ntdll->addr, argument);

		// A thread the guest asked to start suspended is started all the same: started is what
		// the scheduler looks at, and the suspend count is what holds it until a resume.
		if (suspended)
			std::static_pointer_cast<win_thread>(t)->suspend();

		t->start();

		return t;
	}

	// False if this one cannot yet, and the fault is then dispatched here instead.
	virtual bool setup_exception_frame(vcpu&, addr_t, const win::exception_info&) { return false; }

	// The two selectors a dispatch runs between. Unicorn does not fault a supervisor page fetched
	// at CPL 3, but whp runs the guest on the real cpu and does, so the mode is raised either way.
	virtual void set_kernel_mode(vcpu&, bool) {}

	// Builds a request the way the io manager does, hands it to the driver's dispatch routine and
	// reads the result back out of it. It runs on the calling thread's own cpu: driver code and
	// device objects live in the kernel half, which every address space aliases, so there is
	// nothing to switch to reach them.
	irp_result dispatch_irp(vcpu& cpu, const irp_request& req)
	{
		auto& space = *cpu.curr_addr_space();

		const auto device = kernel_.objs.get_object<device_host>(req.device_object);

		if (!device)
		{
			LOG_ERR("irp: 0x{:X} is not a device object", req.device_object);
			return { STATUS_INVALID_PARAMETER, 0 };
		}

		const auto routine = space.read_mem<addr_t>(device->driver_object
			+ offsetof(_DRIVER_OBJECT, MajorFunction) + req.major * sizeof(addr_t));

		if (!routine)
		{
			LOG_WARN("irp: driver 0x{:X} has no handler for major 0x{:X}",
				device->driver_object, req.major);
			return { STATUS_INVALID_DEVICE_REQUEST, 0 };
		}

		const bool is_control = req.major == irp_mj_device_control;
		const auto method = is_control ? control_code_method(req.control_code) : method_buffered;

		// Only a buffered control copies. A direct one hands the driver an mdl over the caller's
		// own output pages, and neither hands over the addresses themselves.
		const bool copies_out = is_control && method == method_buffered;
		const bool copies_in = is_control && method != method_neither;
		const bool needs_mdl = is_control
			&& (method == method_in_direct || method == method_out_direct);

		const pool_block buffer(kernel_.pool,
			copies_in ? std::max(req.input_length, copies_out ? req.output_length : 0u) : 0,
			irp_pool_tag);

		const pool_block mdl(kernel_.pool,
			needs_mdl && req.output_buffer ? mdl_size(req.output_buffer, req.output_length) : 0,
			pool_tag("Mdl "));

		const pool_block request(kernel_.pool,
			sizeof(_IRP) + irp_stack_count * sizeof(_IO_STACK_LOCATION), irp_pool_tag);

		if (!request.addr() || (copies_in && req.input_length && !buffer.addr()))
		{
			LOG_ERR("irp: out of pool for a {} byte request", req.input_length);
			return { STATUS_INSUFFICIENT_RESOURCES, 0 };
		}

		if (copies_in)
			copy_guest(space, buffer.addr(), req.input_buffer, req.input_length);

		// Nothing here pages, so the mdl is born mapped: MmGetSystemAddressForMdl is a macro that
		// returns MappedSystemVa when that flag is set, rather than asking for a mapping the
		// emulator would have to invent.
		if (mdl.addr())
		{
			mdl_t m{};
			m.size = static_cast<std::int16_t>(mdl_size(req.output_buffer, req.output_length));
			m.mdl_flags = mdl_mapped_to_system_va | mdl_pages_locked;
			m.start_va = mdl_page_base(req.output_buffer);
			m.byte_offset = static_cast<std::uint32_t>(mdl_page_offset(req.output_buffer));
			m.byte_count = req.output_length;
			m.mapped_system_va = req.output_buffer;

			emu_object<mdl_t>(space, mdl.addr()).write(m);
		}

		const auto irp = request.addr();
		const auto stack_addr = irp + sizeof(_IRP);
		const auto ptr = [](const addr_t a) { return static_cast<std::uintptr_t>(a); };

		_IRP body{};
		body.Type = io_type_irp;
		body.Size = static_cast<unsigned short>(sizeof(_IRP) + sizeof(_IO_STACK_LOCATION));
		body.StackCount = static_cast<char>(irp_stack_count);
		body.CurrentLocation = static_cast<char>(irp_stack_count);
		body.RequestorMode = static_cast<char>(UserMode);
		body.Flags = copies_in
			? irp_buffered_io | irp_deallocate_buffer
				| (req.input_length ? irp_input_operation : 0u)
			: 0u;
		body.MdlAddress = reinterpret_cast<_MDL*>(ptr(mdl.addr()));
		body.AssociatedIrp.SystemBuffer = reinterpret_cast<void*>(ptr(buffer.addr()));
		body.UserBuffer = reinterpret_cast<void*>(ptr(copies_out ? 0 : req.output_buffer));
		body.Tail.Overlay.CurrentStackLocation =
			reinterpret_cast<_IO_STACK_LOCATION*>(ptr(stack_addr));

		_IO_STACK_LOCATION stack{};
		stack.MajorFunction = req.major;
		stack.DeviceObject = reinterpret_cast<_DEVICE_OBJECT*>(ptr(req.device_object));
		stack.FileObject = reinterpret_cast<_FILE_OBJECT*>(ptr(req.file_object));

		if (is_control)
		{
			auto& params = stack.Parameters.DeviceIoControl;
			params.IoControlCode = req.control_code;
			params.InputBufferLength = req.input_length;
			params.OutputBufferLength = req.output_length;
			params.Type3InputBuffer = reinterpret_cast<void*>(
				ptr(method == method_neither ? req.input_buffer : 0));
		}

		emu_object<_IRP>(space, irp).write(body);
		emu_object<_IO_STACK_LOCATION>(space, stack_addr).write(stack);

		// Driver code lives in supervisor pages, so the dispatch runs in kernel mode and the
		// caller's thread goes back to user mode after it.
		set_kernel_mode(cpu, true);
		kernel_.calls.call(cpu, routine, { { req.device_object, irp } });
		set_kernel_mode(cpu, false);

		const emu_object<_IRP> done(space, irp);
		const auto io_status = done.field(&_IRP::IoStatus).read();

		irp_result result{ static_cast<NTSTATUS>(io_status.Status),
			static_cast<std::uint64_t>(io_status.Information) };

		// IoCompleteRequest pops every stack location, so a request it has been through is the
		// one whose current location has gone past the last.
		const bool completed =
			done.field(&_IRP::CurrentLocation).read() > done.field(&_IRP::StackCount).read();

		// A dispatch routine that returned without completing has kept the request, and nothing
		// here runs the driver's later completion -- so the caller is told, rather than handed a
		// status block the driver never filled in.
		if (!completed)
		{
			LOG_WARN("irp 0x{:X}: driver 0x{:X} returned 0x{:X} without completing the request",
				irp, device->driver_object, result.status);

			return { result.status == STATUS_SUCCESS ? STATUS_PENDING : result.status, 0 };
		}

		// Buffered output goes back the way it came, and only as far as the driver said it wrote.
		if (copies_out)
			copy_guest(space, req.output_buffer, buffer.addr(),
				std::min<std::uint64_t>(result.information, req.output_length));

		return result;
	}

	struct user_process_args
	{
		std::shared_ptr<win_user_proc> proc;
		std::shared_ptr<proc_module> image;
		std::shared_ptr<thread> thread;
	};

	// The thread starts at ntdll's LdrInitializeThunk, not at the image's entry point.
	user_process_args create_user_process(vcpu& cpu, const std::string_view exe_name,
		const bool suspended = false, const std::string_view image_path = {})
	{
		auto proc = std::dynamic_pointer_cast<win_user_proc>(
			kernel_.create_process(image_path.empty() ? exe_name : image_path));

		if (!proc)
		{
			LOG_ERR("failed to create a process for {}", exe_name);
			return {};
		}

		proc->set_scheduler(&scheduler_);

		const auto ntdll = proc->find_module(ntdll_name);

		if (!ntdll)
		{
			LOG_ERR("{} is not in {}, so no user process can start",
				ntdll_name, target::guest_fs_dir);
			return {};
		}

		const auto image = proc->load_module(exe_name, false);

		if (!image)
		{
			LOG_ERR("{} is not in {}", exe_name, target::guest_fs_dir);
			return {};
		}

		proc->set_image_base(image->addr);

		const auto ldr_init = ntdll->find_symbol(loader_thread_startup);

		if (!ldr_init)
		{
			LOG_ERR("{}!{} not found", ntdll_name, loader_thread_startup);
			return {};
		}

		auto t = proc->create_suspended_thread(cpu, *ldr_init);

		if (!t)
			return {};

		setup_loader_frame(*t, cpu, image->entry_point, ntdll->addr, 0);

		if (suspended)
			std::static_pointer_cast<win_thread>(t)->suspend();

		t->start();

		LOG_INFO("user process {} (pid={}): image at 0x{:X}, entry 0x{:X}, loader at 0x{:X}{}",
			exe_name, proc->id(), image->addr, image->entry_point, *ldr_init,
			suspended ? ", suspended" : "");

		return { std::move(proc), image, std::move(t) };
	}

private:
	win_kernel_state kernel_;
};

inline std::shared_ptr<process> win_kernel_state::create_process(const std::string_view name)
{
	std::unique_lock lock(proc_mtx_);
	const auto id = objs.allocate_id();
	auto& kspace = *emu_->default_addr_space();
	const auto kusd_pa = *kspace.mmu_->virt_to_phys(kspace, kuser_shared_data_kernel_va);
	auto space = emu_->mem()->create_addr_space();

	// A new space copies the kernel half wholesale, and the self map slot is in that half --
	// so without this the space's own self map names the kernel's tables rather than its
	// own, and a walk through it describes somebody else's page tables. It is the one
	// top-half entry that is not meant to be shared.
	if (emulator_)
		emulator_->prepare_addr_space(*space);

	auto proc = std::make_shared<win_user_proc>(id, std::move(space), objs, fs,
		kusd_pa, name, emu_->cpus().size());
	proc->set_emulator(emulator_);
	processes[id] = proc;

	if (active_process_list.address())
	{
		const auto eproc = insert_process(*emu_->default_addr_space(), id, name,
			proc->peb().address());
		proc->set_eprocess(eproc);
	}

	const auto console = open_console();
	proc->set_std_handles(console, console, console);

	return proc;
}
