#include "ntoskrnl.hpp"
#include "../win_kernel.hpp"
#include "../defs.hpp"
#include "../per_cpu.hpp"
#include "../user_setup.hpp"
#include "../string.hpp"
#include "../service_table.hpp"
#include "../../../util/log.hpp"

#include <cstddef>
#include <utility>
#include <cstdint>
#include <string_view>
#include <vector>
#include <type_traits>

// ntoskrnl's own initialisers never ran, so every global it would have filled in at boot still
// holds whatever the PE image carried. Most of those are zero, which is merely useless -- but a
// few are zero in a way that says something false, and KdDebuggerNotPresent is the worst of
// them: it is a BOOLEAN where TRUE means "no debugger", so reading 0 tells every driver that
// asks that a kernel debugger is attached.
//
// Only the globals whose right value the emulator actually owns are written here. Ones the
// image already has right -- MmHighestUserAddress, MmSystemRangeStart, MmUserProbeAddress,
// NtBuildNumber, NtGlobalFlag -- are left alone: they are per-build, per-arch facts, and this
// repo ships two image sets, so a hardcode here would be a wrong answer waiting for someone to
// swap the guest filesystem.
//
// MmPteBase names the base of the recursive page-table self map, which only x86-64 has one of;
// win_target::pte_base is zero on an architecture that does not.

namespace
{

// `exported` says how loud a miss is. A missing export means the wrong ntoskrnl and is worth
// shouting about; a pdb-only symbol is simply absent on an arch with no cached pdb -- fs_arm64
// has none -- and the run is still correct, so warning per symbol there would only teach people
// to ignore warnings.
//
// The bounds check is not optional: write_mem throws on an unmapped va, and all of this runs
// inside win_kernel_state's constructor, where an escaping exception kills startup with nothing
// in the log to say why.
template <typename T>
	requires std::is_trivially_copyable_v<T>
addr_t write_global(addr_space& space, const proc_module& mod, const std::string_view name,
	const T& value, const bool exported = true)
{
	const auto va = mod.find_symbol(name);

	if (!va)
	{
		if (exported)
			LOG_ERR("{} does not export '{}', so it keeps whatever the image holds",
				mod.name, name);
		else
			LOG_INFO("no symbol for '{}' in {}, so it keeps whatever the image holds",
				name, mod.name);

		return 0;
	}

	if (!mod.contains_addr(*va) || !mod.contains_addr(*va + sizeof(T) - 1))
	{
		LOG_ERR("'{}' resolves to 0x{:X}, which is outside {}", name, *va, mod.name);
		return 0;
	}

	space.write_mem(*va, value);

	if constexpr (std::is_integral_v<T>)
		LOG_INFO("{}!{} at 0x{:X} = 0x{:X}", mod.name, name, *va,
			static_cast<std::uint64_t>(value));
	else
		LOG_INFO("{}!{} at 0x{:X} initialised ({} bytes)", mod.name, name, *va, sizeof(T));

	return *va;
}

// An empty list head points at itself. Zero is the one shape that is never valid: the first
// walker to follow Flink dereferences null.
addr_t init_list_head(addr_space& space, const proc_module& mod, const std::string_view name,
	const bool exported = true)
{
	const auto va = write_global(space, mod, name, _LIST_ENTRY{}, exported);

	if (va)
		space.write_mem(va, guest_links(va, va));

	return va;
}

// What KiInitializeKernel and KiInitSystem do at boot: the image ships KiServiceTable as rvas,
// compacted in place to (offset from the table << 4) | stack argument dwords.
void init_service_tables(addr_space& space, const proc_module& mod)
{
	const auto table = mod.find_symbol("KiServiceTable");
	const auto limit_va = mod.find_symbol("KiServiceLimit");
	const auto args = mod.find_symbol("KiArgumentTable");

	if (!table || !limit_va || !args)
	{
		LOG_INFO("no service table symbols in {}, so KeServiceDescriptorTable stays empty",
			mod.name);
		return;
	}

	const auto limit = space.read_mem<std::uint32_t>(*limit_va);
	const auto table_rva = static_cast<std::uint32_t>(*table - mod.addr);

	for (std::uint32_t i = 0; i < limit; ++i)
	{
		const auto entry = *table + i * sizeof(std::uint32_t);
		const auto rva = space.read_mem<std::uint32_t>(entry);
		const auto arg_bytes = space.read_mem<std::uint8_t>(*args + i);

		space.write_mem<std::uint32_t>(entry, ((rva - table_rva) << 4) | (arg_bytes >> 2));
	}

	const service_table_descriptor_t descriptor{ .base = *table, .limit = limit, .number = *args };

	for (const auto name : { "KeServiceDescriptorTable", "KeServiceDescriptorTableShadow",
		"KeServiceDescriptorTableFilter" })
		write_global(space, mod, name, descriptor, false);
}

// KdDebuggerDataBlock is where a driver looks for what ntoskrnl never exports, PteBase above
// all: it names the self map, and a driver that cannot read it goes hunting for the self map by
// probing pml4 slots instead. The image already carries the block with every pointer relocated;
// what it does not carry is the header KdInitSystem stamps at boot, so only that is written
// here. Offsets are the published KDDEBUGGER_DATA64 layout, which the public pdb does not
// describe, and the size is the one ntoskrnl's own initialiser stores.
void init_debugger_data(addr_space& space, const proc_module& mod)
{
	constexpr std::uint32_t kdbg_owner_tag = 0x4742444B;

	constexpr std::size_t off_owner_tag = 0x10;
	constexpr std::size_t off_size = 0x14;
	constexpr std::size_t off_kern_base = 0x18;
	constexpr std::size_t off_pte_base = 0x360;

	const auto block = mod.find_symbol("KdDebuggerDataBlock");

	if (!block || !mod.contains_addr(*block) || !mod.contains_addr(*block + kdbg_block_size - 1))
	{
		LOG_INFO("no KdDebuggerDataBlock in {}, so a driver that wants PteBase has to hunt "
			"for the self map", mod.name);
		return;
	}

	space.write_mem<std::uint32_t>(*block + off_owner_tag, kdbg_owner_tag);
	space.write_mem<std::uint32_t>(*block + off_size, kdbg_block_size);
	space.write_mem<addr_t>(*block + off_kern_base, mod.addr);

	// The image's copy names the slot the build defaults to; the mmu decides the real one.
	if constexpr (win_target::pte_base)
		space.write_mem<addr_t>(*block + off_pte_base, win_target::pte_base);

	// The block is the only entry on the list ntoskrnl walks to find it.
	if (const auto head = mod.find_symbol("KdpDebuggerDataListHead");
		head && mod.contains_addr(*head))
	{
		space.write_mem(*head, guest_links(*block, *block));
		space.write_mem(*block, guest_links(*head, *head));
	}
	else
	{
		space.write_mem(*block, guest_links(*block, *block));
	}

	LOG_INFO("{}!KdDebuggerDataBlock at 0x{:X}: PteBase 0x{:X}, KernBase 0x{:X}",
		mod.name, *block, win_target::pte_base, mod.addr);
}

// NT gives the database a pml4 slot of its own and starts it at the slot boundary, so the entry
// for a frame is at a known offset from a 512gb aligned base. A driver that goes looking for the
// database rather than trusting the exported pointer relies on that, and a base bumped along with
// everything else in the kernel range does not have it.
constexpr addr_t pfn_database_base = 0xFFFFFA8000000000;

// The same array's physical base. Entries are written physically, not virtually, because they
// are written from inside the mmu while it holds its own lock -- which a virtual write would
// deadlock against. map_virt_phys is handed one contiguous run, so an entry is a multiply away.
addr_t pfn_database_phys = 0;

// The self map address of the entry that maps `va` at `level`: level 0 is the page's own pte,
// level 1 the pte of that pte, and so on up to the root. Pure arithmetic -- it reads no tables,
// so unlike a walk it does not care whether the self map has been installed yet.
[[maybe_unused]] addr_t pte_at_level(addr_t va, const unsigned level)
{
	for (unsigned i = 0; i <= level; ++i)
		va = win_target::pte_base + ((va / 0x1000) & 0xFFFFFFFFFull) * 8;

	return va;
}

// A frame the page tables hand out has an entry here describing it. A frame whose entry is blank
// is one the tables claim without the memory manager knowing, which is what a driver looking for
// tampered tables is looking for.
//
// Everything an entry holds is either a literal or already in the mmu's hand at the moment of
// mapping: the frame is the index, the virtual address gives PteAddress by arithmetic, and the
// table the entry sits in is PteFrame. Nothing is looked up, remembered, or walked.
void describe_frame(mmu& m, const addr_t pa, const addr_t va, const addr_t table_pa,
	const unsigned level)
{
	const auto page = m.page_size();
	const auto pfn = pa / page;

	if (pfn < lowest_physical_page || pfn > highest_physical_page)
		return;

	_MMPFN entry{};
	entry.u2.ShareCount = 1;
	entry.u3.ReferenceCount = 1;
	entry.u3.e1.PageLocation = 6;   // ActiveAndValid
	entry.u4.PfnExists = 1;
	entry.u4.ResidentPage = 1;
	entry.u4.PteFrame = table_pa / page;

	// Only an arch with a recursive self map can name the pte that maps a frame. ARM64 has
	// none, and real ARM64 Windows publishes no such fact about its own tables either.
	if constexpr (win_target::pte_base)
		entry.PteAddress = reinterpret_cast<_MMPTE*>(
			static_cast<std::uintptr_t>(pte_at_level(va, level)));

	m.write_phys(pfn_database_phys + pfn * sizeof(_MMPFN), entry);
}

// A frame nothing maps any more. Zeroed reads as PageLocation 0 (ZeroedPageList), no references
// and PfnExists clear -- a coherent "this frame is free", which beats an entry still claiming to
// be valid while the pte it names reads zero.
void forget_frame(mmu& m, const addr_t pa)
{
	const auto pfn = pa / m.page_size();

	if (pfn < lowest_physical_page || pfn > highest_physical_page)
		return;

	m.write_phys(pfn_database_phys + pfn * sizeof(_MMPFN), _MMPFN{});
}

// Ob creates one _OBJECT_TYPE per kind of object it manages and publishes a pointer to each in
// an exported global. Those globals are null in the image, and nothing here ran ObCreateObjectType
// to fill them, so a driver that reads one gets null and dereferences it -- Vanguard reads the
// process type's TotalNumberOfObjects, which is a load through the null pointer at +0x2C.
//
// The type is otherwise empty on purpose: the counts are the only fields anything here could
// answer honestly, and they belong to an object manager that keeps its bookkeeping host side.
addr_t init_object_type(addr_space& space, const proc_module& mod, const std::string_view global,
	const std::u16string_view name)
{
	const auto addr = space.alloc(sizeof(_OBJECT_TYPE), prot_rw | prot_supervisor);

	if (!addr)
	{
		LOG_ERR("no room for an _OBJECT_TYPE, so {} stays null", global);
		return 0;
	}

	_OBJECT_TYPE type{};
	type.Name = win::init_unicode_string(space, name, prot_rw | prot_supervisor);

	space.write_mem(addr, type);

	// Both lists are empty, and an empty list head points at itself rather than holding zeroes.
	for (const auto head : { addr + offsetof(_OBJECT_TYPE, TypeList),
		addr + offsetof(_OBJECT_TYPE, CallbackList) })
	{
		space.write_mem(head, guest_links(head, head));
	}

	if (!write_global<addr_t>(space, mod, global, addr))
		return 0;

	return addr;
}

}

// Built before anything else maps, so every page the machine goes on to map describes itself on
// the way in and nothing has to be swept up afterwards. The physical run is taken first, because
// its base has to be known before the hook can be called with it -- the array's own pages are
// mapped below and land in the database the same way everything else does.
void modules::init_pfn_database(addr_space& space)
{
	constexpr auto bytes = pfn_database_entries * sizeof(_MMPFN);

	static_assert(bytes == (highest_physical_page + 1) * sizeof(_MMPFN),
		"the database is indexed by raw frame number, so it is as long as the highest frame");

	auto& m = *space.mmu_;

	pfn_database_phys = m.alloc_phys(bytes, prot_rw);

	m.set_page_note([](mmu& mm, const addr_t pa, const addr_t va, const addr_t table_pa,
		const unsigned level, const bool mapped)
	{
		if (mapped)
			describe_frame(mm, pa, va, table_pa, level);
		else
			forget_frame(mm, pa);
	});

	m.map_virt_phys(space, pfn_database_base, pfn_database_phys, bytes,
		prot_rw | prot_supervisor);

	LOG_INFO("pfn database: {} entries of {} bytes at 0x{:X} (physical 0x{:X})",
		pfn_database_entries, sizeof(_MMPFN), pfn_database_base, pfn_database_phys);
}

void modules::init_ntoskrnl_globals(win_kernel_state& state, proc_module& mod)
{
	auto& space = state.kernel_space();

	// The headline. Everything else here is a convenience; this one is a correction.
	write_global<std::uint8_t>(space, mod, "KdDebuggerNotPresent", 1);

	// Both already read 0 out of the image, and 0 is what they should say. Written anyway so
	// the emulator's debugger story is stated once, in one place, rather than being two thirds
	// accidental -- swap in a differently built ntoskrnl and the story does not silently change.
	write_global<std::uint8_t>(space, mod, "KdDebuggerEnabled", 0);
	write_global<std::uint8_t>(space, mod, "KdEnteredDebugger", 0);

	// The image's own copy is a link-time guess; the real base is wherever it just mapped.
	write_global<addr_t>(space, mod, "PsNtosImageBase", mod.addr, false);

	// A driver can reach the same fact two ways, so the global and KeQueryTimeIncrement have to
	// agree -- a zero here against 156250 from the export is a kernel contradicting itself.
	write_global<std::uint32_t>(space, mod, "KeTimeIncrement", clock_increment_100ns, false);
	write_global<std::uint32_t>(space, mod, "ExpTickCountMultiplier",
		default_tick_count_multiplier, false);

	init_list_head(space, mod, "PiDDBCacheList", false);
	init_list_head(space, mod, "CallbackListHead", false);
	init_list_head(space, mod, "ExpCallbackListHead", false);

	// The lock that guards the cache list above. Initialised the way ExInitializeResourceLite
	// initialises one, so a driver that acquires it finds a well formed object.
	if (const auto va = write_global(space, mod, "PiDDBLock", _ERESOURCE{}, false))
	{
		const auto head = va + offsetof(_ERESOURCE, SystemResourcesList);
		space.write_mem(head, guest_links(head, head));
	}

	// The slot this names is the one the mmu actually points back at itself.
	if constexpr (win_target::pte_base)
		write_global<addr_t>(space, mod, "MmPteBase", win_target::pte_base, false);

	// Never publish a pointer that was not actually mapped. A bogus non-null one faults at a
	// plausible-looking kernel address and reads as a guest bug; null faults at 0 and is
	// recognisable on sight.
	if (pfn_database_phys && write_global<addr_t>(space, mod, "MmPfnDatabase",
		pfn_database_base, false))
	{
		LOG_INFO("MmPfnDatabase reads back 0x{:X}",
			space.read_mem<addr_t>(*mod.find_symbol("MmPfnDatabase")));
	}

	init_debugger_data(space, mod);
	init_service_tables(space, mod);

	// The four ObGetObjectType can name, so that reading a type back gives the same pointer the
	// global holds rather than null.
	init_object_type(space, mod, "PsProcessType", u"Process");
	init_object_type(space, mod, "PsThreadType", u"Thread");
	init_object_type(space, mod, "IoFileObjectType", u"File");
	init_object_type(space, mod, "MmSectionObjectType", u"Section");
	init_object_type(space, mod, "ExEventObjectType", u"Event");

	// The mapped ntoskrnl is the authority on its own build, and NtBuildNumber is exported on
	// both arches so this needs no pdb. The low 16 bits are the build; the rest are flags.
	if (const auto va = mod.find_symbol("NtBuildNumber"); va && mod.contains_addr(*va))
	{
		if (const auto build = space.read_mem<std::uint32_t>(*va) & 0xFFFF)
		{
			state.nt_build_number = build;
			LOG_INFO("{} reports build {}", mod.name, build);
		}
		else
		{
			LOG_WARN("{}!NtBuildNumber reads 0, so build {} is reported instead",
				mod.name, state.nt_build_number);
		}
	}

	// These three cannot be written yet: KiProcessorBlock is indexed by cpu number and holds
	// KPRCB pointers, and the other two want the final count -- none of which exists until
	// create_vcpus runs. Their addresses are cached now because the module is not kept.
	// Not written, only located: KPCR.LockArray points an entry at it, and that is built per
	// cpu, after this runs.
	state.non_paged_pool_lock = mod.find_symbol("NonPagedPoolLock").value_or(0);

	state.late_globals.ki_processor_block = mod.find_symbol("KiProcessorBlock").value_or(0);
	state.late_globals.ke_number_processors = mod.find_symbol("KeNumberProcessors").value_or(0);
	state.late_globals.ke_active_processors = mod.find_symbol("KeActiveProcessors").value_or(0);
}
