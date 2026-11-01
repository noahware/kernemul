#include "whp.hpp"

#if defined(KERNEMUL_HAS_WHP)
#include "../mmu.hpp"
#include "../calling_conv.hpp"

#include <emulator/emulator.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <intrin.h>
#include <limits>
#include <optional>
#include <ranges>
#include <stdexcept>

namespace
{

constexpr std::size_t page_size = hm::emu::page_size;

bool host_has_umip()
{
	int regs[4]{};
	__cpuidex(regs, 7, 0);

	return (static_cast<std::uint32_t>(regs[2]) & (1u << 2)) != 0;
}

addr_t page_align(const addr_t addr)
{
	return addr & ~static_cast<addr_t>(page_size - 1);
}

bool is_seg_reg(const reg_t reg)
{
	return reg >= x86::cs && reg <= x86::ldtr;
}

bool is_table_reg(const reg_t reg)
{
	return reg == x86::gdtr || reg == x86::idtr;
}

bool is_xmm_reg(const reg_t reg)
{
	return reg >= x86::xmm0 && reg <= x86::xmm15;
}

hm::reg_t to_hm_reg(const reg_t reg)
{
	switch (reg)
	{
	case x86::rax:    return hm::reg::rax;
	case x86::rcx:    return hm::reg::rcx;
	case x86::rdx:    return hm::reg::rdx;
	case x86::rbx:    return hm::reg::rbx;
	case x86::rsp:    return hm::reg::rsp;
	case x86::rbp:    return hm::reg::rbp;
	case x86::rsi:    return hm::reg::rsi;
	case x86::rdi:    return hm::reg::rdi;
	case x86::r8:     return hm::reg::r8;
	case x86::r9:     return hm::reg::r9;
	case x86::r10:    return hm::reg::r10;
	case x86::r11:    return hm::reg::r11;
	case x86::r12:    return hm::reg::r12;
	case x86::r13:    return hm::reg::r13;
	case x86::r14:    return hm::reg::r14;
	case x86::r15:    return hm::reg::r15;
	case x86::rip:    return hm::reg::rip;
	case x86::rflags: return hm::reg::rflags;
	case x86::cr0:    return hm::reg::cr0;
	case x86::cr2:    return hm::reg::cr2;
	case x86::cr3:    return hm::reg::cr3;
	case x86::cr4:    return hm::reg::cr4;
	case x86::cr8:    return hm::reg::cr8;
	case x86::efer:   return hm::reg::efer;
	case x86::star:   return hm::reg::star;
	case x86::lstar:  return hm::reg::lstar;
	case x86::cstar:  return hm::reg::cstar;
	case x86::fmask:  return hm::reg::sfmask;
	case x86::cs:     return hm::reg::cs;
	case x86::ds:     return hm::reg::ds;
	case x86::es:     return hm::reg::es;
	case x86::ss:     return hm::reg::ss;
	case x86::fs:     return hm::reg::fs;
	case x86::gs:     return hm::reg::gs;
	case x86::tr:     return hm::reg::tr;
	case x86::ldtr:   return hm::reg::ldtr;
	case x86::gdtr:   return hm::reg::gdtr;
	case x86::idtr:   return hm::reg::idtr;
	case x86::xmm0:   return hm::reg::xmm0;
	case x86::xmm1:   return hm::reg::xmm1;
	case x86::xmm2:   return hm::reg::xmm2;
	case x86::xmm3:   return hm::reg::xmm3;
	case x86::xmm4:   return hm::reg::xmm4;
	case x86::xmm5:   return hm::reg::xmm5;
	case x86::xmm6:   return hm::reg::xmm6;
	case x86::xmm7:   return hm::reg::xmm7;
	case x86::xmm8:   return hm::reg::xmm8;
	case x86::xmm9:   return hm::reg::xmm9;
	case x86::xmm10:  return hm::reg::xmm10;
	case x86::xmm11:  return hm::reg::xmm11;
	case x86::xmm12:  return hm::reg::xmm12;
	case x86::xmm13:  return hm::reg::xmm13;
	case x86::xmm14:  return hm::reg::xmm14;
	case x86::xmm15:  return hm::reg::xmm15;
	default:
		throw std::runtime_error(std::format("no hypermulator register for {}", reg));
	}
}

// Descriptor form: type at bit 8, bits 19:16 the high limit nibble, neither in the compact form.
constexpr std::uint16_t to_hm_seg_attr(const std::uint32_t flags)
{
	return static_cast<std::uint16_t>((flags >> 8) & 0xF0FF);
}

constexpr std::uint32_t from_hm_seg_attr(const std::uint16_t attributes)
{
	return static_cast<std::uint32_t>(attributes & 0xF0FF) << 8;
}

hm::mem_prot to_hm_prot(const mem_prot prot)
{
	return static_cast<hm::mem_prot>(prot & prot_rwx);
}

mem_prot to_prot(const hm::mem_vmexit::access access)
{
	switch (access)
	{
	case hm::mem_vmexit::access::read:    return prot_read;
	case hm::mem_vmexit::access::write:   return prot_write;
	case hm::mem_vmexit::access::execute: return prot_exec;
	default:                              return prot_none;
	}
}

hm::hook_insn_t to_hm_insn(const hook_insn_t insn)
{
	switch (insn)
	{
	case hook_insn_t::cpuid: return hm::hook_insn_t::cpuid;
	case hook_insn_t::rdtsc: return hm::hook_insn_t::rdtsc;
	default:
		throw std::runtime_error("instruction hook unsupported by the hypermulator backend");
	}
}

// IA32_EFER.SCE. Clear, and syscall is #UD rather than an entry through LSTAR.
constexpr std::uint64_t efer_sce = 1;

constexpr std::uint64_t cr4_umip = 1ull << 11;

constexpr std::uint8_t syscall_insn[] = { 0x0F, 0x05 };

// RFLAGS.TF. On this backend the trap flag belongs to hypermulator, which arms it to step
// through a code hook's range; the guest never asked for it. It has to be kept out of every
// rflags the host reads or writes, because what the host does with one is save it into a
// thread being created or a CONTEXT being captured -- and a thread restored with a borrowed
// trap flag single-steps its first instruction into a debug trap that no step callback owns.
constexpr std::uint64_t rflags_tf = 1ull << 8;

bool is_usermode(const std::uint16_t cs_selector)
{
	return (cs_selector & 3) == 3;
}

}

struct x86_whp_emu::whp_hook : emu_hook
{
	hm::emu* backend = nullptr;
	bool syscall = false;
	std::vector<std::shared_ptr<hm::emu_hook>> native;

	~whp_hook() override
	{
		for (const auto& hook : native)
			backend->remove_hook(hook);
	}
};

x86_whp_vcpu::x86_whp_vcpu(x86_whp_emu* const emu, std::shared_ptr<const struct arch> arch,
	hm::emu& backend, const std::size_t id)
	:	vcpu(emu, std::move(arch), id), whp_(*emu), hm_(backend) { }

void x86_whp_vcpu::run()
{
	whp_.sync_syscall_enable(*this);

	hm_.run();
}

void x86_whp_vcpu::stop()
{
	hm_.stop();
}

void x86_whp_vcpu::try_stop()
{
	hm_.try_stop();
}

void x86_whp_vcpu::flush_tlb()
{
	// The partition has no flush of its own; reloading cr3 is the architectural one.
	reg(x86::cr3, reg<addr_t>(x86::cr3));
}

void x86_whp_vcpu::reg_read(const reg_t reg, void* const value, const std::size_t size)
{
	const auto native = to_hm_reg(reg);

	const auto read = [&](void* const buf, const std::size_t buf_size)
	{
		if (!hm_.reg_read(native, buf, buf_size))
			throw std::runtime_error(std::format("failed to read register {}", reg));
	};

	if (is_table_reg(reg))
	{
		hm::table_reg table{};
		read(&table, sizeof(table));

		const x86::seg_reg sr{ 0, table.base, table.limit, 0 };
		std::memcpy(value, &sr, std::min(size, sizeof(sr)));
		return;
	}

	if (is_seg_reg(reg))
	{
		hm::segment_reg segment{};
		read(&segment, sizeof(segment));

		const x86::seg_reg sr{
			segment.selector, segment.base, segment.limit, from_hm_seg_attr(segment.attributes)
		};
		std::memcpy(value, &sr, std::min(size, sizeof(sr)));
		return;
	}

	if (is_xmm_reg(reg))
	{
		x86::xmm_t xmm{};
		read(&xmm, sizeof(xmm));

		std::memcpy(value, &xmm, std::min(size, sizeof(xmm)));
		return;
	}

	std::uint64_t raw{};
	read(&raw, sizeof(raw));

	if (reg == x86::rflags)
		raw &= ~rflags_tf;

	std::memcpy(value, &raw, std::min(size, sizeof(raw)));
}

void x86_whp_vcpu::reg_write(const reg_t reg, const void* const value, const std::size_t size)
{
	const auto native = to_hm_reg(reg);

	const auto write = [&](const void* const buf, const std::size_t buf_size)
	{
		if (!hm_.reg_write(native, buf, buf_size))
			throw std::runtime_error(std::format("failed to write register {}", reg));
	};

	if (is_table_reg(reg) || is_seg_reg(reg))
	{
		x86::seg_reg sr{};
		std::memcpy(&sr, value, std::min(size, sizeof(sr)));

		if (is_table_reg(reg))
		{
			const hm::table_reg table{ {}, static_cast<std::uint16_t>(sr.limit), sr.base };
			write(&table, sizeof(table));
			return;
		}

		const hm::segment_reg segment{
			sr.base, sr.limit, sr.selector, to_hm_seg_attr(sr.flags)
		};
		write(&segment, sizeof(segment));
		return;
	}

	if (is_xmm_reg(reg))
	{
		x86::xmm_t xmm{};
		std::memcpy(&xmm, value, std::min(size, sizeof(xmm)));

		write(&xmm, sizeof(xmm));
		return;
	}

	std::uint64_t raw{};
	std::memcpy(&raw, value, std::min(size, sizeof(raw)));

	// WHP rejects a CR4 bit the host cpu lacks instead of ignoring it as the hardware would.
	if (reg == x86::cr4 && !host_has_umip())
		raw &= ~cr4_umip;

	// Whatever stepping is under way outlives this write: the value going in never carries a
	// trap flag of its own, since reg_read took it out of the one it came from.
	if (reg == x86::rflags)
	{
		std::uint64_t current{};

		if (!hm_.reg_read(native, &current, sizeof(current)))
			throw std::runtime_error("failed to read rflags back");

		raw = (raw & ~rflags_tf) | (current & rflags_tf);
	}

	write(&raw, sizeof(raw));
}

x86_whp_emu::x86_whp_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv)
	:	emu(std::make_shared<x86::arch>(), std::move(mem), std::move(call_conv)),
		hm_(std::make_unique<hm::emu>(hm::machine_mode_64)) { }

x86_whp_emu::~x86_whp_emu() = default;

std::shared_ptr<vcpu> x86_whp_emu::create_vcpu(const std::size_t id)
{
	if (id != 0)
		throw std::runtime_error("the hypermulator backend runs a single cpu");

	return std::make_shared<x86_whp_vcpu>(this, arch_, *hm_, id);
}

vcpu* x86_whp_emu::hook_cpu() const
{
	return cpus_.empty() ? nullptr : cpus_.front().get();
}

std::vector<x86_whp_emu::phys_run> x86_whp_emu::phys_runs(const addr_t start_addr,
	const addr_t end_addr, addr_space* const named)
{
	if (start_addr > end_addr)
		throw std::runtime_error("the whp backend needs a bounded hook range");

	const auto cpu = hook_cpu();
	const auto in_cpu = cpu ? cpu->curr_addr_space() : nullptr;
	const auto shared = default_addr_space();

	// The space the caller named, or the one the cpu is in when it named none. This backend
	// hooks physical memory, so the range has to be translated as the hook is installed -- and
	// a watch on a process still being built is installed before any cpu has entered it, so the
	// cpu is still in the kernel's space, which does not map the page at all.
	addr_space* const current = named ? named : in_cpu.get();
	addr_space* const fallback = shared.get();

	std::vector<phys_run> runs;

	for (addr_t va = start_addr; va <= end_addr;)
	{
		const addr_t page = page_align(va);
		const addr_t chunk_end = std::min(page + page_size, end_addr + 1);

		auto page_pa = current ? mem_->virt_to_phys(*current, page) : std::nullopt;

		if (!page_pa && fallback && current != fallback)
			page_pa = mem_->virt_to_phys(*fallback, page);

		if (!page_pa)
			throw std::runtime_error(std::format("hook range 0x{:X} is not mapped", va));

		const addr_t begin = *page_pa + (va - page);
		const addr_t end = begin + (chunk_end - va);

		if (!runs.empty() && runs.back().end == begin)
			runs.back().end = end;
		else
			runs.push_back({ begin, end });

		va = chunk_end;
	}

	return runs;
}

emu::hook_handle x86_whp_emu::add_hook(std::unique_ptr<whp_hook> hook)
{
	if (std::ranges::find(hook->native, nullptr) != hook->native.end())
		throw std::runtime_error("the partition refused a hook");

	auto* const handle = hook.get();
	hooks_.push_back(std::move(hook));

	return handle;
}

emu::hook_handle x86_whp_emu::hook_mem(const addr_t start_addr, const addr_t end_addr,
	const mem_prot prot, mem_hk_cb cb, addr_space* const space)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<mem_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr, space))
	{
		hook->native.push_back(hm_->hook_mem(to_hm_prot(prot),
			[this, &callback](const hm::addr_t addr, const hm::mem_vmexit::access access)
			{
				// hypermulator reports the address it resolved the access to, not its width.
				callback(*hook_cpu(), addr, 0, to_prot(access));
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_insn(const addr_t start_addr, const addr_t end_addr,
	const hook_insn_t insn, insn_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<insn_hk_cb>(hook->cb);

	// Instruction exits carry the virtual rip, so this range is not translated.
	const bool bounded = start_addr <= end_addr;

	// There is no syscall exit to ask for -- neither whp nor vmx under it has one -- so the
	// cpu is made to refuse the instruction instead: with EFER.SCE clear, syscall is #UD,
	// and a #UD is an exit hypermulator already reports. That clearing is confined to ring
	// 3, where no guest can read an msr to notice: a driver may rdmsr IA32_EFER, and an SCE
	// that is clear under it would say plainly that it is not on a real cpu.
	if (insn == hook_insn_t::syscall)
	{
		const auto start = bounded ? start_addr : 0;
		const auto end = bounded ? end_addr : std::numeric_limits<addr_t>::max();

		hook->syscall = true;
		++syscall_hooks_;

		// Registered ahead of the os layer's exception hook: a syscall's #UD looks exactly
		// like an illegal instruction, and whichever hook is asked first decides which it was.
		hook->native.push_back(hm_->hook_exception(
			[this, &callback, start, end](hm::exception_id)
			{ return try_dispatch_syscall(callback, start, end); },
			hm::excp_invalid_opcode, true));

		return add_hook(std::move(hook));
	}

	hook->native.push_back(hm_->hook_insn(to_hm_insn(insn),
		[this, &callback] { return callback(*hook_cpu()); },
		bounded ? start_addr : 0,
		bounded ? end_addr + 1 : 0));

	return add_hook(std::move(hook));
}

void x86_whp_emu::sync_syscall_enable(vcpu& cpu)
{
	const bool fault_on_syscall = syscall_hooks_ != 0
		&& is_usermode(cpu.reg<x86::seg_reg>(x86::cs).selector);

	const auto efer = cpu.reg(x86::efer);
	const auto wanted = fault_on_syscall ? (efer & ~efer_sce) : (efer | efer_sce);

	if (wanted != efer)
		cpu.reg(x86::efer, wanted);
}

bool x86_whp_emu::try_dispatch_syscall(insn_hk_cb& cb, const addr_t start, const addr_t end)
{
	auto* const cpu = hook_cpu();

	if (!cpu)
		return false;

	// Only ring 3 runs without SCE, so a #UD under a driver is the guest's own.
	if (!is_usermode(cpu->reg<x86::seg_reg>(x86::cs).selector))
		return false;

	const auto pc = cpu->pc();

	if (pc < start || pc > end)
		return false;

	std::uint8_t insn[sizeof(syscall_insn)]{};

	try
	{
		cpu->read_virt_mem(pc, insn, sizeof(insn));
	}
	catch (const std::exception&)
	{
		// The pc of a #UD is mapped or there would have been a page fault instead, but a
		// race with another cpu unmapping it would land here rather than take the machine down.
		return false;
	}

	if (!std::equal(std::begin(insn), std::end(insn), std::begin(syscall_insn)))
		return false;

	// A fault leaves the pc on the instruction, which is where the aarch64 hook hands its
	// callback the pc and what dispatch_syscall measures a handler's move against.
	if (!cb(*cpu))
		cpu->set_pc(pc + sizeof(syscall_insn));

	return true;
}

emu::hook_handle x86_whp_emu::hook_code(const addr_t start_addr, const addr_t end_addr,
	code_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<code_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr))
	{
		hook->native.push_back(hm_->hook_code(
			[this, &callback]
			{
				auto* const cpu = hook_cpu();
				callback(*cpu, cpu->pc(), 0);
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_basic_block(const addr_t start_addr, const addr_t end_addr,
	code_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<code_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr))
	{
		hook->native.push_back(hm_->hook_basic_block(
			[this, &callback]
			{
				auto* const cpu = hook_cpu();
				callback(*cpu, cpu->pc(), 0);
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_invalid_mem(const mem_prot access, invalid_mem_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = 1;
	hook->end = 0;
	hook->backend = hm_.get();

	auto& callback = std::get<invalid_mem_hk_cb>(hook->cb);

	hook->native.push_back(hm_->hook_invalid_mem(to_hm_prot(access),
		[this, &callback](const hm::addr_t addr, const hm::mem_vmexit::access type)
		{
			return callback(*hook_cpu(), addr, 0, to_prot(type));
		},
		0, 0));

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_exception(exception_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = 1;
	hook->end = 0;
	hook->backend = hm_.get();

	auto& callback = std::get<exception_hk_cb>(hook->cb);
	auto arch = arch_;

	hook->native.push_back(hm_->hook_exception(
		[this, &callback, arch](const hm::exception_id id)
		{
			return callback(*hook_cpu(), arch->intr_to_excp(static_cast<int>(id)));
		}));

	return add_hook(std::move(hook));
}

void x86_whp_emu::remove_hook(const hook_handle handle)
{
	const auto it = std::ranges::find_if(hooks_,
		[handle](const auto& hook) { return hook.get() == handle; });

	if (it == hooks_.end())
		return;

	// Nothing stands in for the instruction any more, so the next entry gives it back.
	if (static_cast<whp_hook*>(it->get())->syscall && syscall_hooks_ > 0)
		--syscall_hooks_;

	hooks_.erase(it);
}

void x86_whp_emu::map_phys_mem(const addr_t addr, const std::size_t size)
{
	// Wide open on purpose: a hook puts back all it did not ask about, so narrower grants more.
	if (!hm_->map_phys_mem(addr, size, hm::prot_rwx))
		throw std::runtime_error(std::format("failed to map 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::unmap_phys_mem(const addr_t addr, const std::size_t size, mem_prot)
{
	if (!hm_->unmap_phys_mem(addr, size))
		throw std::runtime_error(std::format("failed to unmap 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::read_phys_mem(const addr_t addr, void* const buf, const std::size_t size)
{
	if (!hm_->read_phys_mem(addr, buf, size))
		throw std::runtime_error(std::format("failed to read 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::write_phys_mem(const addr_t addr, const void* const buf, const std::size_t size)
{
	if (!hm_->write_phys_mem(addr, buf, size))
		throw std::runtime_error(std::format("failed to write 0x{:X} bytes at 0x{:X}", size, addr));
}

#endif
