#pragma once
#include "arch.hpp"
#include "calling_conv.hpp"
#include "emu.hpp"
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

inline void guest_tail_call(vcpu& cpu, const addr_t routine,
	const std::span<const std::uint64_t> args)
{
	const auto& conv = *cpu.emu()->call_conv();

	for (std::size_t i = 0; i < args.size(); ++i)
		conv.write_arg(cpu, i, args[i]);

	cpu.set_pc(routine);
}

class guest_caller
{
public:
	std::uint64_t call(vcpu& cpu, addr_t routine, std::span<const std::uint64_t> args,
		std::size_t scratch = 0)
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		const auto& conv = *cpu.emu()->call_conv();

		std::vector<reg_val> saved(regs.size());

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &saved[i], a->reg_size(regs[i]));

		// Below the scratch rather than at it: the routine being called owns the shadow space
		// above its return address and spills its arguments there before it reads anything.
		// Starting it at the scratch base would put that space on top of whatever the caller
		// built for it -- an exception record, whose first field is the code the handler then
		// reads back as the low half of its own first argument.
		cpu.set_sp(scratch_base(cpu, scratch) - conv.sp_spadow());
		a->set_ret_addr(cpu, trampoline(cpu));

		for (std::size_t i = 0; i < args.size(); ++i)
			conv.write_arg(cpu, i, args[i]);

		cpu.set_pc(routine);
		cpu.run();

		const auto result = conv.read_ret(cpu);

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_write(regs[i], &saved[i], a->reg_size(regs[i]));

		return result;
	}

	static addr_t scratch_base(vcpu& cpu, const std::size_t size)
	{
		return (cpu.sp() - red_zone - size) & ~addr_t(0xF);
	}

private:
	// Clear of the handler frame, so a routine reading past its arguments stays off it.
	static constexpr addr_t red_zone = 0x100;

	// Returned to rather than executed: the hook fires on the address.
	addr_t trampoline(vcpu& cpu)
	{
		std::call_once(once_, [&]
		{
			trampoline_ = cpu.curr_addr_space()->alloc(0x1000, prot_rx | prot_supervisor);

			cpu.emu()->hook_code(trampoline_, trampoline_,
				[](vcpu& c, addr_t, std::size_t) { c.stop(); });
		});

		return trampoline_;
	}

	std::once_flag once_;
	addr_t trampoline_ = 0;
};
