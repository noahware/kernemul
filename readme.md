# Kernemul

Windows kernel driver and usermode app emulator for x86-64 and ARM64 targets. This can run on multiple host operating systems, such as Windows or Linux. AI was used for assisting development in this project, including the kernel handler implementations.

## How does it work?

The functions of multiple kernel drivers are reimplemented. When the guest (emulated code) executes them, execution is redirected to the host handlers where the call is processed. For emulated drivers, this redirection happens directly whenever they choose to execute. For usermode apps, only syscalls are redirected to the kernel handlers. This means that for usermode apps, most DLLs can be loaded and work fine as long as any syscalls it relies on have a matching kernel handler implemented.

### Example handler syntax

```cpp
state.redirect(mod, "KeSetEvent",
    [](vcpu&, emu_object<_KEVENT> event, const std::int32_t increment,
        const std::uint8_t wait) -> std::int32_t
    {
        if (!event)
            return 0;

        const auto previous = win::signal_state(event);
        win::set_signal_state(event, 1);

        THREAD_LOG_INFO("KeSetEvent(event=0x{:X}, increment={}, wait={}) -> {}",
            event.address(), increment, wait, previous);

        return previous;
    });
```

### What functions are redirected so far?

Currently, over 380+ functions are reimplemented in the kernel (120 of which are syscalls). Feel free to make a pull request with more implementations as this will allow more advanced apps to be supported. The kernel types were built for the version 26100 of the Windows kernel.

### Architecture abstraction

The emulator supports both ARM64 and x86-64 targets (64 bit only). The filesystems for the ARM64 and x86-64 systems are premade (see 'Getting started') so you can emulate binaries for ARM64 Windows without having to extract the kernel binaries yourselves.

## Emulator backends

There are 2 emulator backends: WHP (Windows hypervisor platform) and Unicorn. WHP uses virtualisation to execute instructions a lot faster but is only usable on Windows hosts. Unicorn is regular emulation but will work on different host operating systems too (e.g. Linux). The Unicorn implementation has host multithreading (emulates multiple vCPUs).

# Getting started
## Cloning

```
git clone --recurse-submodules https://github.com/noahware/kernemul.git
```

## Prebuilt filesystems

Filesystems contain the guest OS files that will be mapped in the emulator. These must be placed (extracted) in the same directory as you execute the emulator in.

[x86-64 fs](https://noahware.cc/fs_x86_64.zip)
[ARM64 fs](https://noahware.cc/fs_arm64.zip)

## Building

Build for whichever guest architecture/emulation backend you want to target.

x64 targets via WHP/Hyper-V (x64 Windows hosts only):

```
cmake --preset x64-whp && cmake --build --preset x64-whp
```

x64 targets via Unicorn (any host):

```
cmake --preset x64 && cmake --build --preset x64
```

ARM64 targets via Unicorn (any host):

```
cmake --preset arm64 && cmake --build --preset arm64
```

## Running

Place the images you want to emulate in their `fs` folder. This folder must be in the same directory as the emulator is executed in (the x86-64 folder is fs_x86_64 and the ARM folder is fs_arm64).

```
usage: kernemul [image...]

examples:
  kernemul test_driver.sys
  kernemul test_printf.exe test_seh.exe
  kernemul test_driver.sys test_user.exe
```

# Credits

- [John](https://github.com/invpcid) for helping with bugs on EAC, ideas, and some function implementation handlers.
- [Heinrich](https://github.com/nikgeneburn) for helping with anti-emulation on Unicorn.

# License

This project uses the GPL-2.0 license.
