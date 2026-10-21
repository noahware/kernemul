#pragma once
#include "dispatcher.hpp"
#include "filesystem.hpp"
#include "token.hpp"
#include "win_obj_manager.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>


struct file_host final : win_object
{
	std::shared_ptr<win_file> file;
	std::string path;

	std::uint64_t position = 0;

	// Written to the emulator's own stdout rather than anything in the guest filesystem.
	bool console = false;

	// A handle opened on a device names one instead of a file: the driver is reached through the
	// device object, and the file object is the per-open context it is handed on every request.
	addr_t device_object = 0;
	addr_t file_object = 0;

	bool directory = false;
	bool delete_on_close = false;

	std::string dir_filter;
	bool dir_started = false;

	std::uint32_t ea_scan = 0;

	[[nodiscard]] bool is_device() const noexcept { return device_object != 0; }
};

struct pipe_host final : win_object
{
	std::string path;
	std::shared_ptr<struct pipe_instance> instance;
	std::uint64_t generation = 0;
	bool server = false;
	bool message_read = false;
	bool nonblocking = false;
	bool synchronous = false;
};

struct directory_host final : win_object
{
	std::string name;
};

struct process_object final : win_object
{
	std::uint64_t pid = 0;
};

// The driver behind a device object, kept host side so a driver overrunning its own extension
// cannot rewrite the link back to itself.
struct device_host final : win_object
{
	addr_t driver_object = 0;

	// As IoCreateDevice was given it, for logging and for unregistering the name on delete.
	std::string name;
};

struct symbolic_link_host final : win_object
{
	std::string target;
};

// Object manager names are compared the way the guest writes them, which is neither consistently
// cased nor consistently prefixed: \??\X, \DosDevices\X and \GLOBAL??\X all reach the same link.
// win_filesystem::normalize already folds exactly that, so the device namespace is keyed through
// it -- registering and looking up both go through here, so the two cannot drift.
inline std::string object_namespace_key(const std::string_view name)
{
	return win_filesystem::normalize(name);
}

struct section_host final : win_object
{
	// Null for a pagefile-backed section, whose view starts zeroed and is sized by MaximumSize.
	std::shared_ptr<win_file> file;
	std::string path;
	std::uint64_t size = 0;
	bool is_image = false;

	// SectionPageProtection from NtCreateSection: what a view may be mapped with.
	std::uint32_t protection = 0x04;

	// An image section's view is the file laid out at its virtual addresses, not the file as it
	// sits on disk, so it is built once here and copied from. Empty for anything else.
	std::vector<std::uint8_t> image;

	// The pages every view of a data section maps, allocated when it is first mapped so that a
	// write through one view is the same write through another. They are a list because a
	// section can grow: pages already handed to views stay where they are, and the new ones
	// follow as another run.
	struct extent
	{
		addr_t pa;
		std::uint64_t size;
	};

	std::vector<extent> extents;
	std::uint64_t backed = 0;
	std::mutex phys_mtx;
};

struct dispatcher_host final : win_object
{
	win::dispatcher_type type;
	std::string name;

	dispatcher_host(const win::dispatcher_type t, std::string n)
		: type(t), name(std::move(n)) {}
};

inline constexpr std::uint32_t sec_image = 0x01000000;

// Opaque to the guest apart from its size, which sits where the real one keeps it.
inline constexpr std::size_t section_body_size = 0x40;
inline constexpr std::size_t section_body_size_offset = 0x30;
