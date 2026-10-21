#pragma once
#include "registry.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// The on-disk registry hive format (REGF), which is what NtSaveKey writes and NtLoadKey reads.
namespace win::hive
{

enum class load_result
{
	loaded,
	not_a_hive,
	corrupt,
};

// The key at `path` and everything under it as a hive file. The key becomes the hive's root.
[[nodiscard]] std::vector<std::uint8_t> save(const win_registry& registry, std::string_view path,
	std::uint64_t filetime);

// Builds the hive's keys under `target`. Nothing is added unless the whole hive reads cleanly.
load_result load(win_registry& registry, std::string_view target,
	std::span<const std::uint8_t> data);

}
