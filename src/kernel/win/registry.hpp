#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

enum class registry_type : std::uint32_t
{
	none      = 0,
	sz        = 1,
	expand_sz = 2,
	binary    = 3,
	dword     = 4,
	dword_be  = 5,
	link      = 6,
	multi_sz  = 7,
	qword     = 11,
};

struct registry_value
{
	registry_type type = registry_type::none;
	std::vector<std::uint8_t> data;
};

class win_registry_key
{
public:
	void set_value(std::string_view name, registry_type type, const void* data, std::size_t size);
	void set_value(std::string_view name, registry_type type, std::span<const std::uint8_t> data);
	[[nodiscard]] const registry_value* query_value(std::string_view name) const;
	bool delete_value(std::string_view name);

	void set_dword(std::string_view name, std::uint32_t value);
	void set_qword(std::string_view name, std::uint64_t value);
	void set_string(std::string_view name, std::u16string_view value);
	void set_string(std::string_view name, std::string_view value);
	void set_binary(std::string_view name, const void* data, std::size_t size);
	void set_binary(std::string_view name, std::span<const std::uint8_t> data);

	[[nodiscard]] std::vector<std::string> enumerate_values() const;

private:
	std::unordered_map<std::string, registry_value> values_;
};

class win_registry
{
public:
	[[nodiscard]] std::shared_ptr<win_registry_key> open_key(std::string_view path) const;
	std::shared_ptr<win_registry_key> create_key(std::string_view path);
	bool delete_key(std::string_view path);
	[[nodiscard]] bool key_exists(std::string_view path) const;
	[[nodiscard]] std::vector<std::string> enumerate_subkeys(std::string_view parent_path) const;

	enum class rename_result { renamed, not_found, collision };

	// Only the last component changes, and everything below the key goes with it. The key objects
	// themselves are the same ones, so a handle holding one still holds the renamed key.
	rename_result rename_key(std::string_view path, std::string_view new_name);

	// The key at this path and every key under it, and how many that was.
	std::size_t delete_subtree(std::string_view path);

	// Takes the keys of another store that this one does not have, leaving the ones it does.
	void adopt(win_registry& other);

	// Where a key lives now, which a rename can have changed since a handle was opened on it.
	[[nodiscard]] std::optional<std::string> path_of(const win_registry_key* key) const;

	// Counts renames, so whoever caches a path can tell it may have gone stale.
	[[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }

	[[nodiscard]] static std::string normalize_path(std::u16string_view guest_path);

private:
	std::unordered_map<std::string, std::shared_ptr<win_registry_key>> keys_;
	std::uint64_t epoch_ = 0;
};
