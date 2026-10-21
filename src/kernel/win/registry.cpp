#include "registry.hpp"
#include "../../util/string.hpp"
#include "../../util/log.hpp"

#include <algorithm>
#include <cstring>
#include <set>

void win_registry_key::set_value(const std::string_view name, const registry_type type,
	const void* data, const std::size_t size)
{
	auto& entry = values_[std::string(name)];
	entry.type = type;
	entry.data.resize(size);

	if (data && size > 0)
		std::memcpy(entry.data.data(), data, size);
}

void win_registry_key::set_value(const std::string_view name, const registry_type type,
	const std::span<const std::uint8_t> data)
{
	set_value(name, type, data.data(), data.size());
}

const registry_value* win_registry_key::query_value(const std::string_view name) const
{
	const auto it = values_.find(std::string(name));
	return it != values_.end() ? &it->second : nullptr;
}

bool win_registry_key::delete_value(const std::string_view name)
{
	return values_.erase(std::string(name)) > 0;
}

void win_registry_key::set_dword(const std::string_view name, const std::uint32_t value)
{
	set_value(name, registry_type::dword, &value, sizeof(value));
}

void win_registry_key::set_qword(const std::string_view name, const std::uint64_t value)
{
	set_value(name, registry_type::qword, &value, sizeof(value));
}

void win_registry_key::set_string(const std::string_view name, const std::u16string_view value)
{
	const auto byte_length = (value.size() + 1) * sizeof(char16_t);
	std::vector<std::uint8_t> buffer(byte_length, 0);
	std::memcpy(buffer.data(), value.data(), value.size() * sizeof(char16_t));
	set_value(name, registry_type::sz, buffer.data(), buffer.size());
}

void win_registry_key::set_string(const std::string_view name, const std::string_view value)
{
	set_string(name, widen_string(value));
}

void win_registry_key::set_binary(const std::string_view name, const void* data, const std::size_t size)
{
	set_value(name, registry_type::binary, data, size);
}

void win_registry_key::set_binary(const std::string_view name, const std::span<const std::uint8_t> data)
{
	set_value(name, registry_type::binary, data.data(), data.size());
}

std::vector<std::string> win_registry_key::enumerate_values() const
{
	std::vector<std::string> result;
	result.reserve(values_.size());

	for (const auto& [name, _] : values_)
		result.push_back(name);

	std::sort(result.begin(), result.end());
	return result;
}

std::shared_ptr<win_registry_key> win_registry::open_key(const std::string_view path) const
{
	const auto it = keys_.find(std::string(path));
	return it != keys_.end() ? it->second : nullptr;
}

std::shared_ptr<win_registry_key> win_registry::create_key(const std::string_view path)
{
	const auto path_str = std::string(path);
	const auto it = keys_.find(path_str);

	if (it != keys_.end())
		return it->second;

	std::size_t pos = 0;
	while ((pos = path_str.find('/', pos)) != std::string::npos)
	{
		const auto ancestor = path_str.substr(0, pos);
		if (!keys_.contains(ancestor))
			keys_[ancestor] = std::make_shared<win_registry_key>();
		++pos;
	}

	auto key = std::make_shared<win_registry_key>();
	keys_[path_str] = key;

	LOG_INFO("registry: created key '{}'", path_str);
	return key;
}

bool win_registry::delete_key(const std::string_view path)
{
	return keys_.erase(std::string(path)) > 0;
}

bool win_registry::key_exists(const std::string_view path) const
{
	return keys_.contains(std::string(path));
}

win_registry::rename_result win_registry::rename_key(const std::string_view path,
	const std::string_view new_name)
{
	const auto old_path = std::string(path);

	if (!keys_.contains(old_path))
		return rename_result::not_found;

	const auto slash = old_path.rfind('/');
	std::string leaf(new_name);

	for (auto& c : leaf)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

	const auto new_path = slash == std::string::npos ? leaf : old_path.substr(0, slash + 1) + leaf;

	if (new_path == old_path)
		return rename_result::renamed;

	if (keys_.contains(new_path))
		return rename_result::collision;

	const auto old_prefix = old_path + "/";
	std::vector<std::pair<std::string, std::shared_ptr<win_registry_key>>> moved;

	for (auto it = keys_.begin(); it != keys_.end();)
	{
		if (it->first == old_path || it->first.starts_with(old_prefix))
		{
			moved.emplace_back(new_path + it->first.substr(old_path.size()), std::move(it->second));
			it = keys_.erase(it);
			continue;
		}

		++it;
	}

	for (auto& [moved_path, key] : moved)
		keys_.emplace(std::move(moved_path), std::move(key));

	++epoch_;

	LOG_INFO("registry: renamed key '{}' to '{}'", old_path, new_path);

	return rename_result::renamed;
}

std::size_t win_registry::delete_subtree(const std::string_view path)
{
	const auto root = std::string(path);
	const auto prefix = root + "/";
	std::size_t removed = 0;

	for (auto it = keys_.begin(); it != keys_.end();)
	{
		if (it->first == root || it->first.starts_with(prefix))
		{
			it = keys_.erase(it);
			++removed;
			continue;
		}

		++it;
	}

	return removed;
}

void win_registry::adopt(win_registry& other)
{
	for (auto& [path, key] : other.keys_)
		keys_.emplace(path, key);
}

std::optional<std::string> win_registry::path_of(const win_registry_key* const key) const
{
	for (const auto& [path, candidate] : keys_)
	{
		if (candidate.get() == key)
			return path;
	}

	return std::nullopt;
}

std::vector<std::string> win_registry::enumerate_subkeys(const std::string_view parent_path) const
{
	const auto prefix = std::string(parent_path) + "/";
	std::set<std::string> subkeys;

	for (const auto& [key_path, _] : keys_)
	{
		if (!key_path.starts_with(prefix))
			continue;

		const auto remainder = key_path.substr(prefix.size());
		const auto slash_pos = remainder.find('/');

		if (slash_pos == std::string::npos)
			subkeys.insert(remainder);
		else
			subkeys.insert(remainder.substr(0, slash_pos));
	}

	return { subkeys.begin(), subkeys.end() };
}

std::string win_registry::normalize_path(const std::u16string_view guest_path)
{
	auto path = narrow_wstring(guest_path);

	for (auto& c : path)
	{
		if (c == '\\')
			c = '/';
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	constexpr std::string_view machine_prefix = "registry/machine/";

	if (path.starts_with(machine_prefix))
		path = path.substr(machine_prefix.size());

	if (!path.empty() && path.front() == '/')
		path = path.substr(1);

	if (path.starts_with(machine_prefix))
		path = path.substr(machine_prefix.size());

	while (!path.empty() && path.back() == '/')
		path.pop_back();

	return path;
}
