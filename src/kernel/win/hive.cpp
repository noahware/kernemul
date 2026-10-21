#include "hive.hpp"
#include "../../util/string.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <set>
#include <string>

namespace win::hive
{

namespace
{

constexpr std::size_t base_block_size = 0x1000;
constexpr std::size_t bin_header_size = 0x20;
constexpr std::uint32_t no_offset = 0xFFFFFFFF;

// A data cell holds this much; anything longer is stored as a list of segments of this size.
constexpr std::size_t max_segment = 16344;

// Entries a single subkey list may hold before the keys are split across several under an index root.
constexpr std::size_t max_list_entries = 1000;

constexpr std::uint16_t key_hive_entry = 0x0004;
constexpr std::uint16_t key_no_delete = 0x0008;
constexpr std::uint16_t key_comp_name = 0x0020;

constexpr std::uint16_t value_comp_name = 0x0001;
constexpr std::uint16_t value_tombstone = 0x0002;

constexpr std::uint32_t inline_data = 0x80000000;

// Deep enough for any real hive, and bounded so a hive whose keys loop cannot recurse forever.
constexpr int max_depth = 512;
constexpr std::size_t max_nodes = 2'000'000;

struct corrupt_hive {};

template <typename T>
void put(std::vector<std::uint8_t>& out, const std::size_t offset, const T value)
{
	std::memcpy(out.data() + offset, &value, sizeof(T));
}

template <typename T>
T get(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	if (offset > bytes.size() || bytes.size() - offset < sizeof(T))
		throw corrupt_hive{};

	T value;
	std::memcpy(&value, bytes.data() + offset, sizeof(T));

	return value;
}

std::string lower(std::string text)
{
	for (auto& c : text)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

	return text;
}

std::string upper(std::string text)
{
	for (auto& c : text)
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

	return text;
}

std::uint32_t checksum(const std::vector<std::uint8_t>& base)
{
	std::uint32_t sum = 0;

	for (std::size_t at = 0; at < 508; at += 4)
		sum ^= get<std::uint32_t>(base, at);

	if (sum == 0xFFFFFFFF)
		return 0xFFFFFFFE;

	return sum == 0 ? 1 : sum;
}

// ---- writing ------------------------------------------------------------------------------

// Every cell goes in one hive bin, which is allowed to be any multiple of a page long.
class writer
{
public:
	writer() : bin_(bin_header_size) {}

	std::uint32_t add_cell(const std::span<const std::uint8_t> content)
	{
		const auto total = (4 + content.size() + 7) & ~std::size_t{7};
		const auto at = bin_.size();

		bin_.resize(at + total);
		put<std::int32_t>(bin_, at, -static_cast<std::int32_t>(total));

		if (!content.empty())
			std::memcpy(bin_.data() + at + 4, content.data(), content.size());

		return static_cast<std::uint32_t>(at);
	}

	// Field `at` of the cell at `cell`, counted from the start of its content.
	template <typename T>
	void patch(const std::uint32_t cell, const std::size_t at, const T value)
	{
		put<T>(bin_, cell + 4 + at, value);
	}

	std::vector<std::uint8_t> finish(const std::uint32_t root, const std::uint64_t filetime)
	{
		const auto size = (bin_.size() + base_block_size - 1) & ~(base_block_size - 1);
		const auto tail = size - bin_.size();

		bin_.resize(size);

		// What is left of the bin is one free cell, whose size is positive.
		if (tail)
			put<std::int32_t>(bin_, size - tail, static_cast<std::int32_t>(tail));

		std::memcpy(bin_.data(), "hbin", 4);
		put<std::uint32_t>(bin_, 4, 0);
		put<std::uint32_t>(bin_, 8, static_cast<std::uint32_t>(size));
		put<std::uint64_t>(bin_, 0x14, filetime);

		std::vector<std::uint8_t> base(base_block_size);
		std::memcpy(base.data(), "regf", 4);
		put<std::uint32_t>(base, 0x04, 1);
		put<std::uint32_t>(base, 0x08, 1);
		put<std::uint64_t>(base, 0x0C, filetime);
		put<std::uint32_t>(base, 0x14, 1);
		put<std::uint32_t>(base, 0x18, 5);
		put<std::uint32_t>(base, 0x1C, 0);
		put<std::uint32_t>(base, 0x20, 1);
		put<std::uint32_t>(base, 0x24, root);
		put<std::uint32_t>(base, 0x28, static_cast<std::uint32_t>(size));
		put<std::uint32_t>(base, 0x2C, 1);
		put<std::uint32_t>(base, 0x1FC, checksum(base));

		base.insert(base.end(), bin_.begin(), bin_.end());

		return base;
	}

private:
	std::vector<std::uint8_t> bin_;
};

struct node
{
	std::string name;
	std::shared_ptr<win_registry_key> key;
	std::vector<node> children;
};

node collect(const win_registry& registry, const std::string& path, const std::string& name,
	const int depth)
{
	node out{ name, registry.open_key(path), {} };

	// A key that only exists because something lies below it still has to be written.
	if (!out.key)
		out.key = std::make_shared<win_registry_key>();

	if (depth >= max_depth)
		return out;

	for (const auto& sub : registry.enumerate_subkeys(path))
		out.children.push_back(collect(registry, path + "/" + sub, sub, depth + 1));

	return out;
}

std::uint32_t name_hash(const std::string& name)
{
	std::uint32_t hash = 0;

	for (const auto c : upper(name))
		hash = hash * 37 + static_cast<unsigned char>(c);

	return hash;
}

// A security descriptor granting everyone full control of the key, which is all a hive written
// here has to say about who may open it.
std::vector<std::uint8_t> everyone_descriptor()
{
	std::vector<std::uint8_t> sd(48);

	sd[0] = 1;
	put<std::uint16_t>(sd, 2, 0x8004);
	put<std::uint32_t>(sd, 16, 20);

	// ACL: revision 2, size, one ACE.
	sd[20] = 2;
	put<std::uint16_t>(sd, 22, 28);
	put<std::uint16_t>(sd, 24, 1);

	// ACCESS_ALLOWED_ACE for S-1-1-0 with KEY_ALL_ACCESS.
	put<std::uint16_t>(sd, 28 + 2, 20);
	put<std::uint32_t>(sd, 28 + 4, 0x000F003F);
	sd[28 + 8] = 1;
	sd[28 + 9] = 1;
	sd[28 + 15] = 1;

	return sd;
}

struct tree_writer
{
	writer cells;
	std::uint32_t security = no_offset;
	std::uint32_t key_count = 0;

	std::uint32_t write_data(const std::vector<std::uint8_t>& data, std::uint32_t& size_field)
	{
		if (data.size() <= 4)
		{
			size_field = inline_data | static_cast<std::uint32_t>(data.size());

			std::uint32_t packed = 0;

			if (!data.empty())
				std::memcpy(&packed, data.data(), data.size());

			return packed;
		}

		size_field = static_cast<std::uint32_t>(data.size());

		if (data.size() <= max_segment)
			return cells.add_cell(data);

		std::vector<std::uint8_t> list;

		for (std::size_t at = 0; at < data.size(); at += max_segment)
		{
			const auto length = std::min(max_segment, data.size() - at);
			const auto segment = cells.add_cell({ data.data() + at, length });

			list.resize(list.size() + 4);
			put<std::uint32_t>(list, list.size() - 4, segment);
		}

		const auto list_cell = cells.add_cell(list);

		std::vector<std::uint8_t> head(8);
		std::memcpy(head.data(), "db", 2);
		put<std::uint16_t>(head, 2, static_cast<std::uint16_t>(list.size() / 4));
		put<std::uint32_t>(head, 4, list_cell);

		return cells.add_cell(head);
	}

	std::uint32_t write_value(const std::string& name, const registry_value& value)
	{
		std::uint32_t size_field = 0;
		const auto data = write_data(value.data, size_field);

		std::vector<std::uint8_t> vk(20 + name.size());
		std::memcpy(vk.data(), "vk", 2);
		put<std::uint16_t>(vk, 2, static_cast<std::uint16_t>(name.size()));
		put<std::uint32_t>(vk, 4, size_field);
		put<std::uint32_t>(vk, 8, data);
		put<std::uint32_t>(vk, 12, static_cast<std::uint32_t>(value.type));
		put<std::uint16_t>(vk, 16, value_comp_name);
		std::memcpy(vk.data() + 20, name.data(), name.size());

		return cells.add_cell(vk);
	}

	std::uint32_t write_subkey_lists(std::vector<std::pair<std::uint32_t, std::string>>& entries)
	{
		// Both the lists and the keys in them go by upper case name.
		std::ranges::sort(entries, {}, [](const auto& e) { return upper(e.second); });

		const auto write_list = [&](const std::size_t from, const std::size_t to)
		{
			std::vector<std::uint8_t> list(4 + 8 * (to - from));
			std::memcpy(list.data(), "lh", 2);
			put<std::uint16_t>(list, 2, static_cast<std::uint16_t>(to - from));

			for (std::size_t i = from; i < to; ++i)
			{
				put<std::uint32_t>(list, 4 + 8 * (i - from), entries[i].first);
				put<std::uint32_t>(list, 8 + 8 * (i - from), name_hash(entries[i].second));
			}

			return cells.add_cell(list);
		};

		if (entries.size() <= max_list_entries)
			return write_list(0, entries.size());

		std::vector<std::uint8_t> root(4);
		std::memcpy(root.data(), "ri", 2);

		for (std::size_t from = 0; from < entries.size(); from += max_list_entries)
		{
			const auto list = write_list(from, std::min(entries.size(), from + max_list_entries));

			root.resize(root.size() + 4);
			put<std::uint32_t>(root, root.size() - 4, list);
		}

		put<std::uint16_t>(root, 2, static_cast<std::uint16_t>((root.size() - 4) / 4));

		return cells.add_cell(root);
	}

	std::uint32_t write_node(const node& n, const std::uint32_t parent, const bool is_root,
		const std::uint64_t filetime)
	{
		++key_count;

		const auto value_names = n.key->enumerate_values();
		std::vector<std::uint8_t> value_list;
		std::uint32_t max_value_name = 0;
		std::uint32_t max_value_data = 0;

		for (const auto& value_name : value_names)
		{
			const auto* const value = n.key->query_value(value_name);

			value_list.resize(value_list.size() + 4);
			put<std::uint32_t>(value_list, value_list.size() - 4, write_value(value_name, *value));

			max_value_name = std::max(max_value_name,
				static_cast<std::uint32_t>(value_name.size() * 2));
			max_value_data = std::max(max_value_data, static_cast<std::uint32_t>(value->data.size()));
		}

		const auto values = value_list.empty() ? no_offset : cells.add_cell(value_list);

		const std::uint16_t flags = key_comp_name
			| (is_root ? (key_hive_entry | key_no_delete) : 0);

		// The children need this key's offset, so it is written now and finished once they are.
		std::vector<std::uint8_t> nk(0x4C + n.name.size());
		std::memcpy(nk.data(), "nk", 2);
		put<std::uint16_t>(nk, 2, flags);
		put<std::uint64_t>(nk, 4, filetime);
		put<std::uint32_t>(nk, 0x10, parent);
		put<std::uint32_t>(nk, 0x1C, no_offset);
		put<std::uint32_t>(nk, 0x20, no_offset);
		put<std::uint32_t>(nk, 0x24, static_cast<std::uint32_t>(value_names.size()));
		put<std::uint32_t>(nk, 0x28, values);
		put<std::uint32_t>(nk, 0x2C, security);
		put<std::uint32_t>(nk, 0x30, no_offset);
		put<std::uint32_t>(nk, 0x3C, max_value_name);
		put<std::uint32_t>(nk, 0x40, max_value_data);
		put<std::uint16_t>(nk, 0x48, static_cast<std::uint16_t>(n.name.size()));
		std::memcpy(nk.data() + 0x4C, n.name.data(), n.name.size());

		const auto at = cells.add_cell(nk);

		std::vector<std::pair<std::uint32_t, std::string>> children;
		std::uint32_t max_subkey_name = 0;

		for (const auto& child : n.children)
		{
			children.emplace_back(write_node(child, at, false, filetime), child.name);
			max_subkey_name = std::max(max_subkey_name,
				static_cast<std::uint32_t>(child.name.size() * 2));
		}

		if (!children.empty())
		{
			cells.patch<std::uint32_t>(at, 0x14, static_cast<std::uint32_t>(children.size()));
			cells.patch<std::uint32_t>(at, 0x1C, write_subkey_lists(children));
			cells.patch<std::uint32_t>(at, 0x34, max_subkey_name);
		}

		return at;
	}
};

// ---- reading ------------------------------------------------------------------------------

class reader
{
public:
	reader(win_registry& staging, const std::span<const std::uint8_t> bins)
		: staging_(staging), bins_(bins) {}

	void load_root(const std::uint32_t root, const std::string& target)
	{
		load_key(root, target, true, 0);
	}

private:
	// The content of the cell at `offset`, without the size that heads it.
	std::span<const std::uint8_t> cell(const std::uint32_t offset) const
	{
		if (offset == no_offset || std::uint64_t{offset} + 4 > bins_.size())
			throw corrupt_hive{};

		const auto size = std::int64_t{get<std::int32_t>(bins_, offset)};
		const auto total = static_cast<std::uint64_t>(size < 0 ? -size : size);

		if (total < 8 || std::uint64_t{offset} + total > bins_.size())
			throw corrupt_hive{};

		return bins_.subspan(offset + 4, total - 4);
	}

	static bool has_signature(const std::span<const std::uint8_t> bytes, const char (&sig)[3])
	{
		return bytes.size() >= 2 && bytes[0] == static_cast<std::uint8_t>(sig[0])
			&& bytes[1] == static_cast<std::uint8_t>(sig[1]);
	}

	// Names are either one byte a character or UTF-16, and the registry here keeps one byte.
	static std::string read_name(const std::span<const std::uint8_t> bytes, const std::size_t at,
		const std::size_t length, const bool compressed)
	{
		if (at > bytes.size() || bytes.size() - at < length)
			throw corrupt_hive{};

		std::string name;

		if (compressed)
		{
			name.assign(reinterpret_cast<const char*>(bytes.data() + at), length);
		}
		else
		{
			for (std::size_t i = 0; i + 1 < length; i += 2)
				name += static_cast<char>(get<std::uint16_t>(bytes, at + i) & 0xFF);
		}

		return name;
	}

	void read_value(const std::uint32_t offset, win_registry_key& key)
	{
		const auto vk = cell(offset);

		if (!has_signature(vk, "vk") || vk.size() < 20)
			throw corrupt_hive{};

		const auto flags = get<std::uint16_t>(vk, 16);

		if (flags & value_tombstone)
			return;

		const auto name = read_name(vk, 20, get<std::uint16_t>(vk, 2), flags & value_comp_name);
		const auto size_field = get<std::uint32_t>(vk, 4);
		std::vector<std::uint8_t> data;

		if (size_field & inline_data)
		{
			const auto size = size_field & ~inline_data;

			if (size > 4)
				throw corrupt_hive{};

			data.assign(vk.begin() + 8, vk.begin() + 8 + size);
		}
		else if (size_field > max_segment)
		{
			const auto head = cell(get<std::uint32_t>(vk, 8));

			if (!has_signature(head, "db"))
				throw corrupt_hive{};

			const auto count = get<std::uint16_t>(head, 2);
			const auto list = cell(get<std::uint32_t>(head, 4));

			if (list.size() < std::size_t{count} * 4)
				throw corrupt_hive{};

			for (std::size_t i = 0; i < count && data.size() < size_field; ++i)
			{
				const auto segment = cell(get<std::uint32_t>(list, i * 4));
				// A cell is padded to eight bytes, so it can hold more than the segment it carries.
				const auto take = std::min({ segment.size(), max_segment,
					static_cast<std::size_t>(size_field) - data.size() });

				data.insert(data.end(), segment.begin(), segment.begin() + take);
			}

			if (data.size() != size_field)
				throw corrupt_hive{};
		}
		else if (size_field)
		{
			const auto content = cell(get<std::uint32_t>(vk, 8));

			if (content.size() < size_field)
				throw corrupt_hive{};

			data.assign(content.begin(), content.begin() + size_field);
		}

		key.set_value(name, static_cast<registry_type>(get<std::uint32_t>(vk, 12)), data);
	}

	void load_subkeys(const std::uint32_t offset, const std::string& parent_path, const int depth,
		const bool inside_index_root)
	{
		const auto list = cell(offset);
		const auto count = std::size_t{get<std::uint16_t>(list, 2)};

		if (has_signature(list, "ri"))
		{
			// An index root only ever holds leaves, never another index root.
			if (inside_index_root)
				throw corrupt_hive{};

			for (std::size_t i = 0; i < count; ++i)
				load_subkeys(get<std::uint32_t>(list, 4 + i * 4), parent_path, depth, true);

			return;
		}

		std::size_t stride = 0;

		if (has_signature(list, "li"))
			stride = 4;
		else if (has_signature(list, "lf") || has_signature(list, "lh"))
			stride = 8;
		else
			throw corrupt_hive{};

		for (std::size_t i = 0; i < count; ++i)
			load_key(get<std::uint32_t>(list, 4 + i * stride), parent_path, false, depth + 1);
	}

	void load_key(const std::uint32_t offset, const std::string& parent_path, const bool is_root,
		const int depth)
	{
		if (depth > max_depth || ++nodes_ > max_nodes || !visited_.insert(offset).second)
			throw corrupt_hive{};

		const auto nk = cell(offset);

		if (!has_signature(nk, "nk") || nk.size() < 0x4C)
			throw corrupt_hive{};

		std::string path = parent_path;

		// The root of the hive takes the name of the key it is loaded as, not its own.
		if (!is_root)
		{
			const auto name = lower(read_name(nk, 0x4C, get<std::uint16_t>(nk, 0x48),
				get<std::uint16_t>(nk, 2) & key_comp_name));

			if (name.empty() || name.find_first_of("/\\") != std::string::npos)
				throw corrupt_hive{};

			path += "/" + name;
		}

		auto& key = *staging_.create_key(path);

		if (const auto values = get<std::uint32_t>(nk, 0x24))
		{
			const auto list = cell(get<std::uint32_t>(nk, 0x28));

			if (list.size() < std::size_t{values} * 4)
				throw corrupt_hive{};

			for (std::size_t i = 0; i < values; ++i)
				read_value(get<std::uint32_t>(list, i * 4), key);
		}

		if (get<std::uint32_t>(nk, 0x14))
			load_subkeys(get<std::uint32_t>(nk, 0x1C), path, depth, false);
	}

	win_registry& staging_;
	std::span<const std::uint8_t> bins_;
	std::set<std::uint32_t> visited_;
	std::size_t nodes_ = 0;
};

}

std::vector<std::uint8_t> save(const win_registry& registry, const std::string_view path,
	const std::uint64_t filetime)
{
	const auto slash = path.rfind('/');
	const auto name = std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));

	const auto tree = collect(registry, std::string(path), name.empty() ? "root" : name, 0);

	tree_writer out;

	const auto descriptor = everyone_descriptor();

	std::vector<std::uint8_t> sk(20 + descriptor.size());
	std::memcpy(sk.data(), "sk", 2);
	put<std::uint32_t>(sk, 16, static_cast<std::uint32_t>(descriptor.size()));
	std::memcpy(sk.data() + 20, descriptor.data(), descriptor.size());

	// The only security cell is the head of its own list, so it points back at itself.
	out.security = out.cells.add_cell(sk);
	out.cells.patch<std::uint32_t>(out.security, 4, out.security);
	out.cells.patch<std::uint32_t>(out.security, 8, out.security);

	const auto root = out.write_node(tree, no_offset, true, filetime);

	out.cells.patch<std::uint32_t>(out.security, 12, out.key_count);

	return out.cells.finish(root, filetime);
}

load_result load(win_registry& registry, const std::string_view target,
	const std::span<const std::uint8_t> data)
{
	if (data.size() < base_block_size || std::memcmp(data.data(), "regf", 4) != 0)
		return load_result::not_a_hive;

	try
	{
		const auto root = get<std::uint32_t>(data, 0x24);
		const auto size = std::size_t{get<std::uint32_t>(data, 0x28)};

		if (size > data.size() - base_block_size)
			return load_result::corrupt;

		win_registry staging;

		reader(staging, data.subspan(base_block_size, size)).load_root(root, std::string(target));

		registry.adopt(staging);
	}
	catch (const corrupt_hive&)
	{
		return load_result::corrupt;
	}

	return load_result::loaded;
}

}
