#include "token.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace win::sec
{

namespace
{

constexpr std::uint8_t nt_authority = 5;
constexpr std::uint8_t world_authority = 1;
constexpr std::uint8_t local_authority = 2;
constexpr std::uint8_t label_authority = 16;

constexpr std::uint32_t se_group_mandatory          = 0x01;
constexpr std::uint32_t se_group_enabled_by_default = 0x02;
constexpr std::uint32_t se_group_enabled            = 0x04;
constexpr std::uint32_t se_group_owner              = 0x08;
constexpr std::uint32_t se_group_use_for_deny_only  = 0x10;
constexpr std::uint32_t se_group_integrity          = 0x20;
constexpr std::uint32_t se_group_logon_id           = 0xC0000000;
constexpr std::uint32_t group_on = se_group_mandatory | se_group_enabled_by_default | se_group_enabled;

constexpr std::uint32_t logon_session = 0x40000;
constexpr std::uint32_t integrity_high = 0x3000;
constexpr std::uint32_t session_id = 1;
constexpr std::uint32_t mandatory_policy = 3;
constexpr std::uint32_t elevation_default = 1;

constexpr std::uint32_t default_privileges[] = {
	4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 22, 23, 24, 25, 28, 29, 30, 33, 34, 35, 36,
};

bytes u32(const std::uint32_t value)
{
	bytes out;
	put(out, value);
	return out;
}

bytes encode_sids(const std::span<const group_entry> entries, const addr_t base, const bool counted)
{
	bytes out;

	if (counted)
		put<std::uint64_t>(out, entries.size());

	auto sid_at = base + out.size() + entries.size() * 16;

	for (const auto& e : entries)
	{
		put<std::uint64_t>(out, sid_at);
		put<std::uint64_t>(out, e.attributes);
		sid_at += e.sid.size();
	}

	for (const auto& e : entries)
		out.insert(out.end(), e.sid.begin(), e.sid.end());

	return out;
}

bytes pointer_to(const bytes& target, const addr_t base)
{
	bytes out;
	put<std::uint64_t>(out, base + sizeof(std::uint64_t));
	out.insert(out.end(), target.begin(), target.end());
	return out;
}

bool holds(const token_data& token, const std::span<const std::uint8_t> sid, const bool deny_only)
{
	return std::ranges::equal(token.user, sid) || std::ranges::any_of(token.groups,
		[&](const group_entry& g)
		{
			const auto wanted = se_group_enabled | (deny_only ? se_group_use_for_deny_only : 0);
			return (g.attributes & wanted) && std::ranges::equal(g.sid, sid);
		});
}

}

const generic_mapping& token_generic_mapping()
{
	static constexpr generic_mapping mapping{
		access_read_control | token_query,
		access_read_control | token_adjust_privileges | token_adjust_groups | token_adjust_default,
		access_read_control,
		token_all_access,
	};

	return mapping;
}

std::uint32_t map_token_access(const std::uint32_t desired)
{
	return (desired & access_maximum_allowed) ? token_all_access
		: map_generic(desired, token_generic_mapping());
}

token_data make_default_token(const std::uint64_t token_id)
{
	const auto domain = [](const std::uint32_t rid)
	{
		return make_sid(nt_authority, { 21, 1004336348, 1177238915, 682003330, rid });
	};

	const auto administrators = make_sid(nt_authority, { 32, 544 });
	const sid_t acl_sids[] = { make_sid(nt_authority, { 18 }), administrators };

	token_data t;

	t.user = domain(1000);
	t.owner = administrators;
	t.primary_group = domain(513);
	t.default_dacl = make_allow_all_acl(acl_sids);
	t.token_id = token_id;

	t.groups = {
		{ make_sid(world_authority, { 0 }), group_on },
		{ administrators, group_on | se_group_owner },
		{ make_sid(nt_authority, { 32, 545 }), group_on },
		{ make_sid(nt_authority, { 4 }), group_on },
		{ make_sid(local_authority, { 1 }), group_on },
		{ make_sid(nt_authority, { 11 }), group_on },
		{ make_sid(nt_authority, { 15 }), group_on },
		{ make_sid(local_authority, { 0 }), group_on },
		{ make_sid(nt_authority, { 5, 0, logon_session }), group_on | se_group_logon_id },
		{ make_sid(label_authority, { integrity_high }), se_group_integrity | 0x40 },
	};

	for (const auto luid : default_privileges)
	{
		const bool on = luid == 23 || luid == 29 || luid == 30;
		t.privileges.push_back({ luid, on ? 3u : 0u });
	}

	return t;
}

token_data duplicate_token(const token_data& source, const std::uint32_t type,
	const std::uint32_t impersonation_level, const bool effective_only, const std::uint64_t token_id)
{
	auto t = source;

	t.type = type;
	t.impersonation_level = type == token_impersonation ? impersonation_level : security_anonymous;
	t.token_id = token_id;

	if (effective_only)
	{
		std::erase_if(t.privileges, [](const privilege_entry& p)
		{
			return !(p.attributes & se_privilege_enabled);
		});

		std::erase_if(t.groups, [](const group_entry& g)
		{
			return !(g.attributes & (se_group_enabled | se_group_use_for_deny_only));
		});
	}

	return t;
}

bytes encode_privileges(const std::span<const privilege_entry> privileges)
{
	bytes out;
	put(out, static_cast<std::uint32_t>(privileges.size()));

	for (const auto& p : privileges)
	{
		put(out, p.luid);
		put<std::uint32_t>(out, 0);
		put(out, p.attributes);
	}

	return out;
}

NTSTATUS query_token_information(const token_data& token, const std::uint32_t information_class,
	const addr_t base, bytes& out)
{
	switch (information_class)
	{
	case token_user:
	{
		const group_entry user{ token.user, 0 };
		out = encode_sids({ &user, 1 }, base, false);
		break;
	}

	case token_groups:
		out = encode_sids(token.groups, base, true);
		break;

	case token_privileges:
		out = encode_privileges(token.privileges);
		break;

	case token_owner:
		out = pointer_to(token.owner, base);
		break;

	case token_primary_group:
		out = pointer_to(token.primary_group, base);
		break;

	case token_default_dacl:
		out = pointer_to(token.default_dacl, base);
		break;

	case token_source:
		out = { 'U', 's', 'e', 'r', '3', '2', 0, 0 };
		put(out, token.token_id);
		break;

	case token_type_class:
		out = u32(token.type);
		break;

	case token_impersonation_level:
		if (token.type != token_impersonation)
			return STATUS_INVALID_PARAMETER;

		out = u32(token.impersonation_level);
		break;

	case token_statistics:
		put(out, token.token_id);
		put<std::uint64_t>(out, logon_session);
		put(out, std::numeric_limits<std::int64_t>::max());
		put(out, token.type);
		put(out, token.impersonation_level);
		put<std::uint32_t>(out, 0x1F4);
		put<std::uint32_t>(out, 0x1F4);
		put(out, static_cast<std::uint32_t>(token.groups.size()));
		put(out, static_cast<std::uint32_t>(token.privileges.size()));
		put(out, token.token_id);
		break;

	case token_restricted_sids:
		out = encode_sids({}, base, true);
		break;

	case token_session_id:
		out = u32(session_id);
		break;

	case token_elevation_type:
		out = u32(elevation_default);
		break;

	case token_elevation:
		out = u32(1);
		break;

	case token_sandbox_inert:
	case token_has_restrictions:
	case token_virtualization_allowed:
	case token_virtualization_enabled:
	case token_ui_access:
	case token_is_app_container:
	case token_is_restricted:
	case 42:
	case 45:
	case 46:
	case 47:
	case 48:
		out = u32(0);
		break;

	case 44:
		out.assign(16, 0);
		break;

	case token_integrity_level:
	{
		const group_entry label{ make_sid(label_authority, { integrity_high }), se_group_integrity };
		out = encode_sids({ &label, 1 }, base, false);
		break;
	}

	case token_mandatory_policy:
		out = u32(mandatory_policy);
		break;

	case token_logon_sid:
	{
		const auto logon = std::ranges::find_if(token.groups, [](const group_entry& g)
		{
			return (g.attributes & se_group_logon_id) == se_group_logon_id;
		});

		out = encode_sids({ logon, logon == token.groups.end() ? logon : logon + 1 }, base, true);
		break;
	}

	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	return STATUS_SUCCESS;
}

NTSTATUS adjust_privileges(token_data& token, const bool disable_all,
	std::span<const privilege_entry> requested, std::vector<privilege_entry>& previous)
{
	std::vector<privilege_entry> disable;

	if (disable_all)
	{
		for (const auto& p : token.privileges)
		{
			if (p.attributes & se_privilege_enabled)
				disable.push_back({ p.luid, 0 });
		}

		requested = disable;
	}

	bool missing = false;

	for (const auto& r : requested)
	{
		const auto it = std::ranges::find(token.privileges, r.luid, &privilege_entry::luid);

		if (it == token.privileges.end())
		{
			missing = true;
			continue;
		}

		const bool remove = r.attributes & se_privilege_removed;
		const auto wanted = (it->attributes & ~se_privilege_enabled) | (r.attributes & se_privilege_enabled);

		if (!remove && wanted == it->attributes)
			continue;

		if (std::ranges::find(previous, r.luid, &privilege_entry::luid) == previous.end())
			previous.push_back(*it);

		if (remove)
			token.privileges.erase(it);
		else
			it->attributes = wanted;
	}

	return missing ? STATUS_NOT_ALL_ASSIGNED : STATUS_SUCCESS;
}

NTSTATUS check_access(const descriptor& sd, const token_data& token, const std::uint32_t desired_in,
	const generic_mapping& mapping, std::uint32_t& granted_out)
{
	auto desired = map_generic(desired_in, mapping);

	const bool maximum = desired & access_maximum_allowed;
	desired &= ~access_maximum_allowed;

	std::uint32_t granted = 0;
	std::uint32_t denied = 0;

	if (holds(token, *sd.owner, false))
		granted = access_read_control | access_write_dac;

	const bytes empty_acl(8);
	const auto& acl = sd.dacl ? *sd.dacl : empty_acl;

	if (!sd.dacl)
		granted = 0x01FFFFFF;

	std::size_t at = 8;

	for (std::size_t i = 0, count = acl[4] | acl[5] << 8; i < count && at + 16 <= acl.size(); ++i)
	{
		const auto* const ace = acl.data() + at;
		const std::size_t size = ace[2] | ace[3] << 8;

		if (size < 16 || at + size > acl.size())
			break;

		at += size;

		std::uint32_t mask = 0;
		std::memcpy(&mask, ace + 4, sizeof(mask));

		const std::span<const std::uint8_t> sid(ace + 8, size - 8);
		const std::size_t sid_size = 8 + sid[1] * 4;

		if ((ace[1] & 0x08) || sid[0] != 1 || sid[1] > 15 || sid_size > sid.size())
			continue;

		mask = map_generic(mask, mapping);

		if (ace[0] == 0 && holds(token, sid.first(sid_size), false))
			granted |= mask & ~denied;
		else if (ace[0] == 1 && holds(token, sid.first(sid_size), true))
			denied |= mask & ~granted;
	}

	granted &= ~(access_system_security | denied);

	if (maximum ? !granted : desired & ~granted)
		return STATUS_ACCESS_DENIED;

	granted_out = maximum ? granted : desired;

	return STATUS_SUCCESS;
}

}
