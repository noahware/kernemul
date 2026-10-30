#pragma once
#include "../../emu/defs.hpp"
#include <cstddef>
#include <cstdint>

// Not in the generated types: KSERVICE_TABLE_DESCRIPTOR, as KiInitSystem fills it on both arches.
#pragma pack(push, 8)
struct service_table_descriptor_t
{
	addr_t        base;
	addr_t        count;
	std::uint32_t limit;
	addr_t        number;
};
#pragma pack(pop)

static_assert(offsetof(service_table_descriptor_t, limit) == 0x10);
static_assert(offsetof(service_table_descriptor_t, number) == 0x18);
static_assert(sizeof(service_table_descriptor_t) == 0x20);
