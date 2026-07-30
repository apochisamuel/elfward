/*
 * ew_dwarf.c — DWARF debug information identification and parsing.
 *
 * Identifies DWARF debug sections (.debug_info, .debug_abbrev,
 * .debug_line, .debug_str, etc.), parses compilation unit headers
 * from .debug_info, and provides summary information about the
 * debug data present in the ELF file.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define EW_DWARF_TAG_COMPILE_UNIT    0x11
#define EW_DWARF_TAG_PARTIAL_UNIT    0x3c
#define EW_DWARF_TAG_TYPE_UNIT       0x41

typedef struct {
    uint64_t unit_length;
    uint16_t version;
    uint64_t debug_abbrev_offset;
    uint8_t  address_size;
    uint8_t  unit_type;
    int      is_64bit;
    size_t   header_size;
    size_t   offset_in_section;
} ew_dwarf_cu_header_t;

typedef struct {
    const char *name;
    uint32_t    section_type;
    uint32_t    section_index;
    uint64_t    size;
    int         present;
} ew_dwarf_section_info_t;

typedef struct {
    ew_dwarf_section_info_t sections[12];
    uint32_t                section_count;
    ew_dwarf_cu_header_t   *compile_units;
    uint32_t                cu_count;
    uint32_t                cu_capacity;
    uint16_t                max_version;
    uint16_t                min_version;
    int                     has_debug_info;
    uint64_t                total_debug_size;
} ew_dwarf_info_t;

static const char *dwarf_section_names[] = {
    ".debug_info",
    ".debug_abbrev",
    ".debug_line",
    ".debug_str",
    ".debug_line_str",
    ".debug_ranges",
    ".debug_rnglists",
    ".debug_loc",
    ".debug_loclists",
    ".debug_frame",
    ".debug_aranges",
    ".debug_addr",
};
static const int dwarf_section_name_count = 12;

static ew_error_t identify_dwarf_sections(ew_context_t *ctx,
                                           ew_dwarf_info_t *info)
{
    info->section_count = 0;
    info->total_debug_size = 0;

    for (int d = 0; d < dwarf_section_name_count; d++) {
        ew_dwarf_section_info_t *dsi = &info->sections[info->section_count];
        memset(dsi, 0, sizeof(*dsi));
        dsi->name = dwarf_section_names[d];

        for (uint32_t i = 0; i < ctx->section_count; i++) {
            ew_section_t *sec = &ctx->sections[i];
            if (!sec->name)
                continue;
            if (strcmp(sec->name, dwarf_section_names[d]) == 0) {
                dsi->section_type = sec->sh_type;
                dsi->section_index = i;
                dsi->size = sec->sh_size;
                dsi->present = 1;
                info->total_debug_size += sec->sh_size;
                break;
            }
        }

        info->section_count++;
    }

    info->has_debug_info = 0;
    for (uint32_t i = 0; i < info->section_count; i++) {
        if (info->sections[i].present &&
            strcmp(info->sections[i].name, ".debug_info") == 0) {
            info->has_debug_info = 1;
            break;
        }
    }

    return EW_OK;
}

static ew_error_t parse_cu_header(ew_reader_t *rd,
                                   ew_dwarf_cu_header_t *cu,
                                   size_t section_offset)
{
    cu->offset_in_section = section_offset;

    uint32_t initial_length;
    ew_error_t err = ew_read_u32(rd, &initial_length);
    if (err != EW_OK)
        return err;

    if (initial_length == 0xFFFFFFFF) {
        cu->is_64bit = 1;
        err = ew_read_u64(rd, &cu->unit_length);
        if (err != EW_OK) return err;
        cu->header_size = 12;
    } else {
        cu->is_64bit = 0;
        cu->unit_length = initial_length;
        cu->header_size = 4;
    }

    err = ew_read_u16(rd, &cu->version);
    if (err != EW_OK) return err;
    cu->header_size += 2;

    if (cu->version >= 5) {
        uint8_t unit_type;
        err = ew_read_u8(rd, &unit_type);
        if (err != EW_OK) return err;
        cu->unit_type = unit_type;
        cu->header_size += 1;

        err = ew_read_u8(rd, &cu->address_size);
        if (err != EW_OK) return err;
        cu->header_size += 1;

        if (cu->is_64bit) {
            err = ew_read_u64(rd, &cu->debug_abbrev_offset);
            cu->header_size += 8;
        } else {
            uint32_t off32;
            err = ew_read_u32(rd, &off32);
            cu->debug_abbrev_offset = off32;
            cu->header_size += 4;
        }
        if (err != EW_OK) return err;
    } else {
        if (cu->is_64bit) {
            err = ew_read_u64(rd, &cu->debug_abbrev_offset);
            cu->header_size += 8;
        } else {
            uint32_t off32;
            err = ew_read_u32(rd, &off32);
            cu->debug_abbrev_offset = off32;
            cu->header_size += 4;
        }
        if (err != EW_OK) return err;

        err = ew_read_u8(rd, &cu->address_size);
        if (err != EW_OK) return err;
        cu->header_size += 1;

        cu->unit_type = 0;
    }

    return EW_OK;
}

static ew_error_t parse_debug_info_headers(ew_context_t *ctx,
                                            ew_dwarf_info_t *info)
{
    ew_section_t *debug_info = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].name &&
            strcmp(ctx->sections[i].name, ".debug_info") == 0) {
            debug_info = &ctx->sections[i];
            break;
        }
    }

    if (!debug_info || !debug_info->data || debug_info->sh_size == 0) {
        info->cu_count = 0;
        return EW_OK;
    }

    ew_reader_t rd;
    ew_reader_init(&rd, debug_info->data, (size_t)debug_info->sh_size,
                    ctx->is_big_endian);

    info->min_version = 0xFFFF;
    info->max_version = 0;

    while (ew_reader_remaining(&rd) >= 4) {
        size_t cu_start = ew_reader_tell(&rd);

        if (info->cu_count >= info->cu_capacity) {
            uint32_t new_cap = info->cu_capacity == 0 ?
                               16 : info->cu_capacity * 2;
            if (new_cap > 65536)
                return EW_ERR_LIMIT;
            ew_dwarf_cu_header_t *tmp = realloc(
                info->compile_units,
                new_cap * sizeof(ew_dwarf_cu_header_t));
            if (!tmp)
                return EW_ERR_NOMEM;
            info->compile_units = tmp;
            info->cu_capacity = new_cap;
        }

        ew_dwarf_cu_header_t *cu = &info->compile_units[info->cu_count];
        memset(cu, 0, sizeof(*cu));

        ew_error_t err = parse_cu_header(&rd, cu, cu_start);
        if (err != EW_OK)
            break;

        if (cu->version < info->min_version)
            info->min_version = cu->version;
        if (cu->version > info->max_version)
            info->max_version = cu->version;

        info->cu_count++;

        size_t unit_end = cu_start + (cu->is_64bit ? 12 : 4) +
                          (size_t)cu->unit_length;
        if (unit_end > debug_info->sh_size)
            break;

        ew_reader_seek(&rd, unit_end);
    }

    return EW_OK;
}

ew_error_t ew_parse_dwarf_info(ew_context_t *ctx, ew_dwarf_info_t *info)
{
    if (!ctx || !info)
        return EW_ERR_INVALID;

    memset(info, 0, sizeof(*info));

    ew_error_t err = identify_dwarf_sections(ctx, info);
    if (err != EW_OK)
        return err;

    if (info->has_debug_info) {
        err = parse_debug_info_headers(ctx, info);
        if (err != EW_OK)
            return err;
    }

    return EW_OK;
}

void ew_dwarf_info_destroy(ew_dwarf_info_t *info)
{
    if (!info)
        return;
    free(info->compile_units);
    memset(info, 0, sizeof(*info));
}

uint32_t ew_dwarf_section_count(ew_context_t *ctx)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].name &&
            strncmp(ctx->sections[i].name, ".debug_", 7) == 0)
            count++;
    }
    return count;
}
