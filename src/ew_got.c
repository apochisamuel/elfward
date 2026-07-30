/*
 * ew_got.c — GOT and PLT analysis.
 *
 * Parses the Global Offset Table (.got, .got.plt) and Procedure
 * Linkage Table (.plt) sections, resolving GOT entries to their
 * corresponding relocations and symbols. Provides functions to
 * enumerate PLT stubs and map them to imported symbols.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint64_t address;
    uint64_t value;
    uint32_t reloc_index;
    uint32_t symbol_index;
    const char *symbol_name;
    int is_resolved;
    int is_lazy;
} ew_got_entry_t;

typedef struct {
    uint64_t address;
    uint64_t got_entry_addr;
    uint32_t got_index;
    const char *target_name;
    int is_resolved;
} ew_plt_entry_t;

typedef struct {
    ew_got_entry_t *entries;
    uint32_t count;
    uint32_t capacity;
    uint64_t base_addr;
    uint64_t size;
    int is_got_plt;
} ew_got_table_t;

typedef struct {
    ew_plt_entry_t *entries;
    uint32_t count;
    uint32_t capacity;
    uint64_t base_addr;
    uint64_t entry_size;
} ew_plt_table_t;

static ew_error_t got_ensure_capacity(ew_got_table_t *tbl, uint32_t needed)
{
    if (tbl->count + needed <= tbl->capacity)
        return EW_OK;
    uint32_t new_cap = tbl->capacity == 0 ? 64 : tbl->capacity * 2;
    while (new_cap < tbl->count + needed)
        new_cap *= 2;
    if (new_cap > EW_MAX_SYMBOLS)
        return EW_ERR_LIMIT;
    ew_got_entry_t *tmp = realloc(tbl->entries,
                                   new_cap * sizeof(ew_got_entry_t));
    if (!tmp)
        return EW_ERR_NOMEM;
    tbl->entries = tmp;
    tbl->capacity = new_cap;
    return EW_OK;
}

static ew_error_t plt_ensure_capacity(ew_plt_table_t *tbl, uint32_t needed)
{
    if (tbl->count + needed <= tbl->capacity)
        return EW_OK;
    uint32_t new_cap = tbl->capacity == 0 ? 64 : tbl->capacity * 2;
    while (new_cap < tbl->count + needed)
        new_cap *= 2;
    if (new_cap > EW_MAX_SYMBOLS)
        return EW_ERR_LIMIT;
    ew_plt_entry_t *tmp = realloc(tbl->entries,
                                   new_cap * sizeof(ew_plt_entry_t));
    if (!tmp)
        return EW_ERR_NOMEM;
    tbl->entries = tmp;
    tbl->capacity = new_cap;
    return EW_OK;
}

static ew_section_t *find_section_by_name(ew_context_t *ctx, const char *name)
{
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].name && strcmp(ctx->sections[i].name, name) == 0)
            return &ctx->sections[i];
    }
    return NULL;
}

static ew_relocation_t *find_reloc_at(ew_context_t *ctx, uint64_t addr)
{
    for (uint32_t i = 0; i < ctx->reloc_count; i++) {
        if (ctx->relocs[i].r_offset == addr)
            return &ctx->relocs[i];
    }
    return NULL;
}

ew_error_t ew_parse_got(ew_context_t *ctx, ew_got_table_t *out,
                         const char *section_name)
{
    if (!ctx || !out)
        return EW_ERR_INVALID;

    memset(out, 0, sizeof(*out));

    ew_section_t *got_sec = find_section_by_name(ctx, section_name);
    if (!got_sec || !got_sec->data || got_sec->sh_size == 0)
        return EW_OK;

    size_t entry_size = ctx->is_64bit ? 8 : 4;
    uint32_t entry_count = (uint32_t)(got_sec->sh_size / entry_size);

    if (entry_count == 0)
        return EW_OK;

    ew_error_t err = got_ensure_capacity(out, entry_count);
    if (err != EW_OK)
        return err;

    out->base_addr = got_sec->sh_addr;
    out->size = got_sec->sh_size;
    out->is_got_plt = (strcmp(section_name, ".got.plt") == 0);

    ew_reader_t rd;
    ew_reader_init(&rd, got_sec->data, (size_t)got_sec->sh_size,
                    ctx->is_big_endian);

    for (uint32_t i = 0; i < entry_count; i++) {
        ew_got_entry_t *entry = &out->entries[out->count];
        memset(entry, 0, sizeof(*entry));

        entry->address = got_sec->sh_addr + (uint64_t)i * entry_size;

        if (ctx->is_64bit) {
            ew_read_u64(&rd, &entry->value);
        } else {
            uint32_t val32;
            ew_read_u32(&rd, &val32);
            entry->value = val32;
        }

        ew_relocation_t *rel = find_reloc_at(ctx, entry->address);
        if (rel) {
            entry->reloc_index = (uint32_t)(rel - ctx->relocs);
            if (rel->target_symbol) {
                entry->symbol_name = rel->target_symbol->name;
                entry->symbol_index = rel->sym_index;
                entry->is_resolved = rel->target_symbol->resolved;
            }

            if (rel->type == EW_R_X86_64_JUMP_SLOT)
                entry->is_lazy = 1;
        }

        out->count++;
    }

    return EW_OK;
}

ew_error_t ew_parse_plt(ew_context_t *ctx, ew_plt_table_t *out)
{
    if (!ctx || !out)
        return EW_ERR_INVALID;

    memset(out, 0, sizeof(*out));

    ew_section_t *plt_sec = find_section_by_name(ctx, ".plt");
    if (!plt_sec || !plt_sec->data || plt_sec->sh_size == 0)
        return EW_OK;

    uint64_t plt_entry_size = plt_sec->sh_entsize;
    if (plt_entry_size == 0)
        plt_entry_size = 16;

    uint32_t plt_count = (uint32_t)(plt_sec->sh_size / plt_entry_size);
    if (plt_count <= 1)
        return EW_OK;

    out->base_addr = plt_sec->sh_addr;
    out->entry_size = plt_entry_size;

    ew_got_table_t got_plt;
    ew_parse_got(ctx, &got_plt, ".got.plt");

    ew_error_t err = plt_ensure_capacity(out, plt_count - 1);
    if (err != EW_OK) {
        free(got_plt.entries);
        return err;
    }

    for (uint32_t i = 1; i < plt_count; i++) {
        ew_plt_entry_t *pe = &out->entries[out->count];
        memset(pe, 0, sizeof(*pe));

        pe->address = plt_sec->sh_addr + (uint64_t)i * plt_entry_size;
        pe->got_index = i;

        if (i < got_plt.count) {
            pe->got_entry_addr = got_plt.entries[i].address;
            pe->target_name = got_plt.entries[i].symbol_name;
            pe->is_resolved = got_plt.entries[i].is_resolved;
        }

        out->count++;
    }

    free(got_plt.entries);
    return EW_OK;
}

uint32_t ew_count_lazy_bindings(ew_context_t *ctx)
{
    uint32_t count = 0;
    ew_got_table_t got;

    if (ew_parse_got(ctx, &got, ".got.plt") != EW_OK)
        return 0;

    for (uint32_t i = 0; i < got.count; i++) {
        if (got.entries[i].is_lazy)
            count++;
    }

    free(got.entries);
    return count;
}

uint32_t ew_count_got_entries(ew_context_t *ctx)
{
    ew_got_table_t got;
    if (ew_parse_got(ctx, &got, ".got") != EW_OK)
        return 0;
    uint32_t n = got.count;
    free(got.entries);
    return n;
}

ew_error_t ew_report_got(ew_context_t *ctx, ew_report_t *report)
{
    if (!ctx || !report)
        return EW_ERR_INVALID;

    ew_got_table_t got;
    ew_error_t err = ew_parse_got(ctx, &got, ".got");
    if (err != EW_OK)
        return err;

    ew_got_table_t got_plt;
    err = ew_parse_got(ctx, &got_plt, ".got.plt");
    if (err != EW_OK) {
        free(got.entries);
        return err;
    }

    free(got.entries);
    free(got_plt.entries);
    return EW_OK;
}
