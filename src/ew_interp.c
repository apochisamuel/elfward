/*
 * ew_interp.c — Interpreter and initialization array parsing.
 *
 * Extracts the PT_INTERP path (dynamic linker), parses .init_array,
 * .fini_array, and .preinit_array sections, and resolves DT_INIT
 * and DT_FINI addresses to their corresponding symbols.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint64_t *addrs;
    uint32_t  count;
    uint32_t  capacity;
} ew_func_array_t;

typedef struct {
    const char      *interp_path;
    uint64_t         init_addr;
    uint64_t         fini_addr;
    ew_func_array_t  init_array;
    ew_func_array_t  fini_array;
    ew_func_array_t  preinit_array;
    int              has_interp;
    int              has_init;
    int              has_fini;
} ew_init_info_t;

static ew_error_t func_array_add(ew_func_array_t *arr, uint64_t addr)
{
    if (arr->count >= arr->capacity) {
        uint32_t new_cap = arr->capacity == 0 ? 16 : arr->capacity * 2;
        if (new_cap > 4096)
            return EW_ERR_LIMIT;
        uint64_t *tmp = realloc(arr->addrs, new_cap * sizeof(uint64_t));
        if (!tmp)
            return EW_ERR_NOMEM;
        arr->addrs = tmp;
        arr->capacity = new_cap;
    }
    arr->addrs[arr->count++] = addr;
    return EW_OK;
}

static void func_array_free(ew_func_array_t *arr)
{
    free(arr->addrs);
    arr->addrs = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

static ew_error_t parse_interp(ew_context_t *ctx, ew_init_info_t *info)
{
    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg = &ctx->segments[i];
        if (seg->p_type != EW_PT_INTERP)
            continue;

        if (!seg->data || seg->p_filesz == 0)
            continue;

        size_t len = (size_t)seg->p_filesz;
        const uint8_t *data_ptr = seg->data;
        int null_terminated = 0;
        for (size_t j = 0; j < len; j++) {
            if (data_ptr[j] == '\0') {
                null_terminated = 1;
                break;
            }
        }

        if (null_terminated) {
            info->interp_path = (const char *)data_ptr;
            info->has_interp = 1;
        }
        break;
    }

    return EW_OK;
}

static ew_error_t parse_func_array(ew_context_t *ctx,
                                    ew_section_t *sec,
                                    ew_func_array_t *arr)
{
    if (!sec || !sec->data || sec->sh_size == 0)
        return EW_OK;

    size_t entry_size = ctx->is_64bit ? 8 : 4;
    uint32_t count = (uint32_t)(sec->sh_size / entry_size);

    if (count > 4096)
        return EW_ERR_LIMIT;

    ew_reader_t rd;
    ew_reader_init(&rd, sec->data, (size_t)sec->sh_size,
                    ctx->is_big_endian);

    for (uint32_t i = 0; i < count; i++) {
        uint64_t addr;
        if (ctx->is_64bit) {
            ew_error_t err = ew_read_u64(&rd, &addr);
            if (err != EW_OK) break;
        } else {
            uint32_t val32;
            ew_error_t err = ew_read_u32(&rd, &val32);
            if (err != EW_OK) break;
            addr = val32;
        }

        if (addr == 0 || addr == (uint64_t)-1)
            continue;

        ew_error_t err = func_array_add(arr, addr);
        if (err != EW_OK)
            return err;
    }

    return EW_OK;
}

static void resolve_init_fini_from_dynamic(ew_context_t *ctx,
                                            ew_init_info_t *info)
{
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        ew_dynamic_entry_t *dyn = &ctx->dynamics[i];
        if (dyn->d_tag == EW_DT_NULL)
            break;

        switch (dyn->d_tag) {
        case EW_DT_INIT:
            info->init_addr = dyn->d_val;
            info->has_init = 1;
            break;
        case EW_DT_FINI:
            info->fini_addr = dyn->d_val;
            info->has_fini = 1;
            break;
        default:
            break;
        }
    }
}

ew_error_t ew_parse_init_info(ew_context_t *ctx, ew_init_info_t *info)
{
    if (!ctx || !info)
        return EW_ERR_INVALID;

    memset(info, 0, sizeof(*info));

    ew_error_t err = parse_interp(ctx, info);
    if (err != EW_OK)
        return err;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        switch (sec->sh_type) {
        case EW_SHT_INIT_ARRAY:
            err = parse_func_array(ctx, sec, &info->init_array);
            if (err != EW_OK) goto fail;
            break;
        case EW_SHT_FINI_ARRAY:
            err = parse_func_array(ctx, sec, &info->fini_array);
            if (err != EW_OK) goto fail;
            break;
        case EW_SHT_PREINIT_ARRAY:
            err = parse_func_array(ctx, sec, &info->preinit_array);
            if (err != EW_OK) goto fail;
            break;
        default:
            break;
        }
    }

    if (ctx->dynamics && ctx->dynamic_count > 0) {
        resolve_init_fini_from_dynamic(ctx, info);
    }

    return EW_OK;

fail:
    func_array_free(&info->init_array);
    func_array_free(&info->fini_array);
    func_array_free(&info->preinit_array);
    return err;
}

void ew_init_info_destroy(ew_init_info_t *info)
{
    if (!info)
        return;
    func_array_free(&info->init_array);
    func_array_free(&info->fini_array);
    func_array_free(&info->preinit_array);
    memset(info, 0, sizeof(*info));
}

const char *ew_find_symbol_at(ew_context_t *ctx, uint64_t addr)
{
    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (sym->st_value == addr && sym->name &&
                sym->name[0] != '\0') {
                return sym->name;
            }
        }
    }
    return NULL;
}

ew_error_t ew_report_init_info(ew_context_t *ctx, ew_report_t *report)
{
    if (!ctx || !report)
        return EW_ERR_INVALID;

    ew_init_info_t info;
    ew_error_t err = ew_parse_init_info(ctx, &info);
    if (err != EW_OK)
        return err;

    ew_init_info_destroy(&info);
    return EW_OK;
}
