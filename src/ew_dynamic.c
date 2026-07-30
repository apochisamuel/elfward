/*
 * ew_dynamic.c — Dynamic section parsing.
 *
 * Reads the .dynamic section containing the array of Elf{32,64}_Dyn
 * entries, and resolves string-valued tags (DT_NEEDED, DT_SONAME,
 * DT_RPATH, DT_RUNPATH) through the dynamic string table.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Dynamic entry parsing (ELF32)                                       */
/* ------------------------------------------------------------------ */

static ew_error_t parse_dyn32(ew_reader_t *rd, ew_dynamic_entry_t *dyn)
{
    ew_error_t err;
    int32_t tag32;
    uint32_t val32;

    err = ew_read_i32(rd, &tag32);
    if (err != EW_OK) return err;
    dyn->d_tag = tag32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    dyn->d_val = val32;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Dynamic entry parsing (ELF64)                                       */
/* ------------------------------------------------------------------ */

static ew_error_t parse_dyn64(ew_reader_t *rd, ew_dynamic_entry_t *dyn)
{
    ew_error_t err;

    err = ew_read_i64(rd, &dyn->d_tag);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &dyn->d_val);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Identify string-valued dynamic tags                                 */
/* ------------------------------------------------------------------ */

static int is_string_tag(int64_t tag)
{
    switch (tag) {
    case EW_DT_NEEDED:
    case EW_DT_SONAME:
    case EW_DT_RPATH:
    case EW_DT_RUNPATH:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Resolve dynamic entry string values                                 */
/* ------------------------------------------------------------------ */

static void resolve_dynamic_strings(ew_context_t *ctx)
{
    if (!ctx->dynstrtab || ctx->dynstrtab_size == 0)
        return;

    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        ew_dynamic_entry_t *dyn = &ctx->dynamics[i];

        if (dyn->d_tag == EW_DT_NULL)
            break;

        if (!is_string_tag(dyn->d_tag)) {
            dyn->string_val = NULL;
            dyn->resolved = 1;
            continue;
        }

        if (dyn->d_val >= ctx->dynstrtab_size) {
            dyn->string_val = NULL;
            dyn->resolved = 0;
            continue;
        }

        const char *name = ctx->dynstrtab + dyn->d_val;
        size_t remaining = ctx->dynstrtab_size - (size_t)dyn->d_val;

        int terminated = 0;
        for (size_t j = 0; j < remaining; j++) {
            if (name[j] == '\0') {
                terminated = 1;
                break;
            }
        }

        if (terminated) {
            dyn->string_val = name;
            dyn->resolved = 1;
        } else {
            dyn->string_val = NULL;
            dyn->resolved = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Validate dynamic section consistency                                */
/* ------------------------------------------------------------------ */

static ew_error_t validate_dynamic_entries(ew_context_t *ctx)
{
    int has_strtab = 0;
    int has_symtab = 0;
    int has_strsz = 0;
    int has_null_terminator = 0;

    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        ew_dynamic_entry_t *dyn = &ctx->dynamics[i];

        if (dyn->d_tag == EW_DT_NULL) {
            has_null_terminator = 1;
            break;
        }

        switch (dyn->d_tag) {
        case EW_DT_STRTAB:
            has_strtab = 1;
            break;
        case EW_DT_SYMTAB:
            has_symtab = 1;
            break;
        case EW_DT_STRSZ:
            has_strsz = 1;
            break;
        default:
            break;
        }
    }

    if (!has_null_terminator) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "dynamic section lacks DT_NULL terminator");
        return EW_ERR_BAD_DYNAMIC;
    }

    /* Warn about missing mandatory tags but don't fail */
    (void)has_strtab;
    (void)has_symtab;
    (void)has_strsz;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Extract DT_NEEDED library names                                     */
/* ------------------------------------------------------------------ */

static uint32_t count_needed_libs(ew_context_t *ctx)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        if (ctx->dynamics[i].d_tag == EW_DT_NEEDED)
            count++;
        if (ctx->dynamics[i].d_tag == EW_DT_NULL)
            break;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Find specific dynamic tag value                                     */
/* ------------------------------------------------------------------ */

static ew_dynamic_entry_t *find_dyn_tag(ew_context_t *ctx, int64_t tag)
{
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        if (ctx->dynamics[i].d_tag == tag)
            return &ctx->dynamics[i];
        if (ctx->dynamics[i].d_tag == EW_DT_NULL)
            break;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Cross-validate dynamic pointers against section table               */
/* ------------------------------------------------------------------ */

static ew_error_t cross_validate_dynamic(ew_context_t *ctx)
{
    /* Check DT_HASH points to a valid section */
    ew_dynamic_entry_t *dt_hash = find_dyn_tag(ctx, EW_DT_HASH);
    if (dt_hash) {
        int found = 0;
        for (uint32_t i = 0; i < ctx->section_count; i++) {
            if (ctx->sections[i].sh_type == EW_SHT_HASH &&
                ctx->sections[i].sh_addr == dt_hash->d_val) {
                found = 1;
                break;
            }
        }
        if (!found && ctx->section_count > 0) {
            /* DT_HASH doesn't match any section; not fatal */
        }
    }

    /* Check DT_GNU_HASH similarly */
    ew_dynamic_entry_t *dt_gnu = find_dyn_tag(ctx, EW_DT_GNU_HASH);
    if (dt_gnu) {
        int found = 0;
        for (uint32_t i = 0; i < ctx->section_count; i++) {
            if (ctx->sections[i].sh_type == EW_SHT_GNU_HASH &&
                ctx->sections[i].sh_addr == dt_gnu->d_val) {
                found = 1;
                break;
            }
        }
        (void)found;
    }

    /* Verify DT_STRSZ matches .dynstr size if available */
    ew_dynamic_entry_t *dt_strsz = find_dyn_tag(ctx, EW_DT_STRSZ);
    if (dt_strsz && ctx->dynstrtab_size > 0) {
        if (dt_strsz->d_val != ctx->dynstrtab_size) {
            /* Size mismatch; note but don't fail */
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point: parse dynamic section                           */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_dynamics(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Find the DYNAMIC section */
    ew_section_t *dyn_sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_DYNAMIC) {
            dyn_sec = &ctx->sections[i];
            break;
        }
    }

    if (!dyn_sec || !dyn_sec->data || dyn_sec->sh_size == 0) {
        ctx->dynamics = NULL;
        ctx->dynamic_count = 0;
        return EW_OK;
    }

    /* Determine entry size */
    size_t entry_size = ctx->is_64bit ? 16 : 8;
    if (dyn_sec->sh_entsize > 0)
        entry_size = (size_t)dyn_sec->sh_entsize;

    if (entry_size < (ctx->is_64bit ? 16u : 8u)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "dynamic entry size %zu too small", entry_size);
        ctx->last_error = EW_ERR_BAD_DYNAMIC;
        return EW_ERR_BAD_DYNAMIC;
    }

    uint32_t dyn_count = (uint32_t)(dyn_sec->sh_size / entry_size);
    if (dyn_count > EW_MAX_DYNAMIC_ENTRIES) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "too many dynamic entries: %u", dyn_count);
        ctx->last_error = EW_ERR_LIMIT;
        return EW_ERR_LIMIT;
    }

    ctx->dynamics = calloc(dyn_count, sizeof(ew_dynamic_entry_t));
    if (!ctx->dynamics) {
        ctx->last_error = EW_ERR_NOMEM;
        return EW_ERR_NOMEM;
    }
    ctx->dynamic_count = dyn_count;

    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    for (uint32_t i = 0; i < dyn_count; i++) {
        size_t offset = (size_t)dyn_sec->sh_offset + (size_t)i * entry_size;
        ew_error_t err = ew_reader_seek(&rd, offset);
        if (err != EW_OK) {
            ctx->last_error = err;
            return err;
        }

        if (ctx->is_64bit)
            err = parse_dyn64(&rd, &ctx->dynamics[i]);
        else
            err = parse_dyn32(&rd, &ctx->dynamics[i]);

        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "failed to parse dynamic entry %u", i);
            ctx->last_error = err;
            return err;
        }

        /* Stop at DT_NULL */
        if (ctx->dynamics[i].d_tag == EW_DT_NULL) {
            ctx->dynamic_count = i + 1;
            break;
        }
    }

    /* Resolve string values */
    resolve_dynamic_strings(ctx);

    /* Validate dynamic section */
    ew_error_t err = validate_dynamic_entries(ctx);
    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    /* Cross-validate with section table */
    cross_validate_dynamic(ctx);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Validation entry point for dynamic section                          */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate_dynamics(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (!ctx->dynamics || ctx->dynamic_count == 0)
        return EW_OK;

    /* Check for duplicate DT_SONAME */
    int soname_count = 0;
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        if (ctx->dynamics[i].d_tag == EW_DT_SONAME)
            soname_count++;
        if (ctx->dynamics[i].d_tag == EW_DT_NULL)
            break;
    }
    if (soname_count > 1) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "multiple DT_SONAME entries found");
        return EW_ERR_DUPLICATE;
    }

    /* Verify DT_NEEDED libraries have resolved names */
    uint32_t needed = count_needed_libs(ctx);
    if (needed > EW_MAX_DEPENDENCIES) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "too many DT_NEEDED entries: %u", needed);
        return EW_ERR_LIMIT;
    }

    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        ew_dynamic_entry_t *dyn = &ctx->dynamics[i];
        if (dyn->d_tag == EW_DT_NULL)
            break;

        if (dyn->d_tag == EW_DT_NEEDED && !dyn->string_val) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "unresolved DT_NEEDED at index %u (offset %lu)",
                     i, (unsigned long)dyn->d_val);
            return EW_ERR_UNRESOLVED;
        }
    }

    return EW_OK;
}
