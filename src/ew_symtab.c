/*
 * ew_symtab.c — String table resolution and symbol table parsing.
 *
 * Locates string tables referenced by symbol tables, parses both
 * .symtab and .dynsym sections, and resolves symbol names through
 * their associated string tables.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* String table resolution                                             */
/* ------------------------------------------------------------------ */

static ew_error_t resolve_strtab_for_section(ew_context_t *ctx,
                                              ew_section_t *sec,
                                              const char **strtab_out,
                                              size_t *size_out)
{
    uint32_t link = sec->sh_link;
    if (link >= ctx->section_count) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "symbol table sh_link %u out of range", link);
        return EW_ERR_BAD_STRTAB;
    }

    ew_section_t *strsec = &ctx->sections[link];
    if (strsec->sh_type != EW_SHT_STRTAB) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "linked section %u is not STRTAB (type=%u)",
                 link, strsec->sh_type);
        return EW_ERR_BAD_STRTAB;
    }

    if (!strsec->data || strsec->sh_size == 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "linked string table %u has no data", link);
        return EW_ERR_BAD_STRTAB;
    }

    if (strsec->sh_size > EW_MAX_STRTAB_SIZE) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "string table %u too large: %lu bytes",
                 link, (unsigned long)strsec->sh_size);
        return EW_ERR_LIMIT;
    }

    if (!ew_validate_strtab(strsec->data, (size_t)strsec->sh_size)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "malformed string table at section %u", link);
        return EW_ERR_BAD_STRTAB;
    }

    *strtab_out = (const char *)strsec->data;
    *size_out   = (size_t)strsec->sh_size;
    return EW_OK;
}

ew_error_t ew_resolve_strtabs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ctx->symstrtab = NULL;
    ctx->symstrtab_size = 0;
    ctx->dynstrtab = NULL;
    ctx->dynstrtab_size = 0;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        if (sec->sh_type == EW_SHT_SYMTAB && !ctx->symstrtab) {
            ew_error_t err = resolve_strtab_for_section(
                ctx, sec, &ctx->symstrtab, &ctx->symstrtab_size);
            if (err != EW_OK) {
                ctx->last_error = err;
                return err;
            }
        }

        if (sec->sh_type == EW_SHT_DYNSYM && !ctx->dynstrtab) {
            ew_error_t err = resolve_strtab_for_section(
                ctx, sec, &ctx->dynstrtab, &ctx->dynstrtab_size);
            if (err != EW_OK) {
                ctx->last_error = err;
                return err;
            }
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol parsing (ELF32)                                              */
/* ------------------------------------------------------------------ */

static ew_error_t parse_sym32(ew_reader_t *rd, ew_symbol_t *sym)
{
    ew_error_t err;
    uint32_t val32;

    err = ew_read_u32(rd, &sym->st_name);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sym->st_value = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sym->st_size = val32;

    err = ew_read_u8(rd, &sym->st_info);
    if (err != EW_OK) return err;

    err = ew_read_u8(rd, &sym->st_other);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &sym->st_shndx);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol parsing (ELF64)                                              */
/* ------------------------------------------------------------------ */

static ew_error_t parse_sym64(ew_reader_t *rd, ew_symbol_t *sym)
{
    ew_error_t err;

    err = ew_read_u32(rd, &sym->st_name);
    if (err != EW_OK) return err;

    err = ew_read_u8(rd, &sym->st_info);
    if (err != EW_OK) return err;

    err = ew_read_u8(rd, &sym->st_other);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &sym->st_shndx);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sym->st_value);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sym->st_size);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol name resolution                                              */
/* ------------------------------------------------------------------ */

static void resolve_sym_names(ew_symbol_t *syms, uint32_t count,
                               const char *strtab, size_t strtab_size)
{
    for (uint32_t i = 0; i < count; i++) {
        ew_symbol_t *sym = &syms[i];
        sym->name = NULL;

        if (!strtab || strtab_size == 0)
            continue;

        if (sym->st_name >= strtab_size)
            continue;

        const char *name = strtab + sym->st_name;
        size_t remaining = strtab_size - sym->st_name;

        /* Verify null termination */
        int terminated = 0;
        for (size_t j = 0; j < remaining; j++) {
            if (name[j] == '\0') {
                terminated = 1;
                break;
            }
        }

        if (terminated)
            sym->name = name;
    }
}

/* ------------------------------------------------------------------ */
/* Section target resolution for symbols                               */
/* ------------------------------------------------------------------ */

static void resolve_sym_sections(ew_context_t *ctx, ew_symbol_t *syms,
                                  uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        ew_symbol_t *sym = &syms[i];
        sym->target_section = NULL;

        if (sym->st_shndx == EW_SHN_UNDEF ||
            sym->st_shndx == EW_SHN_ABS ||
            sym->st_shndx == EW_SHN_COMMON)
            continue;

        if (sym->st_shndx >= EW_SHN_LORESERVE)
            continue;

        if (sym->st_shndx < ctx->section_count) {
            sym->target_section = &ctx->sections[sym->st_shndx];
        }
    }
}

/* ------------------------------------------------------------------ */
/* Parse a single symbol table section                                 */
/* ------------------------------------------------------------------ */

static ew_error_t parse_symtab_section(ew_context_t *ctx, ew_section_t *sec,
                                        ew_symbol_t **syms_out,
                                        uint32_t *count_out,
                                        int is_dynamic)
{
    if (!sec->data || sec->sh_size == 0) {
        *syms_out = NULL;
        *count_out = 0;
        return EW_OK;
    }

    size_t entry_size = ctx->is_64bit ? 24 : 16;
    if (sec->sh_entsize > 0)
        entry_size = (size_t)sec->sh_entsize;

    if (entry_size < (ctx->is_64bit ? 24u : 16u)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "symbol entry size %zu too small", entry_size);
        return EW_ERR_BAD_SYMBOL;
    }

    uint32_t sym_count = (uint32_t)(sec->sh_size / entry_size);
    if (sym_count > EW_MAX_SYMBOLS) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "too many symbols: %u (max %u)", sym_count, EW_MAX_SYMBOLS);
        return EW_ERR_LIMIT;
    }

    ew_symbol_t *syms = calloc(sym_count, sizeof(ew_symbol_t));
    if (!syms)
        return EW_ERR_NOMEM;

    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    for (uint32_t i = 0; i < sym_count; i++) {
        size_t offset = (size_t)sec->sh_offset + (size_t)i * entry_size;
        ew_error_t err = ew_reader_seek(&rd, offset);
        if (err != EW_OK) {
            free(syms);
            return err;
        }

        syms[i].index = i;
        syms[i].is_dynamic = is_dynamic;
        syms[i].resolved = 0;
        syms[i].version_index = -1;
        syms[i].ownership_stage = 0;
        syms[i].generation = ctx->generation;

        if (ctx->is_64bit)
            err = parse_sym64(&rd, &syms[i]);
        else
            err = parse_sym32(&rd, &syms[i]);

        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "failed to parse symbol %u in %s",
                     i, is_dynamic ? "dynsym" : "symtab");
            free(syms);
            return err;
        }
    }

    *syms_out = syms;
    *count_out = sym_count;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point: parse all symbol tables                         */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_symtabs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        if (sec->sh_type == EW_SHT_SYMTAB && !ctx->symtab) {
            ew_error_t err = parse_symtab_section(
                ctx, sec, &ctx->symtab, &ctx->symtab_count, 0);
            if (err != EW_OK) {
                ctx->last_error = err;
                return err;
            }
            resolve_sym_names(ctx->symtab, ctx->symtab_count,
                              ctx->symstrtab, ctx->symstrtab_size);
            resolve_sym_sections(ctx, ctx->symtab, ctx->symtab_count);
        }

        if (sec->sh_type == EW_SHT_DYNSYM && !ctx->dynsym) {
            ew_error_t err = parse_symtab_section(
                ctx, sec, &ctx->dynsym, &ctx->dynsym_count, 1);
            if (err != EW_OK) {
                ctx->last_error = err;
                return err;
            }
            resolve_sym_names(ctx->dynsym, ctx->dynsym_count,
                              ctx->dynstrtab, ctx->dynstrtab_size);
            resolve_sym_sections(ctx, ctx->dynsym, ctx->dynsym_count);
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol counting                                                     */
/* ------------------------------------------------------------------ */

uint32_t ew_symbol_count(ew_context_t *ctx, int dynamic)
{
    if (!ctx)
        return 0;
    return dynamic ? ctx->dynsym_count : ctx->symtab_count;
}
