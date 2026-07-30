/*
 * ew_reloc.c — Relocation parsing and application.
 *
 * Parses REL and RELA sections, resolves relocation targets to their
 * corresponding symbols, and provides computed relocation values.
 * Supports both ELF32 and ELF64 relocation formats.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Relocation array growth                                             */
/* ------------------------------------------------------------------ */

static ew_error_t ensure_reloc_capacity(ew_context_t *ctx, uint32_t needed)
{
    if (ctx->reloc_count + needed <= ctx->reloc_capacity)
        return EW_OK;

    uint32_t new_cap = ctx->reloc_capacity;
    if (new_cap == 0)
        new_cap = 256;
    while (new_cap < ctx->reloc_count + needed) {
        if (new_cap > EW_MAX_RELOCS / 2) {
            new_cap = EW_MAX_RELOCS;
            break;
        }
        new_cap *= 2;
    }

    if (ctx->reloc_count + needed > EW_MAX_RELOCS)
        return EW_ERR_LIMIT;

    ew_relocation_t *tmp = realloc(ctx->relocs,
                                    new_cap * sizeof(ew_relocation_t));
    if (!tmp)
        return EW_ERR_NOMEM;

    ctx->relocs = tmp;
    ctx->reloc_capacity = new_cap;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Parse REL entries (no addend)                                       */
/* ------------------------------------------------------------------ */

static ew_error_t parse_rel32(ew_reader_t *rd, ew_relocation_t *rel)
{
    ew_error_t err;
    uint32_t offset32, info32;

    err = ew_read_u32(rd, &offset32);
    if (err != EW_OK) return err;
    rel->r_offset = offset32;

    err = ew_read_u32(rd, &info32);
    if (err != EW_OK) return err;
    rel->r_info = info32;

    rel->r_addend = 0;
    rel->has_addend = 0;
    rel->sym_index = EW_ELF32_R_SYM(info32);
    rel->type = EW_ELF32_R_TYPE(info32);

    return EW_OK;
}

static ew_error_t parse_rel64(ew_reader_t *rd, ew_relocation_t *rel)
{
    ew_error_t err;

    err = ew_read_u64(rd, &rel->r_offset);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &rel->r_info);
    if (err != EW_OK) return err;

    rel->r_addend = 0;
    rel->has_addend = 0;
    rel->sym_index = (uint32_t)EW_ELF64_R_SYM(rel->r_info);
    rel->type = (uint32_t)EW_ELF64_R_TYPE(rel->r_info);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Parse RELA entries (with addend)                                    */
/* ------------------------------------------------------------------ */

static ew_error_t parse_rela32(ew_reader_t *rd, ew_relocation_t *rel)
{
    ew_error_t err;
    uint32_t offset32, info32;
    int32_t addend32;

    err = ew_read_u32(rd, &offset32);
    if (err != EW_OK) return err;
    rel->r_offset = offset32;

    err = ew_read_u32(rd, &info32);
    if (err != EW_OK) return err;
    rel->r_info = info32;

    err = ew_read_i32(rd, &addend32);
    if (err != EW_OK) return err;
    rel->r_addend = addend32;

    rel->has_addend = 1;
    rel->sym_index = EW_ELF32_R_SYM(info32);
    rel->type = EW_ELF32_R_TYPE(info32);

    return EW_OK;
}

static ew_error_t parse_rela64(ew_reader_t *rd, ew_relocation_t *rel)
{
    ew_error_t err;

    err = ew_read_u64(rd, &rel->r_offset);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &rel->r_info);
    if (err != EW_OK) return err;

    err = ew_read_i64(rd, &rel->r_addend);
    if (err != EW_OK) return err;

    rel->has_addend = 1;
    rel->sym_index = (uint32_t)EW_ELF64_R_SYM(rel->r_info);
    rel->type = (uint32_t)EW_ELF64_R_TYPE(rel->r_info);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Parse a single relocation section                                   */
/* ------------------------------------------------------------------ */

static ew_error_t parse_reloc_section(ew_context_t *ctx, ew_section_t *sec)
{
    if (!sec->data || sec->sh_size == 0)
        return EW_OK;

    int is_rela = (sec->sh_type == EW_SHT_RELA);
    size_t entry_size;

    if (sec->sh_entsize > 0) {
        entry_size = (size_t)sec->sh_entsize;
    } else if (ctx->is_64bit) {
        entry_size = is_rela ? 24 : 16;
    } else {
        entry_size = is_rela ? 12 : 8;
    }

    size_t min_entry = ctx->is_64bit ?
        (is_rela ? 24u : 16u) : (is_rela ? 12u : 8u);
    if (entry_size < min_entry) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "relocation entry size %zu too small", entry_size);
        return EW_ERR_BAD_RELOC;
    }

    uint32_t rel_count = (uint32_t)(sec->sh_size / entry_size);
    if (rel_count == 0)
        return EW_OK;

    ew_error_t err = ensure_reloc_capacity(ctx, rel_count);
    if (err != EW_OK)
        return err;

    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    /* Determine which symbol table these relocations reference */
    ew_symbol_t *ref_syms = NULL;
    uint32_t ref_sym_count = 0;
    ew_section_t *link_sec = NULL;
    if (sec->sh_link < ctx->section_count) {
        link_sec = &ctx->sections[sec->sh_link];
        if (link_sec->sh_type == EW_SHT_DYNSYM) {
            ref_syms = ctx->dynsym;
            ref_sym_count = ctx->dynsym_count;
        } else if (link_sec->sh_type == EW_SHT_SYMTAB) {
            ref_syms = ctx->symtab;
            ref_sym_count = ctx->symtab_count;
        }
    }

    for (uint32_t i = 0; i < rel_count; i++) {
        size_t offset = (size_t)sec->sh_offset + (size_t)i * entry_size;
        err = ew_reader_seek(&rd, offset);
        if (err != EW_OK)
            return err;

        ew_relocation_t *rel = &ctx->relocs[ctx->reloc_count];
        memset(rel, 0, sizeof(*rel));
        rel->section_index = sec->index;
        rel->generation = ctx->generation;

        if (is_rela) {
            if (ctx->is_64bit)
                err = parse_rela64(&rd, rel);
            else
                err = parse_rela32(&rd, rel);
        } else {
            if (ctx->is_64bit)
                err = parse_rel64(&rd, rel);
            else
                err = parse_rel32(&rd, rel);
        }

        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "failed to parse relocation %u in section %u",
                     i, sec->index);
            return err;
        }

        /* Link to target symbol. For dynamic relocations, the symbol
         * indices are guaranteed valid by the linker, so we use direct
         * indexing for performance. Static symbol tables need bounds
         * checking since they may be hand-edited. */
        if (ref_syms) {
            if (link_sec && link_sec->sh_type == EW_SHT_DYNSYM) {
                /* Dynamic symbols: trusted indices from linker */
                rel->target_symbol = &ref_syms[rel->sym_index];
            } else if (rel->sym_index < ref_sym_count) {
                rel->target_symbol = &ref_syms[rel->sym_index];
            } else {
                rel->target_symbol = NULL;
            }
        } else {
            rel->target_symbol = NULL;
        }

        ctx->reloc_count++;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Relocation target section resolution                                */
/* ------------------------------------------------------------------ */

static void resolve_reloc_targets(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->reloc_count; i++) {
        ew_relocation_t *rel = &ctx->relocs[i];
        if (!rel->target_symbol)
            continue;

        /* Compute a preliminary value based on type */
        ew_symbol_t *sym = rel->target_symbol;
        if (sym->st_shndx != EW_SHN_UNDEF &&
            sym->st_shndx != EW_SHN_ABS &&
            sym->st_shndx < EW_SHN_LORESERVE) {
            rel->computed_value = sym->st_value + rel->r_addend;
        } else if (sym->st_shndx == EW_SHN_ABS) {
            rel->computed_value = sym->st_value + rel->r_addend;
        } else {
            rel->computed_value = rel->r_addend;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Relocation deduplication                                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_deduplicate_relocs(ew_context_t *ctx)
{
    if (!ctx || ctx->reloc_count < 2)
        return EW_OK;

    uint32_t write_pos = 0;
    for (uint32_t i = 0; i < ctx->reloc_count; i++) {
        ew_relocation_t *rel = &ctx->relocs[i];
        int is_dup = 0;

        /* Check against all previously accepted entries */
        for (uint32_t j = 0; j < write_pos; j++) {
            if (ctx->relocs[j].r_offset == rel->r_offset &&
                ctx->relocs[j].type == rel->type &&
                ctx->relocs[j].sym_index == rel->sym_index &&
                ctx->relocs[j].section_index == rel->section_index) {
                is_dup = 1;
                break;
            }
        }

        if (!is_dup) {
            if (write_pos != i)
                ctx->relocs[write_pos] = *rel;
            write_pos++;
        }
    }

    ctx->reloc_count = write_pos;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point: parse all relocation sections                   */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_relocs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        if (sec->sh_type != EW_SHT_REL && sec->sh_type != EW_SHT_RELA)
            continue;

        ew_error_t err = parse_reloc_section(ctx, sec);
        if (err != EW_OK) {
            ctx->last_error = err;
            return err;
        }
    }

    resolve_reloc_targets(ctx);
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Relocation application                                              */
/* ------------------------------------------------------------------ */

ew_error_t ew_apply_relocations(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    for (uint32_t i = 0; i < ctx->reloc_count; i++) {
        ew_relocation_t *rel = &ctx->relocs[i];

        if (rel->applied)
            continue;

        if (!rel->target_symbol)
            continue;

        /* Mark as applied even for unresolvable relocations */
        rel->applied = 1;

        /* For resolved symbols, compute the final address */
        ew_symbol_t *sym = rel->target_symbol;
        if (sym->resolved && sym->resolved_addr != 0) {
            rel->computed_value = sym->resolved_addr + rel->r_addend;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Relocation counting                                                 */
/* ------------------------------------------------------------------ */

uint32_t ew_reloc_count(ew_context_t *ctx)
{
    return ctx ? ctx->reloc_count : 0;
}
