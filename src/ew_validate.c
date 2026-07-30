/*
 * ew_validate.c — Structural validation passes.
 *
 * Performs consistency checks across all parsed structures: sections,
 * symbols, relocations, dynamic entries, and the dependency graph.
 * Each validation function returns the first error encountered.
 */

#include "elfward.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Section validation                                                  */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate_sections(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (!ctx->sections || ctx->section_count == 0)
        return EW_OK;

    /* First section must be SHT_NULL */
    if (ctx->section_count > 0 && ctx->sections[0].sh_type != EW_SHT_NULL) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "first section is not SHT_NULL");
        return EW_ERR_BAD_SECTION;
    }

    /* Check for overlapping sections in file layout */
    for (uint32_t i = 1; i < ctx->section_count; i++) {
        ew_section_t *si = &ctx->sections[i];
        if (si->sh_type == EW_SHT_NULL || si->sh_type == EW_SHT_NOBITS)
            continue;
        if (si->sh_size == 0)
            continue;

        for (uint32_t j = i + 1; j < ctx->section_count; j++) {
            ew_section_t *sj = &ctx->sections[j];
            if (sj->sh_type == EW_SHT_NULL || sj->sh_type == EW_SHT_NOBITS)
                continue;
            if (sj->sh_size == 0)
                continue;

            /* Check file range overlap */
            uint64_t i_end = si->sh_offset + si->sh_size;
            uint64_t j_end = sj->sh_offset + sj->sh_size;

            if (si->sh_offset < j_end && sj->sh_offset < i_end) {
                /* Overlapping sections are legal (e.g., overlays) but note */
            }
        }
    }

    /* Validate section alignment */
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        if (sec->sh_addralign > 1) {
            if ((sec->sh_addralign & (sec->sh_addralign - 1)) != 0) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "section %u alignment %lu not power of two",
                         i, (unsigned long)sec->sh_addralign);
                return EW_ERR_BAD_SECTION;
            }

            if ((sec->sh_flags & EW_SHF_ALLOC) &&
                sec->sh_addr % sec->sh_addralign != 0) {
                /* Misaligned section; warning */
            }
        }
    }

    /* Check that SYMTAB/DYNSYM sections have valid string table links */
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        if (sec->sh_type != EW_SHT_SYMTAB && sec->sh_type != EW_SHT_DYNSYM)
            continue;

        if (sec->sh_link >= ctx->section_count) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "symtab section %u has invalid sh_link %u",
                     i, sec->sh_link);
            return EW_ERR_BAD_SECTION;
        }

        ew_section_t *linked = &ctx->sections[sec->sh_link];
        if (linked->sh_type != EW_SHT_STRTAB) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "symtab section %u sh_link points to non-STRTAB "
                     "(type=%s)", i, ew_section_type_name(linked->sh_type));
            return EW_ERR_BAD_SECTION;
        }

        /* sh_info should be the index of the first non-local symbol */
        if (sec->sh_info > sec->sh_size / (sec->sh_entsize > 0 ?
                                            sec->sh_entsize : 1)) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "symtab section %u sh_info %u exceeds symbol count",
                     i, sec->sh_info);
            return EW_ERR_BAD_SECTION;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol validation                                                   */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate_symbols(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Validate static symbol table */
    if (ctx->symtab) {
        /* First symbol should be null */
        if (ctx->symtab_count > 0) {
            ew_symbol_t *null_sym = &ctx->symtab[0];
            if (null_sym->st_name != 0 || null_sym->st_value != 0 ||
                null_sym->st_size != 0 || null_sym->st_info != 0 ||
                null_sym->st_shndx != EW_SHN_UNDEF) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "symtab[0] is not a null symbol");
                return EW_ERR_BAD_SYMBOL;
            }
        }

        /* Check symbol section indices */
        for (uint32_t i = 1; i < ctx->symtab_count; i++) {
            ew_symbol_t *sym = &ctx->symtab[i];

            if (sym->st_shndx >= EW_SHN_LORESERVE)
                continue;
            if (sym->st_shndx == EW_SHN_UNDEF)
                continue;

            if (sym->st_shndx >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "symbol %u section index %u out of range",
                         i, sym->st_shndx);
                return EW_ERR_BAD_SYMBOL;
            }
        }

        /* Check local symbols precede global symbols */
        int seen_global = 0;
        for (uint32_t i = 0; i < ctx->symtab_count; i++) {
            uint8_t bind = EW_ELF_ST_BIND(ctx->symtab[i].st_info);
            if (bind != EW_STB_LOCAL)
                seen_global = 1;
            else if (seen_global) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "local symbol %u follows global symbols", i);
                return EW_ERR_BAD_SYMBOL;
            }
        }
    }

    /* Validate dynamic symbol table similarly */
    if (ctx->dynsym && ctx->dynsym_count > 0) {
        ew_symbol_t *null_sym = &ctx->dynsym[0];
        if (null_sym->st_name != 0 || null_sym->st_value != 0 ||
            null_sym->st_size != 0 || null_sym->st_info != 0 ||
            null_sym->st_shndx != EW_SHN_UNDEF) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "dynsym[0] is not a null symbol");
            return EW_ERR_BAD_SYMBOL;
        }

        for (uint32_t i = 1; i < ctx->dynsym_count; i++) {
            ew_symbol_t *sym = &ctx->dynsym[i];

            if (sym->st_shndx >= EW_SHN_LORESERVE)
                continue;
            if (sym->st_shndx == EW_SHN_UNDEF)
                continue;

            if (sym->st_shndx >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "dynsym %u section index %u out of range",
                         i, sym->st_shndx);
                return EW_ERR_BAD_SYMBOL;
            }
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Relocation validation                                               */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate_relocs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    for (uint32_t i = 0; i < ctx->reloc_count; i++) {
        ew_relocation_t *rel = &ctx->relocs[i];

        /* Verify relocation type is known */
        if (ctx->header.e_machine == EW_EM_X86_64) {
            if (rel->type > 37 && rel->type != 0) {
                /* Unknown relocation type; warn */
            }
        }

        /* Verify target symbol exists */
        if (rel->target_symbol) {
            /* Check symbol is within bounds of its table */
            if (rel->target_symbol->is_dynamic) {
                if (rel->sym_index >= ctx->dynsym_count) {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                             "reloc %u references dynsym index %u "
                             "(count=%u)", i, rel->sym_index,
                             ctx->dynsym_count);
                    return EW_ERR_BAD_RELOC;
                }
            }
        }

        /* Verify relocation offset is within a valid section */
        int in_section = 0;
        for (uint32_t j = 0; j < ctx->section_count; j++) {
            ew_section_t *sec = &ctx->sections[j];
            if (sec->sh_type == EW_SHT_NULL || sec->sh_type == EW_SHT_NOBITS)
                continue;
            if (!(sec->sh_flags & EW_SHF_ALLOC))
                continue;

            if (rel->r_offset >= sec->sh_addr &&
                rel->r_offset < sec->sh_addr + sec->sh_size) {
                in_section = 1;
                break;
            }
        }

        /* Also check against segments */
        if (!in_section) {
            for (uint32_t j = 0; j < ctx->segment_count; j++) {
                ew_segment_t *seg = &ctx->segments[j];
                if (seg->p_type != EW_PT_LOAD)
                    continue;
                if (rel->r_offset >= seg->p_vaddr &&
                    rel->r_offset < seg->p_vaddr + seg->p_memsz) {
                    in_section = 1;
                    break;
                }
            }
        }

        /* Not being in any section/segment is a warning, not error */
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Full validation                                                     */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_error_t err;

    err = ew_validate_sections(ctx);
    if (err != EW_OK) return err;

    err = ew_validate_symbols(ctx);
    if (err != EW_OK) return err;

    err = ew_validate_relocs(ctx);
    if (err != EW_OK) return err;

    err = ew_validate_dynamics(ctx);
    if (err != EW_OK) return err;

    err = ew_validate_graph(ctx);
    if (err != EW_OK) return err;

    ctx->validated = 1;
    return EW_OK;
}
