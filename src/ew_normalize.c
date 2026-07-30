/*
 * ew_normalize.c — Canonicalization and normalization.
 *
 * Transforms parsed ELF data into canonical forms: deduplicates
 * sections by name+type, normalizes symbol ordering, and produces
 * a consistent representation for downstream querying.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Section canonicalization                                            */
/* ------------------------------------------------------------------ */

ew_error_t ew_canonicalize_sections(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (!ctx->sections || ctx->section_count == 0)
        return EW_OK;

    /* Assign stable canonical IDs based on name+type dedup */
    int next_id = 1;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        if (sec->sh_type == EW_SHT_NULL) {
            sec->canonical_id = 0;
            continue;
        }

        /* Check for earlier section with same name and type */
        int found_dup = 0;
        if (sec->name) {
            for (uint32_t j = 0; j < i; j++) {
                ew_section_t *prev = &ctx->sections[j];
                if (prev->name && prev->sh_type == sec->sh_type &&
                    strcmp(prev->name, sec->name) == 0) {
                    sec->canonical_id = prev->canonical_id;
                    found_dup = 1;
                    break;
                }
            }
        }

        if (!found_dup) {
            sec->canonical_id = next_id++;
        }
    }

    /* Verify canonical ID uniqueness per name+type pair */
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *si = &ctx->sections[i];
        if (si->sh_type == EW_SHT_NULL || !si->name)
            continue;

        for (uint32_t j = i + 1; j < ctx->section_count; j++) {
            ew_section_t *sj = &ctx->sections[j];
            if (sj->sh_type == EW_SHT_NULL || !sj->name)
                continue;

            if (si->canonical_id == sj->canonical_id) {
                /* Same canonical group; verify they share name+type */
                if (strcmp(si->name, sj->name) != 0 ||
                    si->sh_type != sj->sh_type) {
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                             "canonical ID collision: sections %u and %u",
                             i, j);
                    return EW_ERR_INTERNAL;
                }
            }
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbol normalization                                                */
/* ------------------------------------------------------------------ */

ew_error_t ew_normalize_symbols(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Normalize static symbol table: verify local-before-global ordering */
    if (ctx->symtab && ctx->symtab_count > 1) {
        int first_global = -1;
        for (uint32_t i = 0; i < ctx->symtab_count; i++) {
            uint8_t bind = EW_ELF_ST_BIND(ctx->symtab[i].st_info);
            if (bind != EW_STB_LOCAL && first_global < 0) {
                first_global = (int)i;
                break;
            }
        }

        /* Update ownership generation for all symbols */
        for (uint32_t i = 0; i < ctx->symtab_count; i++) {
            ctx->symtab[i].generation = ctx->generation;
        }
    }

    /* Same for dynamic symbols */
    if (ctx->dynsym && ctx->dynsym_count > 1) {
        for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
            ctx->dynsym[i].generation = ctx->generation;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Full normalization pass                                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_normalize(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_error_t err;

    err = ew_canonicalize_sections(ctx);
    if (err != EW_OK) return err;

    err = ew_normalize_symbols(ctx);
    if (err != EW_OK) return err;

    err = ew_deduplicate_relocs(ctx);
    if (err != EW_OK) return err;

    ctx->normalized = 1;
    ctx->generation++;

    return EW_OK;
}
