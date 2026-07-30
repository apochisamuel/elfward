/*
 * ew_recover.c — Error recovery and full parse orchestration.
 *
 * Provides graceful recovery from parse errors by attempting partial
 * analysis of remaining valid structures. Also implements the
 * ew_parse_full() and ew_full_analysis() convenience functions that
 * execute the complete analysis pipeline.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Error recoverability classification                                 */
/* ------------------------------------------------------------------ */

int ew_is_recoverable(ew_error_t err)
{
    switch (err) {
    case EW_OK:
        return 1;

    /* Fatal errors that prevent any further processing */
    case EW_ERR_NOMEM:
    case EW_ERR_BAD_MAGIC:
    case EW_ERR_BAD_CLASS:
    case EW_ERR_BAD_ENCODING:
    case EW_ERR_BAD_VERSION:
    case EW_ERR_INTERNAL:
        return 0;

    /* Recoverable: can continue with partial data */
    case EW_ERR_INVALID:
    case EW_ERR_TRUNCATED:
    case EW_ERR_BAD_SECTION:
    case EW_ERR_BAD_SEGMENT:
    case EW_ERR_BAD_SYMBOL:
    case EW_ERR_BAD_RELOC:
    case EW_ERR_BAD_DYNAMIC:
    case EW_ERR_BAD_NOTE:
    case EW_ERR_BAD_HASH:
    case EW_ERR_BAD_VERSION_INFO:
    case EW_ERR_BAD_STRTAB:
    case EW_ERR_OVERFLOW:
    case EW_ERR_CYCLE:
    case EW_ERR_UNRESOLVED:
    case EW_ERR_DUPLICATE:
    case EW_ERR_NOT_FOUND:
    case EW_ERR_READONLY:
    case EW_ERR_STATE:
    case EW_ERR_LIMIT:
        return 1;

    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Recovery: attempt parse with error tolerance                        */
/* ------------------------------------------------------------------ */

ew_error_t ew_recover_parse(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    if (ctx->in_recovery)
        return EW_ERR_STATE;

    ctx->in_recovery = 1;
    ctx->recovery_depth++;
    ew_error_t first_err = EW_OK;
    int phase = 0;

    /* Phase 0: Header (must succeed) */
    ew_error_t err = ew_parse_header(ctx);
    if (err != EW_OK) {
        if (!ew_is_recoverable(err)) {
            ctx->in_recovery = 0;
            return err;
        }
        first_err = err;
        ctx->recovery_errors[ctx->recovery_depth - 1] = err;
        ctx->in_recovery = 0;
        return err;  /* Can't continue without a valid header */
    }
    phase++;

    /* Phase 1: Sections (best effort) */
    err = ew_parse_sections(ctx);
    if (err != EW_OK) {
        if (first_err == EW_OK)
            first_err = err;
        ctx->recovery_errors[ctx->recovery_depth - 1] = err;
        /* Continue without sections if possible */
    }
    phase++;

    /* Phase 2: Segments (best effort) */
    err = ew_parse_segments(ctx);
    if (err != EW_OK) {
        if (first_err == EW_OK)
            first_err = err;
    }
    phase++;

    /* Phase 3: String tables (depends on sections) */
    if (ctx->sections && ctx->section_count > 0) {
        err = ew_resolve_strtabs(ctx);
        if (err != EW_OK && first_err == EW_OK)
            first_err = err;
    }
    phase++;

    /* Phase 4: Symbol tables (depends on strtabs) */
    if (ctx->sections && ctx->section_count > 0) {
        err = ew_parse_symtabs(ctx);
        if (err != EW_OK && first_err == EW_OK)
            first_err = err;
    }
    phase++;

    /* Phase 5: Dynamic section (depends on strtabs) */
    if (ctx->sections && ctx->section_count > 0) {
        err = ew_parse_dynamics(ctx);
        if (err != EW_OK && first_err == EW_OK)
            first_err = err;
    }
    phase++;

    /* Phase 6: Relocations (depends on symtabs) */
    if (ctx->symtab || ctx->dynsym) {
        err = ew_parse_relocs(ctx);
        if (err != EW_OK && first_err == EW_OK)
            first_err = err;
    }
    phase++;

    /* Phase 7: Notes (independent) */
    err = ew_parse_notes(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;
    phase++;

    ctx->parsed = 1;
    ctx->in_recovery = 0;

    (void)phase;
    return first_err;
}

/* ------------------------------------------------------------------ */
/* Recovery: attempt resolution with error tolerance                   */
/* ------------------------------------------------------------------ */

ew_error_t ew_recover_resolve(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (!ctx->parsed)
        return EW_ERR_STATE;

    ew_error_t first_err = EW_OK;

    /* Build hash tables (best effort) */
    ew_error_t err = ew_build_sysv_hash(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;

    err = ew_build_gnu_hash(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;

    /* Resolve versions (best effort) */
    err = ew_resolve_versions(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;

    /* Build dependency graph (best effort) */
    if (ctx->dynamics && ctx->dynamic_count > 0) {
        err = ew_build_dep_graph(ctx);
        if (err != EW_OK && first_err == EW_OK)
            first_err = err;
    }

    /* Resolve symbols (best effort) */
    err = ew_resolve_symbols(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;

    /* Apply relocations (best effort) */
    err = ew_apply_relocations(ctx);
    if (err != EW_OK && first_err == EW_OK)
        first_err = err;

    return first_err;
}

/* ------------------------------------------------------------------ */
/* Convenience: full parse (no resolution)                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_full(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    ew_error_t err;

    err = ew_parse_header(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_sections(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_segments(ctx);
    if (err != EW_OK) return err;

    err = ew_resolve_strtabs(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_symtabs(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_dynamics(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_relocs(ctx);
    if (err != EW_OK) return err;

    err = ew_parse_notes(ctx);
    if (err != EW_OK) return err;

    ctx->parsed = 1;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Convenience: full analysis pipeline                                 */
/* ------------------------------------------------------------------ */

ew_error_t ew_full_analysis(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    ew_error_t err;

    /* Parse */
    err = ew_parse_full(ctx);
    if (err != EW_OK) return err;

    /* Build hash tables */
    err = ew_build_sysv_hash(ctx);
    if (err != EW_OK) return err;

    err = ew_build_gnu_hash(ctx);
    if (err != EW_OK) return err;

    /* Resolve versions */
    err = ew_resolve_versions(ctx);
    if (err != EW_OK) return err;

    /* Build dependency graph */
    err = ew_build_dep_graph(ctx);
    if (err != EW_OK) return err;

    /* Resolve symbols */
    err = ew_resolve_symbols(ctx);
    if (err != EW_OK) return err;

    /* Apply relocations */
    err = ew_apply_relocations(ctx);
    if (err != EW_OK) return err;

    /* Validate */
    err = ew_validate(ctx);
    if (err != EW_OK) return err;

    /* Normalize */
    err = ew_normalize(ctx);
    if (err != EW_OK) return err;

    return EW_OK;
}
