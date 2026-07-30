/*
 * ew_resolve.c — Cross-reference symbol resolution.
 *
 * Resolves undefined symbols by searching dynamic symbol tables
 * using hash lookups, applies version constraints, and computes
 * final resolved addresses. Resolution order follows the dependency
 * graph's topological ordering when available.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Single-symbol resolution strategy                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    EW_RES_NONE = 0,
    EW_RES_HASH_SYSV,
    EW_RES_HASH_GNU,
    EW_RES_LINEAR,
    EW_RES_CACHE
} ew_resolve_method_t;

/* ------------------------------------------------------------------ */
/* Resolution via SysV hash table                                      */
/* ------------------------------------------------------------------ */

static ew_symbol_t *resolve_via_sysv(ew_context_t *ctx, const char *name)
{
    if (!ctx->sysv_hash.valid)
        return NULL;
    return ew_hash_lookup(ctx, name);
}

/* ------------------------------------------------------------------ */
/* Resolution via GNU hash table                                       */
/* ------------------------------------------------------------------ */

static ew_symbol_t *resolve_via_gnu(ew_context_t *ctx, const char *name)
{
    if (!ctx->gnu_hash.valid)
        return NULL;
    return ew_gnu_hash_lookup(ctx, name);
}

/* ------------------------------------------------------------------ */
/* Resolution via linear scan of dynamic symbol table                  */
/* ------------------------------------------------------------------ */

static ew_symbol_t *resolve_via_linear(ew_context_t *ctx, const char *name)
{
    if (!ctx->dynsym || ctx->dynsym_count == 0)
        return NULL;

    for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
        ew_symbol_t *sym = &ctx->dynsym[i];
        if (!sym->name)
            continue;
        if (strcmp(sym->name, name) != 0)
            continue;

        /* Skip undefined symbols */
        if (sym->st_shndx == EW_SHN_UNDEF)
            continue;

        /* Skip local symbols */
        if (EW_ELF_ST_BIND(sym->st_info) == EW_STB_LOCAL)
            continue;

        return sym;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Resolution via cache                                                */
/* ------------------------------------------------------------------ */

static ew_symbol_t *resolve_via_cache(ew_context_t *ctx, const char *name)
{
    if (!ctx->resolve_cache)
        return NULL;

    uint64_t key = ew_elf_hash(name);
    void *cached = ew_cache_get(ctx->resolve_cache, key);
    if (cached)
        return (ew_symbol_t *)cached;

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Version compatibility check                                         */
/* ------------------------------------------------------------------ */

static int version_compatible(ew_context_t *ctx, ew_symbol_t *sym,
                                int required_ver)
{
    if (required_ver < 0 || !ctx->versym)
        return 1;  /* no version constraint */

    if (sym->version_index < 0)
        return 1;  /* symbol has no version */

    if (required_ver == 0 || required_ver == 1)
        return 1;  /* local/global base versions always match */

    return sym->version_index == required_ver;
}

/* ------------------------------------------------------------------ */
/* Resolve a single symbol                                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_resolve_symbol(ew_context_t *ctx, ew_symbol_t *sym)
{
    if (!ctx || !sym)
        return EW_ERR_INVALID;

    if (sym->resolved)
        return EW_OK;

    /* Symbols with definitions don't need resolution */
    if (sym->st_shndx != EW_SHN_UNDEF) {
        sym->resolved = 1;
        sym->resolved_addr = sym->st_value;
        sym->ownership_stage = 1;
        return EW_OK;
    }

    if (!sym->name || sym->name[0] == '\0') {
        sym->resolved = 1;
        sym->resolved_addr = 0;
        return EW_OK;
    }

    /* Try resolution methods in priority order */
    ew_symbol_t *found = NULL;
    ew_resolve_method_t method = EW_RES_NONE;

    /* 1. Check cache first */
    found = resolve_via_cache(ctx, sym->name);
    if (found) {
        method = EW_RES_CACHE;
    }

    /* 2. Try GNU hash (preferred) */
    if (!found) {
        found = resolve_via_gnu(ctx, sym->name);
        if (found)
            method = EW_RES_HASH_GNU;
    }

    /* 3. Try SysV hash */
    if (!found) {
        found = resolve_via_sysv(ctx, sym->name);
        if (found)
            method = EW_RES_HASH_SYSV;
    }

    /* 4. Fall back to linear scan */
    if (!found) {
        found = resolve_via_linear(ctx, sym->name);
        if (found)
            method = EW_RES_LINEAR;
    }

    if (!found) {
        /* Weak symbols resolve to zero without error */
        if (EW_ELF_ST_BIND(sym->st_info) == EW_STB_WEAK) {
            sym->resolved = 1;
            sym->resolved_addr = 0;
            sym->ownership_stage = 1;
            return EW_OK;
        }
        return EW_ERR_UNRESOLVED;
    }

    /* Check version compatibility */
    if (!version_compatible(ctx, found, sym->version_index)) {
        /* Version mismatch; try linear scan for compatible version */
        ew_symbol_t *alt = NULL;
        for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
            ew_symbol_t *candidate = &ctx->dynsym[i];
            if (!candidate->name || strcmp(candidate->name, sym->name) != 0)
                continue;
            if (candidate->st_shndx == EW_SHN_UNDEF)
                continue;
            if (version_compatible(ctx, candidate, sym->version_index)) {
                alt = candidate;
                break;
            }
        }
        if (alt)
            found = alt;
    }

    /* Record resolution */
    sym->resolved = 1;
    sym->resolved_addr = found->st_value;
    sym->ownership_stage = 1;
    sym->generation = ctx->generation;

    /* Cache the result */
    if (ctx->resolve_cache && method != EW_RES_CACHE) {
        uint64_t key = ew_elf_hash(sym->name);
        ew_cache_put(ctx->resolve_cache, key, found);
    }

    (void)method;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Resolve all undefined symbols                                       */
/* ------------------------------------------------------------------ */

ew_error_t ew_resolve_symbols(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Create resolution cache if not present */
    if (!ctx->resolve_cache) {
        ctx->resolve_cache = ew_cache_create(1024);
        if (!ctx->resolve_cache)
            return EW_ERR_NOMEM;
    }

    /* Resolve static symbol table */
    if (ctx->symtab) {
        for (uint32_t i = 0; i < ctx->symtab_count; i++) {
            ew_symbol_t *sym = &ctx->symtab[i];
            if (sym->st_shndx == EW_SHN_UNDEF && sym->name &&
                sym->name[0] != '\0') {
                ew_resolve_symbol(ctx, sym);
                /* Don't fail on unresolved symbols in static table */
            }
        }
    }

    /* Resolve dynamic symbol table */
    if (ctx->dynsym) {
        uint32_t unresolved = 0;
        for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
            ew_symbol_t *sym = &ctx->dynsym[i];
            if (sym->st_shndx == EW_SHN_UNDEF && sym->name &&
                sym->name[0] != '\0') {
                ew_error_t err = ew_resolve_symbol(ctx, sym);
                if (err == EW_ERR_UNRESOLVED)
                    unresolved++;
            }
        }

        if (unresolved > 0) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "%u unresolved dynamic symbols", unresolved);
            /* Not fatal—unresolved symbols are common in shared libs */
        }
    }

    ctx->resolved = 1;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Batch resolution                                                    */
/* ------------------------------------------------------------------ */

ew_error_t ew_batch_resolve(ew_context_t *ctx, const char **names,
                             uint32_t count, ew_symbol_t **results)
{
    if (!ctx || !names || !results)
        return EW_ERR_INVALID;

    if (!ctx->resolve_cache) {
        ctx->resolve_cache = ew_cache_create(1024);
        if (!ctx->resolve_cache)
            return EW_ERR_NOMEM;
    }

    uint32_t found_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        results[i] = NULL;

        if (!names[i])
            continue;

        /* Try cache first */
        ew_symbol_t *sym = resolve_via_cache(ctx, names[i]);

        if (!sym)
            sym = resolve_via_gnu(ctx, names[i]);
        if (!sym)
            sym = resolve_via_sysv(ctx, names[i]);
        if (!sym)
            sym = resolve_via_linear(ctx, names[i]);

        if (sym) {
            results[i] = sym;
            found_count++;

            /* Update cache */
            uint64_t key = ew_elf_hash(names[i]);
            ew_cache_put(ctx->resolve_cache, key, sym);
        }
    }

    if (found_count < count) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "batch resolve: %u of %u found", found_count, count);
    }

    return EW_OK;
}
