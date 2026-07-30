/*
 * ew_query.c — Snapshot creation and symbol query API.
 *
 * Provides query functions that search parsed symbol tables by name,
 * type, section, and binding. Snapshots capture a point-in-time view
 * of the context for stable iteration during concurrent modifications.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Snapshot creation                                                   */
/* ------------------------------------------------------------------ */

ew_snapshot_t *ew_snapshot_create(ew_context_t *ctx)
{
    if (!ctx)
        return NULL;

    ew_snapshot_t *snap = calloc(1, sizeof(ew_snapshot_t));
    if (!snap)
        return NULL;

    snap->generation = ctx->generation;
    snap->detached = 0;
    snap->owner = ctx;

    /* Copy symbol tables */
    if (ctx->symtab && ctx->symtab_count > 0) {
        snap->symbols = malloc(ctx->symtab_count * sizeof(ew_symbol_t));
        if (!snap->symbols) {
            free(snap);
            return NULL;
        }
        memcpy(snap->symbols, ctx->symtab,
               ctx->symtab_count * sizeof(ew_symbol_t));
        snap->symbol_count = ctx->symtab_count;
    }

    /* Copy sections metadata */
    if (ctx->sections && ctx->section_count > 0) {
        snap->sections = malloc(ctx->section_count * sizeof(ew_section_t));
        if (!snap->sections) {
            free(snap->symbols);
            free(snap);
            return NULL;
        }
        memcpy(snap->sections, ctx->sections,
               ctx->section_count * sizeof(ew_section_t));
        snap->section_count = ctx->section_count;
    }

    /* Copy relocations */
    if (ctx->relocs && ctx->reloc_count > 0) {
        snap->relocs = malloc(ctx->reloc_count * sizeof(ew_relocation_t));
        if (!snap->relocs) {
            free(snap->sections);
            free(snap->symbols);
            free(snap);
            return NULL;
        }
        memcpy(snap->relocs, ctx->relocs,
               ctx->reloc_count * sizeof(ew_relocation_t));
        snap->reloc_count = ctx->reloc_count;
    }

    /* Register snapshot with context */
    if (ctx->snapshot_count >= ctx->snapshot_capacity) {
        uint32_t new_cap = ctx->snapshot_capacity == 0 ?
                           4 : ctx->snapshot_capacity * 2;
        ew_snapshot_t **tmp = realloc(ctx->snapshots,
                                      new_cap * sizeof(ew_snapshot_t *));
        if (!tmp) {
            free(snap->relocs);
            free(snap->sections);
            free(snap->symbols);
            free(snap);
            return NULL;
        }
        ctx->snapshots = tmp;
        ctx->snapshot_capacity = new_cap;
    }
    ctx->snapshots[ctx->snapshot_count++] = snap;

    return snap;
}

/* ------------------------------------------------------------------ */
/* Snapshot refresh                                                    */
/* ------------------------------------------------------------------ */

ew_error_t ew_snapshot_refresh(ew_snapshot_t *snap)
{
    if (!snap || !snap->owner || snap->detached)
        return EW_ERR_STATE;

    ew_context_t *ctx = snap->owner;

    /* Re-copy symbol data */
    if (ctx->symtab && ctx->symtab_count > 0) {
        ew_symbol_t *new_syms = realloc(snap->symbols,
                                         ctx->symtab_count *
                                         sizeof(ew_symbol_t));
        if (!new_syms)
            return EW_ERR_NOMEM;
        memcpy(new_syms, ctx->symtab,
               ctx->symtab_count * sizeof(ew_symbol_t));
        snap->symbols = new_syms;
        snap->symbol_count = ctx->symtab_count;
    }

    snap->generation = ctx->generation;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Snapshot detachment                                                 */
/* ------------------------------------------------------------------ */

void ew_snapshot_detach(ew_snapshot_t *snap)
{
    if (!snap)
        return;
    snap->detached = 1;
    snap->owner = NULL;
}

/* ------------------------------------------------------------------ */
/* Snapshot destruction                                                */
/* ------------------------------------------------------------------ */

void ew_snapshot_destroy(ew_snapshot_t *snap)
{
    if (!snap)
        return;

    /* Remove from owner's snapshot list */
    if (snap->owner && !snap->detached) {
        ew_context_t *ctx = snap->owner;
        for (uint32_t i = 0; i < ctx->snapshot_count; i++) {
            if (ctx->snapshots[i] == snap) {
                ctx->snapshots[i] = ctx->snapshots[ctx->snapshot_count - 1];
                ctx->snapshot_count--;
                break;
            }
        }
    }

    free(snap->symbols);
    free(snap->sections);
    free(snap->relocs);
    free(snap);
}

/* ------------------------------------------------------------------ */
/* Query result management                                             */
/* ------------------------------------------------------------------ */

static ew_query_result_t *query_result_create(void)
{
    ew_query_result_t *result = calloc(1, sizeof(ew_query_result_t));
    if (!result)
        return NULL;
    result->capacity = 32;
    result->symbols = malloc(result->capacity * sizeof(ew_symbol_t *));
    if (!result->symbols) {
        free(result);
        return NULL;
    }
    return result;
}

static ew_error_t query_result_add(ew_query_result_t *result,
                                    ew_symbol_t *sym)
{
    if (result->count >= result->capacity) {
        uint32_t new_cap = result->capacity * 2;
        ew_symbol_t **tmp = realloc(result->symbols,
                                     new_cap * sizeof(ew_symbol_t *));
        if (!tmp)
            return EW_ERR_NOMEM;
        result->symbols = tmp;
        result->capacity = new_cap;
    }
    result->symbols[result->count++] = sym;
    return EW_OK;
}

void ew_query_result_destroy(ew_query_result_t *result)
{
    if (!result)
        return;
    free(result->symbols);
    free(result);
}

/* ------------------------------------------------------------------ */
/* Query: symbols by name pattern (substring match)                    */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_symbols_by_name(ew_context_t *ctx,
                                             const char *pattern)
{
    if (!ctx || !pattern)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    /* Search both symbol tables */
    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (!sym->name)
                continue;
            if (strstr(sym->name, pattern) != NULL) {
                query_result_add(result, sym);
            }
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query: symbols by type                                              */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_symbols_by_type(ew_context_t *ctx,
                                             uint8_t sym_type)
{
    if (!ctx)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (EW_ELF_ST_TYPE(sym->st_info) == sym_type) {
                query_result_add(result, sym);
            }
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query: symbols by section                                           */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_symbols_by_section(ew_context_t *ctx,
                                                uint32_t section_idx)
{
    if (!ctx)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (sym->st_shndx == section_idx) {
                query_result_add(result, sym);
            }
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query: symbols by binding                                           */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_symbols_by_binding(ew_context_t *ctx,
                                                uint8_t binding)
{
    if (!ctx)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (EW_ELF_ST_BIND(sym->st_info) == binding) {
                query_result_add(result, sym);
            }
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query: undefined symbols                                            */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_undefined_symbols(ew_context_t *ctx)
{
    if (!ctx)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    ew_symbol_t *tables[] = { ctx->symtab, ctx->dynsym };
    uint32_t counts[] = { ctx->symtab_count, ctx->dynsym_count };

    for (int t = 0; t < 2; t++) {
        if (!tables[t])
            continue;
        for (uint32_t i = 0; i < counts[t]; i++) {
            ew_symbol_t *sym = &tables[t][i];
            if (sym->st_shndx == EW_SHN_UNDEF && sym->name &&
                sym->name[0] != '\0') {
                query_result_add(result, sym);
            }
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query: exported symbols                                             */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_exported_symbols(ew_context_t *ctx)
{
    if (!ctx)
        return NULL;

    ew_query_result_t *result = query_result_create();
    if (!result)
        return NULL;

    if (ctx->dynsym) {
        for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
            ew_symbol_t *sym = &ctx->dynsym[i];
            uint8_t bind = EW_ELF_ST_BIND(sym->st_info);
            uint8_t vis = EW_ELF_ST_VISIBILITY(sym->st_other);

            if (sym->st_shndx == EW_SHN_UNDEF)
                continue;
            if (bind == EW_STB_LOCAL)
                continue;
            if (vis == EW_STV_HIDDEN || vis == EW_STV_INTERNAL)
                continue;

            query_result_add(result, sym);
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Query result sorting                                                */
/* ------------------------------------------------------------------ */

static int cmp_sym_addr(const void *a, const void *b)
{
    const ew_symbol_t *sa = *(const ew_symbol_t *const *)a;
    const ew_symbol_t *sb = *(const ew_symbol_t *const *)b;
    if (sa->st_value < sb->st_value) return -1;
    if (sa->st_value > sb->st_value) return  1;
    return 0;
}

static int cmp_sym_name(const void *a, const void *b)
{
    const ew_symbol_t *sa = *(const ew_symbol_t *const *)a;
    const ew_symbol_t *sb = *(const ew_symbol_t *const *)b;
    if (!sa->name && !sb->name) return 0;
    if (!sa->name) return -1;
    if (!sb->name) return  1;
    return strcmp(sa->name, sb->name);
}

ew_error_t ew_query_sort_by_addr(ew_query_result_t *result)
{
    if (!result)
        return EW_ERR_INVALID;
    if (result->count > 1) {
        qsort(result->symbols, result->count,
              sizeof(ew_symbol_t *), cmp_sym_addr);
    }
    result->sorted = 1;
    return EW_OK;
}

ew_error_t ew_query_sort_by_name(ew_query_result_t *result)
{
    if (!result)
        return EW_ERR_INVALID;
    if (result->count > 1) {
        qsort(result->symbols, result->count,
              sizeof(ew_symbol_t *), cmp_sym_name);
    }
    result->sorted = 1;
    return EW_OK;
}
