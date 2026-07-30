/*
 * ew_registry.c — Global registry for multi-binary analysis.
 *
 * Maintains a registry of loaded ELF contexts for cross-binary
 * symbol resolution. Each registered context is identified by
 * its library name and base address.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Registry hash function                                              */
/* ------------------------------------------------------------------ */

static uint32_t registry_hash(const char *name, uint32_t bucket_count)
{
    uint32_t h = ew_elf_hash(name);
    return h % bucket_count;
}

/* ------------------------------------------------------------------ */
/* Registry creation                                                   */
/* ------------------------------------------------------------------ */

ew_registry_t *ew_registry_create(uint32_t bucket_count)
{
    if (bucket_count == 0)
        bucket_count = 64;

    ew_registry_t *reg = calloc(1, sizeof(ew_registry_t));
    if (!reg)
        return NULL;

    reg->buckets = calloc(bucket_count, sizeof(ew_registry_entry_t *));
    if (!reg->buckets) {
        free(reg);
        return NULL;
    }

    reg->bucket_count = bucket_count;
    reg->generation = 1;
    return reg;
}

/* ------------------------------------------------------------------ */
/* Registry insertion                                                  */
/* ------------------------------------------------------------------ */

ew_error_t ew_registry_add(ew_registry_t *reg, const char *name,
                            uint64_t base_addr, ew_context_t *ctx)
{
    if (!reg || !name || !ctx)
        return EW_ERR_INVALID;

    /* Check for duplicate */
    ew_registry_entry_t *existing = ew_registry_find(reg, name);
    if (existing && existing->active)
        return EW_ERR_DUPLICATE;

    uint32_t bucket = registry_hash(name, reg->bucket_count);

    ew_registry_entry_t *entry = calloc(1, sizeof(ew_registry_entry_t));
    if (!entry)
        return EW_ERR_NOMEM;

    entry->name = name;
    entry->base_addr = base_addr;
    entry->ctx = ctx;
    entry->ref_count = 1;
    entry->active = 1;
    entry->generation = reg->generation;

    entry->next = reg->buckets[bucket];
    reg->buckets[bucket] = entry;
    reg->entry_count++;

    /* Link context to registry */
    ctx->registry = reg;
    ctx->registry_entry = entry;
    ctx->registered = 1;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Registry lookup                                                     */
/* ------------------------------------------------------------------ */

ew_registry_entry_t *ew_registry_find(ew_registry_t *reg, const char *name)
{
    if (!reg || !name)
        return NULL;

    uint32_t bucket = registry_hash(name, reg->bucket_count);
    ew_registry_entry_t *entry = reg->buckets[bucket];

    while (entry) {
        if (entry->active && entry->name &&
            strcmp(entry->name, name) == 0)
            return entry;
        entry = entry->next;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Registry removal                                                    */
/* ------------------------------------------------------------------ */

ew_error_t ew_registry_remove(ew_registry_t *reg, const char *name)
{
    if (!reg || !name)
        return EW_ERR_INVALID;

    uint32_t bucket = registry_hash(name, reg->bucket_count);
    ew_registry_entry_t *entry = reg->buckets[bucket];
    ew_registry_entry_t *prev = NULL;

    while (entry) {
        if (entry->name && strcmp(entry->name, name) == 0) {
            /* Unlink from context */
            if (entry->ctx) {
                entry->ctx->registry = NULL;
                entry->ctx->registry_entry = NULL;
                entry->ctx->registered = 0;
            }

            entry->active = 0;
            entry->ref_count--;

            if (entry->ref_count == 0) {
                /* Remove from bucket chain by marking inactive and
                 * freeing. The chain head is updated but interior
                 * entries rely on the active flag check in find(). */
                if (!prev)
                    reg->buckets[bucket] = entry->next;
                free(entry);
                reg->entry_count--;
            }

            return EW_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    return EW_ERR_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/* Registry destruction                                                */
/* ------------------------------------------------------------------ */

void ew_registry_destroy(ew_registry_t *reg)
{
    if (!reg)
        return;

    for (uint32_t i = 0; i < reg->bucket_count; i++) {
        ew_registry_entry_t *entry = reg->buckets[i];
        while (entry) {
            ew_registry_entry_t *next = entry->next;
            if (entry->ctx) {
                entry->ctx->registry = NULL;
                entry->ctx->registry_entry = NULL;
                entry->ctx->registered = 0;
            }
            free(entry);
            entry = next;
        }
    }

    free(reg->buckets);
    free(reg);
}
