/*
 * ew_cache.c — Resolution cache with generation tracking.
 *
 * Provides a hash-based key-value cache for symbol resolution
 * results. Supports generation-based invalidation, freezing for
 * read-only access, and pinning of critical entries.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Hash function for cache keys                                        */
/* ------------------------------------------------------------------ */

static uint32_t cache_hash(uint64_t key, uint32_t bucket_count)
{
    /* Fibonacci hashing for good distribution */
    uint64_t h = key * 11400714819323198485ULL;
    return (uint32_t)(h >> 32) % bucket_count;
}

/* ------------------------------------------------------------------ */
/* Cache creation                                                      */
/* ------------------------------------------------------------------ */

ew_cache_t *ew_cache_create(uint32_t bucket_count)
{
    if (bucket_count == 0)
        bucket_count = 256;

    /* Round up to power of two for better distribution */
    uint32_t actual = 1;
    while (actual < bucket_count && actual < EW_MAX_CACHE_ENTRIES)
        actual *= 2;

    ew_cache_t *cache = calloc(1, sizeof(ew_cache_t));
    if (!cache)
        return NULL;

    cache->buckets = calloc(actual, sizeof(ew_cache_entry_t *));
    if (!cache->buckets) {
        free(cache);
        return NULL;
    }

    cache->bucket_count = actual;
    cache->entry_count = 0;
    cache->generation = 1;
    cache->frozen = 0;

    return cache;
}

/* ------------------------------------------------------------------ */
/* Cache insertion                                                     */
/* ------------------------------------------------------------------ */

ew_error_t ew_cache_put(ew_cache_t *cache, uint64_t key, void *value)
{
    if (!cache)
        return EW_ERR_INVALID;

    if (cache->frozen)
        return EW_ERR_READONLY;

    if (cache->entry_count >= EW_MAX_CACHE_ENTRIES)
        return EW_ERR_LIMIT;

    uint32_t bucket = cache_hash(key, cache->bucket_count);

    /* Check for existing entry with same key */
    ew_cache_entry_t *entry = cache->buckets[bucket];
    while (entry) {
        if (entry->key == key) {
            /* Update existing entry */
            entry->value = value;
            entry->generation = cache->generation;
            entry->valid = 1;
            return EW_OK;
        }
        entry = entry->next;
    }

    /* Create new entry */
    ew_cache_entry_t *new_entry = calloc(1, sizeof(ew_cache_entry_t));
    if (!new_entry)
        return EW_ERR_NOMEM;

    new_entry->key = key;
    new_entry->value = value;
    new_entry->generation = cache->generation;
    new_entry->pinned = 0;
    new_entry->valid = 1;
    new_entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = new_entry;
    cache->entry_count++;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Cache lookup                                                        */
/* ------------------------------------------------------------------ */

void *ew_cache_get(ew_cache_t *cache, uint64_t key)
{
    if (!cache)
        return NULL;

    uint32_t bucket = cache_hash(key, cache->bucket_count);
    ew_cache_entry_t *entry = cache->buckets[bucket];

    while (entry) {
        if (entry->key == key && entry->valid)
            return entry->value;
        entry = entry->next;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Cache invalidation                                                  */
/* ------------------------------------------------------------------ */

ew_error_t ew_cache_invalidate(ew_cache_t *cache, uint64_t key)
{
    if (!cache)
        return EW_ERR_INVALID;

    if (cache->frozen)
        return EW_ERR_READONLY;

    uint32_t bucket = cache_hash(key, cache->bucket_count);
    ew_cache_entry_t *entry = cache->buckets[bucket];

    while (entry) {
        if (entry->key == key) {
            if (entry->pinned)
                return EW_ERR_READONLY;
            entry->valid = 0;
            return EW_OK;
        }
        entry = entry->next;
    }

    return EW_ERR_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/* Clear all entries                                                   */
/* ------------------------------------------------------------------ */

ew_error_t ew_cache_clear(ew_cache_t *cache)
{
    if (!cache)
        return EW_ERR_INVALID;

    if (cache->frozen)
        return EW_ERR_READONLY;

    for (uint32_t i = 0; i < cache->bucket_count; i++) {
        ew_cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            ew_cache_entry_t *next = entry->next;
            if (!entry->pinned) {
                free(entry);
            } else {
                entry->valid = 0;
                entry->next = NULL;
            }
            entry = next;
        }
        cache->buckets[i] = NULL;
    }

    cache->entry_count = 0;
    cache->generation++;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Freeze/unfreeze                                                     */
/* ------------------------------------------------------------------ */

void ew_cache_freeze(ew_cache_t *cache)
{
    if (cache)
        cache->frozen = 1;
}

/* ------------------------------------------------------------------ */
/* Cache destruction                                                   */
/* ------------------------------------------------------------------ */

void ew_cache_destroy(ew_cache_t *cache)
{
    if (!cache)
        return;

    for (uint32_t i = 0; i < cache->bucket_count; i++) {
        ew_cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            ew_cache_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(cache->buckets);
    free(cache);
}
