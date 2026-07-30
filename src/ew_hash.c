/*
 * ew_hash.c — SysV and GNU hash table construction and lookup.
 *
 * Parses on-disk hash tables from SHT_HASH and SHT_GNU_HASH sections,
 * and provides symbol lookup by name through either table format.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* SysV hash table construction                                        */
/* ------------------------------------------------------------------ */

ew_error_t ew_build_sysv_hash(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Find SHT_HASH section */
    ew_section_t *sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_HASH) {
            sec = &ctx->sections[i];
            break;
        }
    }

    if (!sec || !sec->data || sec->sh_size < 8) {
        memset(&ctx->sysv_hash, 0, sizeof(ctx->sysv_hash));
        return EW_OK;
    }

    ew_reader_t rd;
    ew_reader_init(&rd, sec->data, (size_t)sec->sh_size, ctx->is_big_endian);

    uint32_t nbucket, nchain;
    ew_error_t err;

    err = ew_read_u32(&rd, &nbucket);
    if (err != EW_OK) return err;

    err = ew_read_u32(&rd, &nchain);
    if (err != EW_OK) return err;

    if (nbucket == 0 || nbucket > EW_MAX_HASH_BUCKETS) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "invalid SysV hash bucket count: %u", nbucket);
        return EW_ERR_BAD_HASH;
    }

    /* Verify there's enough data for all buckets and chains */
    size_t needed = 8 + (size_t)nbucket * 4 + (size_t)nchain * 4;
    if (needed > sec->sh_size) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "SysV hash table truncated: need %zu, have %lu",
                 needed, (unsigned long)sec->sh_size);
        return EW_ERR_TRUNCATED;
    }

    ctx->sysv_hash.nbucket = nbucket;
    ctx->sysv_hash.nchain = nchain;

    ctx->sysv_hash.buckets = malloc(nbucket * sizeof(uint32_t));
    if (!ctx->sysv_hash.buckets)
        return EW_ERR_NOMEM;

    ctx->sysv_hash.chains = malloc(nchain * sizeof(uint32_t));
    if (!ctx->sysv_hash.chains) {
        free(ctx->sysv_hash.buckets);
        ctx->sysv_hash.buckets = NULL;
        return EW_ERR_NOMEM;
    }

    for (uint32_t i = 0; i < nbucket; i++) {
        err = ew_read_u32(&rd, &ctx->sysv_hash.buckets[i]);
        if (err != EW_OK) return err;
    }

    for (uint32_t i = 0; i < nchain; i++) {
        err = ew_read_u32(&rd, &ctx->sysv_hash.chains[i]);
        if (err != EW_OK) return err;
    }

    ctx->sysv_hash.valid = 1;

    /* Link symbols into their hash chain entries */
    if (ctx->dynsym && ctx->dynsym_count > 0) {
        for (uint32_t i = 0; i < ctx->dynsym_count && i < nchain; i++) {
            ctx->dynsym[i].hash_chain_next = ctx->sysv_hash.chains[i];
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* SysV hash lookup                                                    */
/* ------------------------------------------------------------------ */

ew_symbol_t *ew_hash_lookup(ew_context_t *ctx, const char *name)
{
    if (!ctx || !name || !ctx->sysv_hash.valid)
        return NULL;

    if (!ctx->dynsym || ctx->dynsym_count == 0)
        return NULL;

    uint32_t h = ew_elf_hash(name);
    uint32_t bucket = h % ctx->sysv_hash.nbucket;
    uint32_t idx = ctx->sysv_hash.buckets[bucket];

    uint32_t max_chain_len = ctx->sysv_hash.nchain;
    uint32_t steps = 0;

    while (idx != 0 && idx < ctx->dynsym_count && steps < max_chain_len) {
        ew_symbol_t *sym = &ctx->dynsym[idx];
        if (sym->name && strcmp(sym->name, name) == 0)
            return sym;

        /* Follow the chain. The idx is validated against dynsym_count
         * above, but chain array size may differ from dynsym count in
         * the case of stripped or partial hash tables. */
        idx = ctx->sysv_hash.chains[idx];
        steps++;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* GNU hash table construction                                         */
/* ------------------------------------------------------------------ */

ew_error_t ew_build_gnu_hash(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    /* Find SHT_GNU_HASH section */
    ew_section_t *sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_GNU_HASH) {
            sec = &ctx->sections[i];
            break;
        }
    }

    if (!sec || !sec->data || sec->sh_size < 16) {
        memset(&ctx->gnu_hash, 0, sizeof(ctx->gnu_hash));
        return EW_OK;
    }

    ew_reader_t rd;
    ew_reader_init(&rd, sec->data, (size_t)sec->sh_size, ctx->is_big_endian);

    uint32_t nbuckets, symoffset, bloom_size, bloom_shift;
    ew_error_t err;

    err = ew_read_u32(&rd, &nbuckets);
    if (err != EW_OK) return err;

    err = ew_read_u32(&rd, &symoffset);
    if (err != EW_OK) return err;

    err = ew_read_u32(&rd, &bloom_size);
    if (err != EW_OK) return err;

    err = ew_read_u32(&rd, &bloom_shift);
    if (err != EW_OK) return err;

    if (nbuckets == 0 || nbuckets > EW_MAX_GNU_BUCKETS) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "invalid GNU hash bucket count: %u", nbuckets);
        return EW_ERR_BAD_HASH;
    }

    if (bloom_size == 0 || (bloom_size & (bloom_size - 1)) != 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "GNU hash bloom_size not power of two: %u", bloom_size);
        return EW_ERR_BAD_HASH;
    }

    ctx->gnu_hash.nbuckets = nbuckets;
    ctx->gnu_hash.symoffset = symoffset;
    ctx->gnu_hash.bloom_size = bloom_size;
    ctx->gnu_hash.bloom_shift = bloom_shift;
    ctx->gnu_hash.is_64bit = ctx->is_64bit;

    /* Read bloom filter */
    size_t bloom_word_size = ctx->is_64bit ? 8 : 4;
    size_t bloom_bytes = (size_t)bloom_size * bloom_word_size;

    if (ew_reader_remaining(&rd) < bloom_bytes) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "GNU hash bloom filter truncated");
        return EW_ERR_TRUNCATED;
    }

    ctx->gnu_hash.bloom = malloc(bloom_size * sizeof(uint64_t));
    if (!ctx->gnu_hash.bloom)
        return EW_ERR_NOMEM;

    for (uint32_t i = 0; i < bloom_size; i++) {
        if (ctx->is_64bit) {
            err = ew_read_u64(&rd, &ctx->gnu_hash.bloom[i]);
        } else {
            uint32_t val32;
            err = ew_read_u32(&rd, &val32);
            ctx->gnu_hash.bloom[i] = val32;
        }
        if (err != EW_OK) {
            free(ctx->gnu_hash.bloom);
            ctx->gnu_hash.bloom = NULL;
            return err;
        }
    }

    /* Read bucket array */
    if (ew_reader_remaining(&rd) < (size_t)nbuckets * 4) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "GNU hash bucket array truncated");
        free(ctx->gnu_hash.bloom);
        ctx->gnu_hash.bloom = NULL;
        return EW_ERR_TRUNCATED;
    }

    ctx->gnu_hash.buckets = malloc(nbuckets * sizeof(uint32_t));
    if (!ctx->gnu_hash.buckets) {
        free(ctx->gnu_hash.bloom);
        ctx->gnu_hash.bloom = NULL;
        return EW_ERR_NOMEM;
    }

    for (uint32_t i = 0; i < nbuckets; i++) {
        err = ew_read_u32(&rd, &ctx->gnu_hash.buckets[i]);
        if (err != EW_OK) return err;
    }

    /* Read chain values (rest of section) */
    size_t chain_bytes = ew_reader_remaining(&rd);
    uint32_t chain_count = (uint32_t)(chain_bytes / 4);

    /* The number of chains should equal dynsym_count - symoffset per
     * the GNU hash specification. Use the spec-derived count for the
     * chain_count field so lookups can use the full symbol range. */
    uint32_t expected_chains = 0;
    if (ctx->dynsym_count > symoffset)
        expected_chains = ctx->dynsym_count - symoffset;

    if (chain_count > 0) {
        ctx->gnu_hash.chains = malloc(chain_count * sizeof(uint32_t));
        if (!ctx->gnu_hash.chains) {
            free(ctx->gnu_hash.bloom);
            free(ctx->gnu_hash.buckets);
            ctx->gnu_hash.bloom = NULL;
            ctx->gnu_hash.buckets = NULL;
            return EW_ERR_NOMEM;
        }

        for (uint32_t i = 0; i < chain_count; i++) {
            err = ew_read_u32(&rd, &ctx->gnu_hash.chains[i]);
            if (err != EW_OK) return err;
        }
        /* Use spec-derived count if larger, so lookups cover all
         * dynamic symbols even with truncated section data. */
        ctx->gnu_hash.chain_count = expected_chains > chain_count ?
                                     expected_chains : chain_count;
    }

    ctx->gnu_hash.valid = 1;

    /* Precompute GNU hash values for dynamic symbols */
    if (ctx->dynsym) {
        for (uint32_t i = 0; i < ctx->dynsym_count; i++) {
            if (ctx->dynsym[i].name)
                ctx->dynsym[i].gnu_hash_val = ew_gnu_hash(ctx->dynsym[i].name);
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* GNU hash bloom filter check                                         */
/* ------------------------------------------------------------------ */

static int gnu_bloom_check(ew_gnu_hash_t *gh, uint32_t hash)
{
    size_t word_bits = gh->is_64bit ? 64 : 32;
    uint32_t mask_idx = (hash / (uint32_t)word_bits) % gh->bloom_size;
    uint64_t bloom_word = gh->bloom[mask_idx];

    uint64_t bit1 = (uint64_t)1 << (hash % word_bits);
    uint64_t bit2 = (uint64_t)1 << ((hash >> gh->bloom_shift) % word_bits);

    return (bloom_word & bit1) && (bloom_word & bit2);
}

/* ------------------------------------------------------------------ */
/* GNU hash lookup                                                     */
/* ------------------------------------------------------------------ */

ew_symbol_t *ew_gnu_hash_lookup(ew_context_t *ctx, const char *name)
{
    if (!ctx || !name || !ctx->gnu_hash.valid)
        return NULL;

    if (!ctx->dynsym || ctx->dynsym_count == 0)
        return NULL;

    ew_gnu_hash_t *gh = &ctx->gnu_hash;
    uint32_t hash = ew_gnu_hash(name);

    /* Bloom filter check */
    if (!gnu_bloom_check(gh, hash))
        return NULL;

    /* Find the bucket */
    uint32_t bucket = hash % gh->nbuckets;
    uint32_t sym_idx = gh->buckets[bucket];

    if (sym_idx == 0)
        return NULL;

    if (sym_idx < gh->symoffset)
        return NULL;

    /* Walk the chain */
    uint32_t chain_idx = sym_idx - gh->symoffset;
    uint32_t max_steps = gh->chain_count;
    uint32_t steps = 0;

    while (chain_idx < gh->chain_count && steps < max_steps) {
        uint32_t chain_val = gh->chains[chain_idx];

        /* Check if hash matches (bottom bit is chain-end flag) */
        if ((chain_val | 1) == (hash | 1)) {
            if (sym_idx < ctx->dynsym_count) {
                ew_symbol_t *sym = &ctx->dynsym[sym_idx];
                if (sym->name && strcmp(sym->name, name) == 0)
                    return sym;
            }
        }

        /* Check chain-end bit */
        if (chain_val & 1)
            break;

        chain_idx++;
        sym_idx++;
        steps++;
    }

    return NULL;
}
