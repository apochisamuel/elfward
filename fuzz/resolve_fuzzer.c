/*
 * resolve_fuzzer.c — Symbol resolution and hash table fuzzer.
 *
 * Focuses on the symbol resolution pipeline: SysV hash construction,
 * GNU hash construction, hash-based lookups, version resolution,
 * dependency graph construction, topological sorting, cycle detection,
 * cache operations, and batch resolution.
 */

#include "elfward.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 16 || size > 32 * 1024 * 1024)
        return 0;

    ew_context_t *ctx = ew_context_create();
    if (!ctx)
        return 0;

    ew_error_t err = ew_context_load(ctx, data, size);
    if (err != EW_OK) {
        ew_context_destroy(ctx);
        return 0;
    }

    /* Parse to get the data structures needed for resolution */
    err = ew_parse_full(ctx);
    if (err != EW_OK) {
        ew_context_destroy(ctx);
        return 0;
    }

    /* Build hash tables */
    ew_build_sysv_hash(ctx);
    ew_build_gnu_hash(ctx);

    /* Resolve version info */
    ew_resolve_versions(ctx);

    /* Build dependency graph */
    ew_build_dep_graph(ctx);

    /* Check for cycles in dependency graph */
    if (ctx->dep_graph) {
        ew_dep_graph_has_cycle(ctx->dep_graph);
        ew_validate_graph(ctx);
    }

    /* Resolve symbols */
    ew_resolve_symbols(ctx);

    /* Apply relocations */
    ew_apply_relocations(ctx);

    /* Exercise hash lookups with some test names */
    static const char *test_names[] = {
        "main", "printf", "_start", "__libc_start_main",
        "malloc", "free", "__gmon_start__", "_init",
        "_fini", "__cxa_finalize", "puts", "exit"
    };

    for (int i = 0; i < 12; i++) {
        ew_hash_lookup(ctx, test_names[i]);
        ew_gnu_hash_lookup(ctx, test_names[i]);
    }

    /* Exercise batch resolution */
    ew_symbol_t *results[12];
    ew_batch_resolve(ctx, test_names, 12, results);

    /* Exercise version lookup */
    for (uint32_t i = 0; i < ctx->dynsym_count && i < 20; i++) {
        ew_symbol_version_name(ctx, i);
    }

    /* Exercise cache operations */
    ew_cache_t *cache = ew_cache_create(64);
    if (cache) {
        for (int i = 0; i < 12; i++) {
            uint64_t key = ew_elf_hash(test_names[i]);
            ew_cache_put(cache, key, (void *)(uintptr_t)(i + 1));
        }

        for (int i = 0; i < 12; i++) {
            uint64_t key = ew_elf_hash(test_names[i]);
            ew_cache_get(cache, key);
        }

        ew_cache_freeze(cache);
        ew_cache_destroy(cache);
    }

    /* Validation pass */
    ew_validate(ctx);

    /* Normalization pass */
    ew_normalize(ctx);

    ew_context_destroy(ctx);
    return 0;
}
