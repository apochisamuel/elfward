/*
 * lifecycle_fuzzer.c — Full parse lifecycle fuzzer.
 *
 * Exercises the complete ELF analysis pipeline: header, sections,
 * segments, symbol tables, dynamic section, relocations, notes,
 * hash tables, version info, dependency graph, resolution, validation,
 * normalization, and reporting.
 */

#include "elfward.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 16 || size > 64 * 1024 * 1024)
        return 0;

    ew_context_t *ctx = ew_context_create();
    if (!ctx)
        return 0;

    ew_error_t err = ew_context_load(ctx, data, size);
    if (err != EW_OK) {
        ew_context_destroy(ctx);
        return 0;
    }

    /* Full analysis pipeline */
    err = ew_full_analysis(ctx);
    if (err != EW_OK) {
        /* Try recovery path on failure */
        ew_context_t *ctx2 = ew_context_create();
        if (ctx2) {
            ew_context_load(ctx2, data, size);
            ew_recover_parse(ctx2);
            ew_recover_resolve(ctx2);

            /* Generate report even on partial parse */
            ew_report_t *report = ew_report_create(ctx2, EW_REPORT_SUMMARY);
            if (report) {
                (void)ew_report_get_text(report);
                ew_report_destroy(report);
            }

            ew_context_destroy(ctx2);
        }
        ew_context_destroy(ctx);
        return 0;
    }

    /* Exercise query API */
    ew_query_result_t *result;

    result = ew_query_symbols_by_name(ctx, "main");
    if (result) {
        ew_query_sort_by_addr(result);
        ew_query_result_destroy(result);
    }

    result = ew_query_undefined_symbols(ctx);
    if (result) {
        ew_query_sort_by_name(result);
        ew_query_result_destroy(result);
    }

    result = ew_query_exported_symbols(ctx);
    if (result)
        ew_query_result_destroy(result);

    result = ew_query_symbols_by_type(ctx, EW_STT_FUNC);
    if (result)
        ew_query_result_destroy(result);

    result = ew_query_symbols_by_binding(ctx, EW_STB_GLOBAL);
    if (result)
        ew_query_result_destroy(result);

    /* Exercise snapshot API */
    ew_snapshot_t *snap = ew_snapshot_create(ctx);
    if (snap) {
        ew_snapshot_refresh(snap);
        ew_snapshot_detach(snap);
        ew_snapshot_destroy(snap);
    }

    /* Generate full report */
    ew_report_t *report = ew_report_create(ctx, EW_REPORT_FULL);
    if (report) {
        (void)ew_report_get_text(report);
        ew_report_destroy(report);
    }

    /* Exercise registry with multiple entries from DT_NEEDED */
    ew_registry_t *reg = ew_registry_create(4);
    if (reg) {
        /* Register the main binary */
        ew_registry_add(reg, "main.elf", 0x400000, ctx);

        /* Register DT_NEEDED dependencies from dynamic section */
        uint32_t needed_count = 0;
        const char *needed_names[8];
        for (uint32_t i = 0; i < ctx->dynamic_count && needed_count < 8; i++) {
            if (ctx->dynamics[i].d_tag == EW_DT_NEEDED &&
                ctx->dynamics[i].string_val) {
                needed_names[needed_count] = ctx->dynamics[i].string_val;
                ew_registry_add(reg, needed_names[needed_count],
                                0x700000 + needed_count * 0x10000, ctx);
                needed_count++;
            }
            if (ctx->dynamics[i].d_tag == EW_DT_NULL)
                break;
        }

        /* Remove middle entries, then look up remaining ones */
        for (uint32_t i = 1; i < needed_count; i += 2) {
            ew_registry_remove(reg, needed_names[i]);
        }
        for (uint32_t i = 0; i < needed_count; i += 2) {
            ew_registry_entry_t *found = ew_registry_find(reg, needed_names[i]);
            (void)found;
        }

        ew_registry_remove(reg, "main.elf");
        ew_registry_destroy(reg);
    }

    ew_context_destroy(ctx);
    return 0;
}
