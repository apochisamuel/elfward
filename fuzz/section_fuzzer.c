/*
 * section_fuzzer.c — Section and segment parsing fuzzer.
 *
 * Focuses on the section header table parsing, segment parsing,
 * string table resolution, symbol table parsing, relocation parsing,
 * and dynamic section parsing. Exercises the phased parsing pipeline
 * individually to maximize coverage of section-processing code paths.
 */

#include "elfward.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

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

    /* Parse header first */
    err = ew_parse_header(ctx);
    if (err != EW_OK) {
        ew_context_destroy(ctx);
        return 0;
    }

    /* Parse sections individually */
    err = ew_parse_sections(ctx);
    if (err != EW_OK) {
        /* Attempt segments even if sections fail */
        ew_parse_segments(ctx);
        ew_context_destroy(ctx);
        return 0;
    }

    /* Parse segments */
    ew_parse_segments(ctx);

    /* Resolve string tables */
    ew_resolve_strtabs(ctx);

    /* Parse symbol tables */
    ew_parse_symtabs(ctx);

    /* Parse dynamic section */
    ew_parse_dynamics(ctx);

    /* Parse relocations */
    ew_parse_relocs(ctx);

    /* Parse notes */
    ew_parse_notes(ctx);

    /* Validate sections */
    ew_validate_sections(ctx);
    ew_validate_symbols(ctx);
    ew_validate_relocs(ctx);
    ew_validate_dynamics(ctx);

    /* Canonicalize sections */
    ew_canonicalize_sections(ctx);
    ew_normalize_symbols(ctx);

    /* Generate section-specific reports */
    ew_report_t *report;

    report = ew_report_create(ctx, EW_REPORT_SECTIONS);
    if (report) {
        (void)ew_report_get_text(report);
        ew_report_destroy(report);
    }

    report = ew_report_create(ctx, EW_REPORT_SEGMENTS);
    if (report) {
        (void)ew_report_get_text(report);
        ew_report_destroy(report);
    }

    report = ew_report_create(ctx, EW_REPORT_SYMBOLS);
    if (report) {
        (void)ew_report_get_text(report);
        ew_report_destroy(report);
    }

    report = ew_report_create(ctx, EW_REPORT_DYNAMIC);
    if (report) {
        (void)ew_report_get_text(report);
        ew_report_destroy(report);
    }

    /* Exercise section query functions */
    for (uint32_t i = 0; i < ctx->section_count && i < 10; i++) {
        ew_query_result_t *result = ew_query_symbols_by_section(ctx, i);
        if (result)
            ew_query_result_destroy(result);
    }

    /* Exercise plan-based execution */
    ew_plan_t *plan = ew_plan_create();
    if (plan) {
        ew_plan_add_step(plan, EW_STEP_BUILD_HASH);
        ew_plan_add_step(plan, EW_STEP_RESOLVE_VERSIONS);
        ew_plan_add_step(plan, EW_STEP_BUILD_GRAPH);
        ew_plan_execute(ctx, plan);
        ew_plan_destroy(plan);
    }

    ew_context_destroy(ctx);
    return 0;
}
