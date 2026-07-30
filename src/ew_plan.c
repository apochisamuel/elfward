/*
 * ew_plan.c — Analysis plan construction and execution.
 *
 * A plan is an ordered sequence of parsing/resolution steps. Plans
 * allow callers to customize analysis depth and can share cached
 * results between multiple analysis runs on the same context.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Step type names for diagnostics                                     */
/* ------------------------------------------------------------------ */

__attribute__((unused))
static const char *step_type_name(ew_step_type_t type)
{
    switch (type) {
    case EW_STEP_PARSE_HEADER:    return "parse_header";
    case EW_STEP_PARSE_SECTIONS:  return "parse_sections";
    case EW_STEP_PARSE_SEGMENTS:  return "parse_segments";
    case EW_STEP_RESOLVE_STRTABS: return "resolve_strtabs";
    case EW_STEP_PARSE_SYMTABS:   return "parse_symtabs";
    case EW_STEP_PARSE_DYNAMICS:  return "parse_dynamics";
    case EW_STEP_PARSE_RELOCS:    return "parse_relocs";
    case EW_STEP_PARSE_NOTES:     return "parse_notes";
    case EW_STEP_BUILD_HASH:      return "build_hash";
    case EW_STEP_RESOLVE_VERSIONS: return "resolve_versions";
    case EW_STEP_BUILD_GRAPH:     return "build_graph";
    case EW_STEP_RESOLVE_SYMBOLS: return "resolve_symbols";
    case EW_STEP_APPLY_RELOCS:    return "apply_relocs";
    case EW_STEP_VALIDATE:        return "validate";
    case EW_STEP_NORMALIZE:       return "normalize";
    case EW_STEP_REGISTER:        return "register";
    case EW_STEP_CACHE:           return "cache";
    default:                      return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Plan lifecycle                                                      */
/* ------------------------------------------------------------------ */

ew_plan_t *ew_plan_create(void)
{
    ew_plan_t *plan = calloc(1, sizeof(ew_plan_t));
    if (!plan)
        return NULL;
    plan->generation = 1;
    return plan;
}

ew_error_t ew_plan_add_step(ew_plan_t *plan, ew_step_type_t type)
{
    if (!plan)
        return EW_ERR_INVALID;

    if (plan->finalized) {
        return EW_ERR_STATE;
    }

    if (plan->step_count >= EW_MAX_PLAN_STEPS) {
        return EW_ERR_LIMIT;
    }

    /* Check for duplicate steps */
    for (uint32_t i = 0; i < plan->step_count; i++) {
        if (plan->steps[i].type == type)
            return EW_ERR_DUPLICATE;
    }

    ew_plan_step_t *step = &plan->steps[plan->step_count];
    step->type = type;
    step->completed = 0;
    step->skipped = 0;
    step->result = EW_OK;
    step->items_processed = 0;

    plan->step_count++;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Execute a single plan step                                          */
/* ------------------------------------------------------------------ */

static ew_error_t execute_step(ew_context_t *ctx, ew_plan_step_t *step)
{
    ew_error_t err = EW_OK;

    switch (step->type) {
    case EW_STEP_PARSE_HEADER:
        err = ew_parse_header(ctx);
        break;
    case EW_STEP_PARSE_SECTIONS:
        err = ew_parse_sections(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->section_count;
        break;
    case EW_STEP_PARSE_SEGMENTS:
        err = ew_parse_segments(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->segment_count;
        break;
    case EW_STEP_RESOLVE_STRTABS:
        err = ew_resolve_strtabs(ctx);
        break;
    case EW_STEP_PARSE_SYMTABS:
        err = ew_parse_symtabs(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->symtab_count + ctx->dynsym_count;
        break;
    case EW_STEP_PARSE_DYNAMICS:
        err = ew_parse_dynamics(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->dynamic_count;
        break;
    case EW_STEP_PARSE_RELOCS:
        err = ew_parse_relocs(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->reloc_count;
        break;
    case EW_STEP_PARSE_NOTES:
        err = ew_parse_notes(ctx);
        if (err == EW_OK)
            step->items_processed = ctx->note_count;
        break;
    case EW_STEP_BUILD_HASH:
        err = ew_build_sysv_hash(ctx);
        if (err == EW_OK)
            err = ew_build_gnu_hash(ctx);
        break;
    case EW_STEP_RESOLVE_VERSIONS:
        err = ew_resolve_versions(ctx);
        break;
    case EW_STEP_BUILD_GRAPH:
        err = ew_build_dep_graph(ctx);
        break;
    case EW_STEP_RESOLVE_SYMBOLS:
        err = ew_resolve_symbols(ctx);
        break;
    case EW_STEP_APPLY_RELOCS:
        err = ew_apply_relocations(ctx);
        break;
    case EW_STEP_VALIDATE:
        err = ew_validate(ctx);
        break;
    case EW_STEP_NORMALIZE:
        err = ew_normalize(ctx);
        break;
    case EW_STEP_REGISTER:
        /* Registration is a no-op without an explicit registry */
        break;
    case EW_STEP_CACHE:
        /* Caching is handled by resolve/hash build */
        ctx->cached = 1;
        break;
    default:
        err = EW_ERR_INVALID;
        break;
    }

    step->result = err;
    step->completed = (err == EW_OK);
    return err;
}

/* ------------------------------------------------------------------ */
/* Plan execution                                                      */
/* ------------------------------------------------------------------ */

ew_error_t ew_plan_execute(ew_context_t *ctx, ew_plan_t *plan)
{
    if (!ctx || !plan)
        return EW_ERR_INVALID;

    if (plan->step_count == 0)
        return EW_OK;

    plan->finalized = 1;
    plan->current_step = 0;

    for (uint32_t i = 0; i < plan->step_count; i++) {
        plan->current_step = i;
        ew_plan_step_t *step = &plan->steps[i];

        /* Skip steps that have already completed */
        if (step->completed) {
            step->skipped = 1;
            continue;
        }

        ew_error_t err = execute_step(ctx, step);
        if (err != EW_OK) {
            /* Record the error but allow plan to note which step failed */
            ctx->last_error = err;
            return err;
        }
    }

    return EW_OK;
}

void ew_plan_destroy(ew_plan_t *plan)
{
    if (!plan)
        return;
    free(plan);
}

/* ------------------------------------------------------------------ */
/* Build a default full analysis plan                                  */
/* ------------------------------------------------------------------ */

__attribute__((unused))
static ew_plan_t *build_default_plan(void)
{
    ew_plan_t *plan = ew_plan_create();
    if (!plan)
        return NULL;

    /* Standard analysis pipeline order */
    ew_plan_add_step(plan, EW_STEP_PARSE_HEADER);
    ew_plan_add_step(plan, EW_STEP_PARSE_SECTIONS);
    ew_plan_add_step(plan, EW_STEP_PARSE_SEGMENTS);
    ew_plan_add_step(plan, EW_STEP_RESOLVE_STRTABS);
    ew_plan_add_step(plan, EW_STEP_PARSE_SYMTABS);
    ew_plan_add_step(plan, EW_STEP_PARSE_DYNAMICS);
    ew_plan_add_step(plan, EW_STEP_PARSE_RELOCS);
    ew_plan_add_step(plan, EW_STEP_PARSE_NOTES);
    ew_plan_add_step(plan, EW_STEP_BUILD_HASH);
    ew_plan_add_step(plan, EW_STEP_RESOLVE_VERSIONS);
    ew_plan_add_step(plan, EW_STEP_BUILD_GRAPH);
    ew_plan_add_step(plan, EW_STEP_RESOLVE_SYMBOLS);
    ew_plan_add_step(plan, EW_STEP_APPLY_RELOCS);
    ew_plan_add_step(plan, EW_STEP_VALIDATE);
    ew_plan_add_step(plan, EW_STEP_NORMALIZE);
    ew_plan_add_step(plan, EW_STEP_CACHE);

    return plan;
}
