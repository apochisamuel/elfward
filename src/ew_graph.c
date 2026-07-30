/*
 * ew_graph.c — Dependency graph construction and traversal.
 *
 * Builds a directed graph of library dependencies from DT_NEEDED
 * entries, performs topological sorting, and detects dependency
 * cycles. Used by symbol resolution to determine binding order.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Node management                                                     */
/* ------------------------------------------------------------------ */

static ew_error_t graph_ensure_node_cap(ew_dep_graph_t *g)
{
    if (g->node_count < g->node_capacity)
        return EW_OK;

    uint32_t new_cap = g->node_capacity == 0 ? 32 : g->node_capacity * 2;
    if (new_cap > EW_MAX_GRAPH_NODES)
        new_cap = EW_MAX_GRAPH_NODES;

    if (g->node_count >= new_cap)
        return EW_ERR_LIMIT;

    ew_dep_node_t *tmp = realloc(g->nodes, new_cap * sizeof(ew_dep_node_t));
    if (!tmp)
        return EW_ERR_NOMEM;

    g->nodes = tmp;
    g->node_capacity = new_cap;
    return EW_OK;
}

static int graph_find_node(ew_dep_graph_t *g, const char *name)
{
    for (uint32_t i = 0; i < g->node_count; i++) {
        if (g->nodes[i].name && strcmp(g->nodes[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

static int graph_add_node(ew_dep_graph_t *g, const char *name)
{
    int existing = graph_find_node(g, name);
    if (existing >= 0)
        return existing;

    if (graph_ensure_node_cap(g) != EW_OK)
        return -1;

    uint32_t idx = g->node_count;
    ew_dep_node_t *node = &g->nodes[idx];
    memset(node, 0, sizeof(*node));
    node->name = name;
    node->node_id = idx;
    node->edges = NULL;
    node->edge_count = 0;
    node->edge_capacity = 0;
    node->generation = g->generation;

    g->node_count++;
    g->sorted = 0;  /* invalidate sort */
    return (int)idx;
}

/* ------------------------------------------------------------------ */
/* Edge management                                                     */
/* ------------------------------------------------------------------ */

ew_error_t ew_dep_graph_add_edge(ew_dep_graph_t *g,
                                  uint32_t from, uint32_t to)
{
    if (!g)
        return EW_ERR_INVALID;

    if (from >= g->node_count || to >= g->node_count)
        return EW_ERR_INVALID;

    /* Self-loop check */
    if (from == to)
        return EW_OK;

    ew_dep_node_t *node = &g->nodes[from];

    /* Check for duplicate edge */
    for (uint32_t i = 0; i < node->edge_count; i++) {
        if (node->edges[i] == to)
            return EW_OK;
    }

    /* Grow edge array if needed */
    if (node->edge_count >= node->edge_capacity) {
        uint32_t new_cap = node->edge_capacity == 0 ?
                           4 : node->edge_capacity * 2;
        uint32_t *tmp = realloc(node->edges, new_cap * sizeof(uint32_t));
        if (!tmp)
            return EW_ERR_NOMEM;
        node->edges = tmp;
        node->edge_capacity = new_cap;
    }

    node->edges[node->edge_count++] = to;
    g->sorted = 0;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Cycle detection via DFS                                             */
/* ------------------------------------------------------------------ */

static int detect_cycle_dfs(ew_dep_graph_t *g, uint32_t node_idx)
{
    ew_dep_node_t *node = &g->nodes[node_idx];

    if (node->in_stack)
        return 1;  /* cycle found */

    if (node->visited)
        return 0;

    node->visited = 1;
    node->in_stack = 1;

    for (uint32_t i = 0; i < node->edge_count; i++) {
        if (detect_cycle_dfs(g, node->edges[i]))
            return 1;
    }

    node->in_stack = 0;
    return 0;
}

int ew_dep_graph_has_cycle(ew_dep_graph_t *g)
{
    if (!g)
        return 0;

    /* Reset visit flags */
    for (uint32_t i = 0; i < g->node_count; i++) {
        g->nodes[i].visited = 0;
        g->nodes[i].in_stack = 0;
    }

    for (uint32_t i = 0; i < g->node_count; i++) {
        if (!g->nodes[i].visited) {
            if (detect_cycle_dfs(g, i)) {
                g->has_cycle = 1;
                return 1;
            }
        }
    }

    g->has_cycle = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Topological sort (reverse post-order DFS)                           */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t *stack;
    uint32_t  top;
    uint32_t  capacity;
} topo_state_t;

static ew_error_t topo_dfs(ew_dep_graph_t *g, uint32_t node_idx,
                             topo_state_t *state)
{
    ew_dep_node_t *node = &g->nodes[node_idx];

    if (node->visited)
        return EW_OK;

    if (node->in_stack)
        return EW_ERR_CYCLE;

    node->in_stack = 1;

    for (uint32_t i = 0; i < node->edge_count; i++) {
        ew_error_t err = topo_dfs(g, node->edges[i], state);
        if (err != EW_OK)
            return err;
    }

    node->in_stack = 0;
    node->visited = 1;

    if (state->top >= state->capacity)
        return EW_ERR_LIMIT;

    state->stack[state->top++] = node_idx;
    return EW_OK;
}

ew_error_t ew_dep_graph_sort(ew_dep_graph_t *g)
{
    if (!g)
        return EW_ERR_INVALID;

    if (g->node_count == 0) {
        g->topo_sorted = NULL;
        g->topo_count = 0;
        g->sorted = 1;
        return EW_OK;
    }

    /* Reset visit flags */
    for (uint32_t i = 0; i < g->node_count; i++) {
        g->nodes[i].visited = 0;
        g->nodes[i].in_stack = 0;
    }

    free(g->topo_sorted);
    g->topo_sorted = malloc(g->node_count * sizeof(uint32_t));
    if (!g->topo_sorted)
        return EW_ERR_NOMEM;

    topo_state_t state;
    state.stack = g->topo_sorted;
    state.top = 0;
    state.capacity = g->node_count;

    for (uint32_t i = 0; i < g->node_count; i++) {
        if (!g->nodes[i].visited) {
            ew_error_t err = topo_dfs(g, i, &state);
            if (err != EW_OK) {
                g->has_cycle = (err == EW_ERR_CYCLE);
                return err;
            }
        }
    }

    g->topo_count = state.top;
    g->sorted = 1;

    /* Reverse the order (DFS post-order gives reverse topo) */
    for (uint32_t i = 0; i < g->topo_count / 2; i++) {
        uint32_t tmp = g->topo_sorted[i];
        g->topo_sorted[i] = g->topo_sorted[g->topo_count - 1 - i];
        g->topo_sorted[g->topo_count - 1 - i] = tmp;
    }

    /* Assign topological ordering to nodes */
    for (uint32_t i = 0; i < g->topo_count; i++) {
        g->nodes[g->topo_sorted[i]].topo_order = i;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Build dependency graph from dynamic section                         */
/* ------------------------------------------------------------------ */

ew_error_t ew_build_dep_graph(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (ctx->dep_graph) {
        ew_dep_graph_destroy(ctx->dep_graph);
        ctx->dep_graph = NULL;
    }

    ew_dep_graph_t *g = calloc(1, sizeof(ew_dep_graph_t));
    if (!g)
        return EW_ERR_NOMEM;

    g->generation = ctx->generation;

    /* Add the main binary as the root node */
    const char *root_name = "<self>";
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        if (ctx->dynamics[i].d_tag == EW_DT_SONAME &&
            ctx->dynamics[i].string_val) {
            root_name = ctx->dynamics[i].string_val;
            break;
        }
        if (ctx->dynamics[i].d_tag == EW_DT_NULL)
            break;
    }

    int root_idx = graph_add_node(g, root_name);
    if (root_idx < 0) {
        free(g);
        return EW_ERR_NOMEM;
    }

    /* Add DT_NEEDED entries as dependencies */
    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        if (ctx->dynamics[i].d_tag == EW_DT_NULL)
            break;

        if (ctx->dynamics[i].d_tag != EW_DT_NEEDED)
            continue;

        const char *lib_name = ctx->dynamics[i].string_val;
        if (!lib_name)
            continue;

        int lib_idx = graph_add_node(g, lib_name);
        if (lib_idx < 0)
            continue;

        ew_error_t err = ew_dep_graph_add_edge(g, (uint32_t)root_idx,
                                                (uint32_t)lib_idx);
        if (err != EW_OK && err != EW_ERR_LIMIT) {
            ew_dep_graph_destroy(g);
            return err;
        }
    }

    /* Perform topological sort */
    ew_error_t err = ew_dep_graph_sort(g);
    if (err == EW_ERR_CYCLE) {
        g->has_cycle = 1;
        /* Don't fail—cycles are valid in shared library deps */
    } else if (err != EW_OK) {
        ew_dep_graph_destroy(g);
        return err;
    }

    ctx->dep_graph = g;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Graph destruction                                                   */
/* ------------------------------------------------------------------ */

void ew_dep_graph_destroy(ew_dep_graph_t *g)
{
    if (!g)
        return;

    if (g->nodes) {
        for (uint32_t i = 0; i < g->node_count; i++) {
            free(g->nodes[i].edges);
        }
        free(g->nodes);
    }

    free(g->topo_sorted);
    free(g);
}

/* ------------------------------------------------------------------ */
/* Validation: check graph consistency                                 */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate_graph(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    if (!ctx->dep_graph)
        return EW_OK;

    ew_dep_graph_t *g = ctx->dep_graph;

    /* Verify all edge targets are valid node indices */
    for (uint32_t i = 0; i < g->node_count; i++) {
        ew_dep_node_t *node = &g->nodes[i];
        for (uint32_t j = 0; j < node->edge_count; j++) {
            if (node->edges[j] >= g->node_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "graph node %u has invalid edge target %u",
                         i, node->edges[j]);
                return EW_ERR_INVALID;
            }
        }
    }

    /* Check for generation consistency */
    for (uint32_t i = 0; i < g->node_count; i++) {
        if (g->nodes[i].generation != g->generation) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "graph node %u has stale generation %d (expected %d)",
                     i, g->nodes[i].generation, g->generation);
            return EW_ERR_STATE;
        }
    }

    return EW_OK;
}
