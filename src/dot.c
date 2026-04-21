#include "dot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *edge_color(int waker_cat)
{
    switch (waker_cat) {
    case WCAT_THREAD:  return "red";
    case WCAT_DISK_IO: return "blue";
    case WCAT_NET_RX:  return "green";
    case WCAT_TIMER:   return "orange";
    case WCAT_SIGNAL:  return "purple";
    default:           return "gray";
    }
}

static const char *node_palette[] = {
    "#b3d9ff", "#ffb3b3", "#b3ffb3", "#ffe6b3", "#e6b3ff",
    "#b3fff0", "#fff0b3", "#ffb3e6", "#b3e6ff", "#e6ffb3",
    "#d9b3ff", "#b3ffcc", "#ffccb3", "#b3ccff", "#ccb3ff",
    "#ff99aa", "#99ccff", "#99ffcc", "#ffcc99", "#cc99ff",
};

static void strip_trailing_dashnum(const char *comm, char *out, size_t outsz)
{
    strncpy(out, comm, outsz - 1);
    out[outsz - 1] = '\0';
    size_t len = strlen(out);
    size_t i = len;
    while (i > 0 && out[i - 1] >= '0' && out[i - 1] <= '9')
        i--;
    if (i > 0 && i < len && out[i - 1] == '-')
        out[i - 1] = '\0';
}

struct comm_color {
    char comm[COMM_LEN];
    const char *color;
};

static struct comm_color *comm_to_color(struct comm_color *cc, int *cc_count,
                                        int *cc_cap, const char *comm,
                                        const char **out_color)
{
    char key[COMM_LEN];
    strip_trailing_dashnum(comm, key, sizeof(key));

    for (int i = 0; i < *cc_count; i++) {
        if (strcmp(cc[i].comm, key) == 0) {
            *out_color = cc[i].color;
            return cc;
        }
    }

    int idx = *cc_count;
    if (idx >= *cc_cap) {
        *cc_cap = *cc_cap ? *cc_cap * 2 : 32;
        cc = realloc(cc, (size_t)*cc_cap * sizeof(struct comm_color));
    }
    strncpy(cc[idx].comm, key, COMM_LEN - 1);
    cc[idx].comm[COMM_LEN - 1] = '\0';
    cc[idx].color = node_palette[idx % (sizeof(node_palette) / sizeof(node_palette[0]))];
    *out_color = cc[idx].color;
    (*cc_count)++;
    return cc;
}

void dep_graph_init(struct dep_graph *g)
{
    memset(g, 0, sizeof(*g));
}

void dep_graph_add(struct dep_graph *g, u32 from_tid, u32 to_tid,
                   int block_cat, int waker_cat, u64 duration_ns,
                   const char *from_comm, const char *to_comm)
{
    for (int i = 0; i < g->edge_count; i++) {
        struct dep_edge *e = &g->edges[i];
        if (e->from_tid == from_tid && e->to_tid == to_tid &&
            e->block_cat == block_cat && e->waker_cat == waker_cat) {
            e->total_ns += duration_ns;
            e->count++;
            return;
        }
    }

    if (g->edge_count >= g->edge_cap) {
        g->edge_cap = g->edge_cap ? g->edge_cap * 2 : 32;
        g->edges = realloc(g->edges, g->edge_cap * sizeof(struct dep_edge));
    }

    struct dep_edge *e = &g->edges[g->edge_count++];
    e->from_tid = from_tid;
    e->to_tid = to_tid;
    e->block_cat = block_cat;
    e->waker_cat = waker_cat;
    e->total_ns = duration_ns;
    e->count = 1;
    strncpy(e->from_comm, from_comm, COMM_LEN - 1);
    strncpy(e->to_comm, to_comm, COMM_LEN - 1);
}

void dep_graph_free(struct dep_graph *g)
{
    free(g->edges);
}

static int is_special_tid(u32 tid)
{
    return tid == 0;
}

static const char *special_node_name(int waker_cat)
{
    switch (waker_cat) {
    case WCAT_DISK_IO: return "disk_io";
    case WCAT_NET_RX:  return "net_rx";
    case WCAT_TIMER:   return "timer";
    case WCAT_SIGNAL:  return "signal";
    case WCAT_OTHER:   return "kernel";
    default:           return "other";
    }
}

static void format_duration(u64 ns, char *buf, size_t bufsz)
{
    if (ns < 1000)
        snprintf(buf, bufsz, "%lluns", (unsigned long long)ns);
    else if (ns < 1000000)
        snprintf(buf, bufsz, "%.1fus", (double)ns / 1e3);
    else if (ns < 1000000000)
        snprintf(buf, bufsz, "%.1fms", (double)ns / 1e6);
    else
        snprintf(buf, bufsz, "%.2fs", (double)ns / 1e9);
}

int dot_generate(struct dep_graph *g, const char *path,
                 u32 min_count, u64 min_ns)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    int *used = calloc(g->edge_count, sizeof(int));
    int nused = 0;
    for (int i = 0; i < g->edge_count; i++) {
        struct dep_edge *e = &g->edges[i];
        if (e->count >= min_count && e->total_ns >= min_ns)
            used[nused++] = i;
    }

    if (nused == 0) {
        fprintf(f, "digraph btrace {\n  rankdir=LR;\n  label=\"no edges above threshold\";\n}\n");
        fclose(f);
        free(used);
        return 0;
    }

    fprintf(f, "digraph btrace {\n");
    fprintf(f, "  rankdir=LR;\n");
    fprintf(f, "  node [shape=record fontsize=10];\n");
    fprintf(f, "  edge [fontsize=9];\n\n");

    u32 *seen_tids = NULL;
    int seen_count = 0, seen_cap = 0;
    struct comm_color *cc = NULL;
    int cc_count = 0, cc_cap = 0;

    for (int k = 0; k < nused; k++) {
        struct dep_edge *e = &g->edges[used[k]];

        if (!is_special_tid(e->from_tid)) {
            int found = 0;
            for (int j = 0; j < seen_count; j++)
                if (seen_tids[j] == e->from_tid) { found = 1; break; }
            if (!found) {
                const char *col;
                cc = comm_to_color(cc, &cc_count, &cc_cap, e->from_comm, &col);
                fprintf(f, "  t%u [label=\"%u\\n%s\" style=filled fillcolor=\"%s\"];\n",
                        e->from_tid, e->from_tid, e->from_comm, col);
                if (seen_count >= seen_cap) {
                    seen_cap = seen_cap ? seen_cap * 2 : 32;
                    seen_tids = realloc(seen_tids, seen_cap * sizeof(u32));
                }
                seen_tids[seen_count++] = e->from_tid;
            }
        }

        if (!is_special_tid(e->to_tid)) {
            int found = 0;
            for (int j = 0; j < seen_count; j++)
                if (seen_tids[j] == e->to_tid) { found = 1; break; }
            if (!found) {
                const char *col;
                cc = comm_to_color(cc, &cc_count, &cc_cap, e->to_comm, &col);
                fprintf(f, "  t%u [label=\"%u\\n%s\" style=filled fillcolor=\"%s\"];\n",
                        e->to_tid, e->to_tid, e->to_comm, col);
                if (seen_count >= seen_cap) {
                    seen_cap = seen_cap ? seen_cap * 2 : 32;
                    seen_tids = realloc(seen_tids, seen_cap * sizeof(u32));
                }
                seen_tids[seen_count++] = e->to_tid;
            }
        }
    }

    int seen_cats = 0;
    int cat_seen[8] = {};
    for (int k = 0; k < nused; k++) {
        struct dep_edge *e = &g->edges[used[k]];
        if (is_special_tid(e->to_tid)) {
            int found = 0;
            for (int j = 0; j < seen_cats; j++)
                if (cat_seen[j] == e->waker_cat) { found = 1; break; }
            if (!found) {
                fprintf(f, "  cat_%s [label=\"[%s]\" shape=ellipse];\n",
                        special_node_name(e->waker_cat),
                        special_node_name(e->waker_cat));
                cat_seen[seen_cats++] = e->waker_cat;
            }
        }
    }

    fprintf(f, "\n");

    for (int k = 0; k < nused; k++) {
        struct dep_edge *e = &g->edges[used[k]];
        char dur[32];
        format_duration(e->total_ns, dur, sizeof(dur));

        char from_id[64], to_id[64];

        if (is_special_tid(e->from_tid))
            snprintf(from_id, sizeof(from_id), "cat_%s", special_node_name(e->waker_cat));
        else
            snprintf(from_id, sizeof(from_id), "t%u", e->from_tid);

        if (is_special_tid(e->to_tid))
            snprintf(to_id, sizeof(to_id), "cat_%s", special_node_name(e->waker_cat));
        else
            snprintf(to_id, sizeof(to_id), "t%u", e->to_tid);

        fprintf(f, "  %s -> %s [label=\"%s\\n%s, %ux\" color=%s];\n",
                from_id, to_id,
                block_cat_name(e->block_cat), dur, e->count,
                edge_color(e->waker_cat));
    }

    fprintf(f, "}\n");
    fclose(f);
    free(used);
    free(seen_tids);
    free(cc);
    return 0;
}
