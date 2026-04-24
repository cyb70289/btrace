#ifndef DOT_H
#define DOT_H

#include "btrace.h"

struct bt_reader;
struct ksym_table;

struct dep_edge {
    u32 from_tid;
    u32 to_tid;
    int block_cat;
    int waker_cat;
    u64 total_ns;
    u32 count;
    int blocked_kstack_id;
    int blocked_ustack_id;
    int waker_kstack_id;
    int waker_ustack_id;
    char from_comm[COMM_LEN];
    char to_comm[COMM_LEN];
};

struct dep_graph {
    struct dep_edge *edges;
    int edge_count;
    int edge_cap;
};

void dep_graph_init(struct dep_graph *g);
void dep_graph_add(struct dep_graph *g, u32 from_tid, u32 to_tid, int block_cat,
                   int waker_cat, u64 duration_ns, int blocked_kstack_id,
                   int blocked_ustack_id, int waker_kstack_id,
                   int waker_ustack_id, const char *from_comm,
                   const char *to_comm);
void dep_graph_free(struct dep_graph *g);
struct sym_cache;
struct maps_parse;

int dot_generate(struct dep_graph *g, const char *path, u32 min_count,
                 u64 min_ns, struct bt_reader *r, struct ksym_table *kt,
                 struct sym_cache *sc, struct maps_parse *mp);

#endif
