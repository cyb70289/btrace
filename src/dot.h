#ifndef DOT_H
#define DOT_H

#include "btrace.h"

struct dep_edge {
    u32 from_tid;
    u32 to_tid;
    int block_cat;
    int waker_cat;
    u64 total_ns;
    u32 count;
    char from_comm[COMM_LEN];
    char to_comm[COMM_LEN];
};

struct dep_graph {
    struct dep_edge *edges;
    int edge_count;
    int edge_cap;
};

void dep_graph_init(struct dep_graph *g);
void dep_graph_add(struct dep_graph *g, u32 from_tid, u32 to_tid,
                   int block_cat, int waker_cat, u64 duration_ns,
                   const char *from_comm, const char *to_comm);
void dep_graph_free(struct dep_graph *g);
int dot_generate(struct dep_graph *g, const char *path);

#endif
