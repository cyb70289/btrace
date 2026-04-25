#include "report.h"
#include "btrace.h"
#include "dot.h"
#include "storage.h"
#include "sym.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *block_cat_name(int cat) {
    switch (cat) {
    case CAT_FUTEX:
        return "futex";
    case CAT_DISK_IO:
        return "disk_io";
    case CAT_NET_IO:
        return "net_io";
    case CAT_POLL:
        return "poll";
    case CAT_SLEEP:
        return "sleep";
    case CAT_IO_URING:
        return "io_uring";
    case CAT_AIO:
        return "aio";
    case CAT_OTHER:
        return "other";
    default:
        return "unknown";
    }
}

const char *waker_cat_name(int cat) {
    switch (cat) {
    case WCAT_THREAD:
        return "thread";
    case WCAT_DISK_IO:
        return "disk_io";
    case WCAT_NET_RX:
        return "net_rx";
    case WCAT_TIMER:
        return "timer";
    case WCAT_OTHER:
        return "kernel";
    default:
        return "unknown";
    }
}

static int is_special_tid(u32 tid) { return tid == 0; }

struct reason_pattern {
    const char *str;
    int cat;
};

static int match_pattern(const char *sym, const struct reason_pattern *pat) {
    return sym && strstr(sym, pat->str);
}

static const struct reason_pattern block_patterns[] = {
    {"futex_wait", CAT_FUTEX},   {"nanosleep", CAT_SLEEP},
    {"ep_poll", CAT_POLL},       {"do_poll", CAT_POLL},
    {"io_uring", CAT_IO_URING},  {"io_getevents", CAT_AIO},
    {"folio_", CAT_DISK_IO},     {"_fsync", CAT_DISK_IO},
    {"_fdatasync", CAT_DISK_IO}, {"_sync_file", CAT_DISK_IO},
    {"vfs_", CAT_DISK_IO},       {"jbd2_", CAT_DISK_IO},
    {"sk_wait_", CAT_NET_IO},    {"tcp_", CAT_NET_IO},
    {"udp_", CAT_NET_IO},        {NULL, 0}};

// XXX: infer thread block reason per kernel call stack
int classify_block_reason(const char **syms, int num_frames) {
    for (const struct reason_pattern *p = block_patterns; p->str; p++) {
        for (int i = 0; i < num_frames; i++) {
            if (match_pattern(syms[i], p))
                return p->cat;
        }
    }
    return CAT_OTHER;
}

static const struct reason_pattern waker_patterns[] = {
    {"futex_wake", WCAT_THREAD},
    {"hrtimer_wakeup", WCAT_TIMER},
    {"jbd2_", WCAT_DISK_IO},
    {"kjournald", WCAT_DISK_IO},
    {"folio_", WCAT_DISK_IO},
    {"bio_", WCAT_DISK_IO},
    {"sock_def_readable", WCAT_NET_RX},
    {"tcp_", WCAT_NET_RX},
    {"udp_", WCAT_NET_RX},
    {"netif_", WCAT_NET_RX},
    {NULL, 0}};

// XXX: infer thread wakeup reason per kernel call stack
int classify_waker_reason(const char **syms, int num_frames) {
    for (const struct reason_pattern *p = waker_patterns; p->str; p++) {
        for (int i = 0; i < num_frames; i++) {
            if (match_pattern(syms[i], p))
                return p->cat;
        }
    }
    return WCAT_OTHER;
}

struct thread_stat {
    u32 tid;
    char comm[COMM_LEN];
    u64 total_ns;
    u32 count;
    u64 min_ns;
    u64 max_ns;
};

struct cat_stat {
    int cat;
    u64 total_ns;
    u32 count;
};

struct stack_stat {
    int kstack_id;
    int ustack_id;
    u64 total_ns;
    u32 count;
    int block_cat;
};

static void format_ns(u64 ns, char *buf, size_t sz) {
    if (ns < 1000ULL)
        snprintf(buf, sz, "%lluns", (unsigned long long)ns);
    else if (ns < 1000000ULL)
        snprintf(buf, sz, "%.1fus", (double)ns / 1e3);
    else if (ns < 1000000000ULL)
        snprintf(buf, sz, "%.1fms", (double)ns / 1e6);
    else
        snprintf(buf, sz, "%.2fs", (double)ns / 1e9);
}

int report_main(int argc, char **argv) {
    const char *input = NULL;
    const char *outdir = ".";
    int gen_dot = 0;
    u32 min_count = 10;
    u64 min_ns = 1000000ULL;

    static struct option long_opts[] = {
        {"input", required_argument, NULL, 'i'},
        {"output", required_argument, NULL, 'o'},
        {"dot", no_argument, NULL, 'D'},
        {"min-count", required_argument, NULL, 'c'},
        {"min-time", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "i:o:Dc:t:", long_opts, NULL)) != -1) {
        switch (c) {
        case 'i':
            input = optarg;
            break;
        case 'o':
            outdir = optarg;
            break;
        case 'D':
            gen_dot = 1;
            break;
        case 'c':
            min_count = (u32)atoi(optarg);
            break;
        case 't':
            min_ns = (u64)atol(optarg) * 1000000ULL;
            break;
        default:
            fprintf(stderr, "Usage: btrace report -i <file> [-o <dir>] [--dot] "
                            "[--min-count N] [--min-time Ms]\n");
            return 1;
        }
    }

    if (!input) {
        fprintf(stderr, "Error: -i <file> is required\n");
        return 1;
    }

    struct bt_reader *r = bt_reader_open(input);
    if (!r) {
        fprintf(stderr, "Error: cannot open %s\n", input);
        return 1;
    }

    if (bt_reader_load_all(r) < 0) {
        fprintf(stderr, "Warning: failed to load some sections\n");
    }

    struct ksym_table kt = {};
    if (r->kallsyms)
        ksym_load(&kt, r->kallsyms);

    struct maps_parse mp = {};
    if (r->maps)
        maps_parse(&mp, r->maps);

    struct sym_cache sc = {};
    sym_cache_init(&sc);

    int max_threads = (r->thread_count > 0) ? r->thread_count : 4096;
    struct thread_stat *tstats = calloc(max_threads, sizeof(*tstats));
    int ntstats = 0;

    struct dep_graph graph;
    dep_graph_init(&graph);

    int max_stacks = 4096;
    struct stack_stat *sstats = calloc(max_stacks, sizeof(*sstats));
    int nsstats = 0;

    /* fast lookups */
    int tid_map[4096];
    for (int i = 0; i < 4096; i++)
        tid_map[i] = -1;
    struct stack_stat **kstack_map = calloc(MAX_STACK_MAP, sizeof(*kstack_map));

    fseek(r->fp, (long)r->hdr.events_off, SEEK_SET);
    uint64_t total_bw = 0;

    for (uint64_t ei = 0; ei < r->hdr.num_events; ei++) {
        uint32_t magic, evt_len;
        if (fread(&magic, sizeof(magic), 1, r->fp) != 1)
            break;
        if (magic != EVENT_MAGIC) {
            fprintf(stderr, "Invalud event magic number\n");
            break;
        }
        if (fread(&evt_len, sizeof(evt_len), 1, r->fp) != 1)
            break;

        struct block_wake_event bw;
        if (evt_len != sizeof(bw)) {
            fprintf(stderr, "Invalid event size\n");
            break;
        }
        if (fread(&bw, 1, evt_len, r->fp) != evt_len)
            break;

        u64 dur = bw.timestamp - bw.block_timestamp;
        total_bw++;

        int tidx = -1;
        for (int h = (int)((bw.blocked_tid ^ (bw.blocked_tid >> 16)) & 4095);;
             h = (h + 1) & 4095) {
            int idx = tid_map[h];
            if (idx == -1) {
                if (ntstats < max_threads) {
                    tid_map[h] = ntstats;
                    tidx = ntstats++;
                    tstats[tidx].tid = bw.blocked_tid;
                    strncpy(tstats[tidx].comm, bw.blocked_comm, COMM_LEN - 1);
                    tstats[tidx].comm[COMM_LEN - 1] = '\0';
                    tstats[tidx].min_ns = UINT64_MAX;
                }
                break;
            }
            if (tstats[idx].tid == bw.blocked_tid) {
                tidx = idx;
                break;
            }
        }
        if (tidx >= 0) {
            tstats[tidx].total_ns += dur;
            tstats[tidx].count++;
            if (dur < tstats[tidx].min_ns)
                tstats[tidx].min_ns = dur;
            if (dur > tstats[tidx].max_ns)
                tstats[tidx].max_ns = dur;
        }

        u64 *kframes = NULL;
        int knframes = 0;
        bt_reader_get_stack(r, bw.blocked_kstack_id, &kframes, &knframes);

        const char *ksyms[12] = {};
        if (knframes > 12)
            knframes = 12;
        for (int i = 0; i < knframes; i++) {
            u64 off;
            ksyms[i] = ksym_lookup(&kt, kframes[i], &off);
        }

        int bcat = classify_block_reason(ksyms, knframes);

        if (bw.blocked_kstack_id >= 0) {
            struct stack_stat *ss = NULL;
            if (bw.blocked_kstack_id < MAX_STACK_MAP)
                ss = kstack_map[bw.blocked_kstack_id];
            if (!ss && nsstats < max_stacks) {
                ss = &sstats[nsstats++];
                if (bw.blocked_kstack_id < MAX_STACK_MAP)
                    kstack_map[bw.blocked_kstack_id] = ss;
                ss->kstack_id = bw.blocked_kstack_id;
                ss->ustack_id = bw.blocked_ustack_id;
                ss->block_cat = bcat;
            }
            if (ss) {
                ss->total_ns += dur;
                ss->count++;
            }
        }

        u64 *wkframes = NULL;
        int wknframes = 0;
        bt_reader_get_stack(r, bw.waker_kstack_id, &wkframes, &wknframes);

        const char *wksyms[12] = {};
        if (wknframes > 12)
            wknframes = 12;
        for (int i = 0; i < wknframes; i++) {
            u64 off;
            wksyms[i] = ksym_lookup(&kt, wkframes[i], &off);
        }

        int wcat = classify_waker_reason(wksyms, wknframes);

        u32 waker_tid = bw.waker_tid;
        char waker_comm[COMM_LEN];
        strncpy(waker_comm, bw.waker_comm, COMM_LEN - 1);
        waker_comm[COMM_LEN - 1] = '\0';

        if (wcat != WCAT_THREAD) {
            waker_tid = 0;
            snprintf(waker_comm, COMM_LEN, "[%s]", waker_cat_name(wcat));
        }

        dep_graph_add(&graph, bw.blocked_tid, waker_tid, bcat, wcat, dur,
                      bw.blocked_kstack_id, bw.blocked_ustack_id,
                      bw.waker_kstack_id, bw.waker_ustack_id, bw.blocked_comm,
                      waker_comm);
    }

    double duration_s =
        (double)(r->hdr.end_time_ns - r->hdr.start_time_ns) / 1e9;

    printf("=== btrace report ===\n");
    printf("Target PID: %u  Duration: %.1fs  Events: %llu\n\n",
           r->hdr.target_pid, duration_s, (unsigned long long)total_bw);

    for (int i = 0; i < ntstats; i++) {
        if (tstats[i].min_ns == UINT64_MAX)
            tstats[i].min_ns = 0;
    }

    printf("Thread Summary:\n");
    printf("  %-8s %-16s %8s %12s %12s %12s\n", "TID", "Name", "Blocks",
           "Total Wait", "Avg Wait", "Max Wait");
    for (int i = 0; i < ntstats; i++) {
        struct thread_stat *ts = &tstats[i];
        char total_s[32], avg_s[32], max_s[32];
        format_ns(ts->total_ns, total_s, sizeof(total_s));
        format_ns(ts->count ? ts->total_ns / ts->count : 0, avg_s,
                  sizeof(avg_s));
        format_ns(ts->max_ns, max_s, sizeof(max_s));
        printf("  %-8u %-16s %8u %12s %12s %12s\n", ts->tid, ts->comm,
               ts->count, total_s, avg_s, max_s);
    }

    printf("\nThread Dependency Graph (waiter -> blocker):\n");
    for (int i = 0; i < graph.edge_count; i++) {
        struct dep_edge *e = &graph.edges[i];
        char dur_s[32];
        format_ns(e->total_ns, dur_s, sizeof(dur_s));

        if (is_special_tid(e->to_tid)) {
            printf("  %u (%s) -> [%s]:  %s (%ux)  [%s]\n", e->from_tid,
                   e->from_comm, waker_cat_name(e->waker_cat), dur_s, e->count,
                   block_cat_name(e->block_cat));
        } else {
            printf("  %u (%s) -> %u (%s):  %s (%ux)  [%s]\n", e->from_tid,
                   e->from_comm, e->to_tid, e->to_comm, dur_s, e->count,
                   block_cat_name(e->block_cat));
        }
    }

    if (nsstats > 0) {
        int stack_stat_cmp(const void *a, const void *b) {
            const struct stack_stat *sa = a, *sb = b;
            if (sa->total_ns < sb->total_ns)
                return 1;
            if (sa->total_ns > sb->total_ns)
                return -1;
            return 0;
        }
        qsort(sstats, (size_t)nsstats, sizeof(*sstats), stack_stat_cmp);

        printf("\nTop Blocking Stacks:\n");
        int to_show = nsstats > 10 ? 10 : nsstats;
        for (int i = 0; i < to_show; i++) {
            struct stack_stat *ss = &sstats[i];
            char dur_s[32];
            format_ns(ss->total_ns, dur_s, sizeof(dur_s));
            printf("\n  [%s] %s (%ux)\n", block_cat_name(ss->block_cat), dur_s,
                   ss->count);

            printf("    kernel:\n");
            u64 *frames = NULL;
            int nframes = 0;
            if (bt_reader_get_stack(r, ss->kstack_id, &frames, &nframes) == 0) {
                for (int j = 0; j < nframes && j < 12; j++) {
                    u64 off;
                    const char *name = ksym_lookup(&kt, frames[j], &off);
                    if (name)
                        printf("      %s+0x%llx\n", name,
                               (unsigned long long)off);
                    else if (frames[j])
                        printf("      0x%llx\n", (unsigned long long)frames[j]);
                }
            }

            if (ss->ustack_id >= 0) {
                printf("    user:\n");
                frames = NULL;
                nframes = 0;
                if (bt_reader_get_stack(r, ss->ustack_id, &frames, &nframes) ==
                    0) {
                    char ubuf[512];
                    for (int j = 0; j < nframes && j < 12; j++) {
                        u64 off;
                        const char *kname = ksym_lookup(&kt, frames[j], &off);
                        if (kname)
                            continue;
                        const char *uname = sym_resolve_user(
                            &sc, &mp, frames[j], ubuf, sizeof(ubuf));
                        if (uname)
                            printf("      %s\n", uname);
                        else if (frames[j])
                            printf("      0x%llx\n",
                                   (unsigned long long)frames[j]);
                    }
                }
            }
        }
    }

    if (gen_dot) {
        char dotpath[4096];
        snprintf(dotpath, sizeof(dotpath), "%s/btrace.dot", outdir);
        fprintf(stderr, "\nGenerating DOT graph ...\n");
        if (dot_generate(&graph, dotpath, min_count, min_ns, r, &kt, &sc,
                         &mp) == 0)
            fprintf(stderr, "DOT graph written to %s\n", dotpath);
        else
            fprintf(stderr, "Error writing DOT graph\n");
    }

    free(kstack_map);
    free(sstats);
    free(tstats);
    dep_graph_free(&graph);
    sym_cache_free(&sc);
    maps_free(&mp);
    ksym_free(&kt);
    bt_reader_close(r);
    return 0;
}
