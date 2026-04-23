#include "report.h"
#include "storage.h"
#include "sym.h"
#include "dot.h"
#include "btrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

const char *block_cat_name(int cat)
{
    switch (cat) {
    case CAT_FUTEX:    return "futex";
    case CAT_DISK_IO:  return "disk_io";
    case CAT_NET_IO:   return "net_io";
    case CAT_EPOLL:    return "epoll";
    case CAT_SLEEP:    return "sleep";
    case CAT_PGFAULT:  return "page_fault";
    case CAT_IO_URING: return "io_uring";
    case CAT_WAITPID:  return "waitpid";
    case CAT_SIGNAL:   return "signal";
    case CAT_OTHER:    return "other";
    default:           return "unknown";
    }
}

const char *waker_cat_name(int cat)
{
    switch (cat) {
    case WCAT_THREAD:  return "thread";
    case WCAT_DISK_IO: return "disk_io";
    case WCAT_NET_RX:  return "net_rx";
    case WCAT_TIMER:   return "timer";
    case WCAT_SIGNAL:  return "signal";
    case WCAT_OTHER:   return "kernel";
    default:           return "unknown";
    }
}

static int is_special_tid(u32 tid)
{
    return tid == 0;
}

static int match_sym(const char **syms, int nframes, const char *pattern)
{
    for (int i = 0; i < nframes && i < 8; i++) {
        if (syms[i] && strstr(syms[i], pattern))
            return 1;
    }
    return 0;
}

int classify_block_reason(int kstack_id, int num_frames, u64 *frames,
                          const char **syms)
{
    (void)kstack_id;
    (void)frames;
    if (match_sym(syms, num_frames, "futex_wait"))   return CAT_FUTEX;
    if (match_sym(syms, num_frames, "ep_poll"))       return CAT_EPOLL;
    if (match_sym(syms, num_frames, "do_poll"))       return CAT_EPOLL;
    if (match_sym(syms, num_frames, "schedule_hrtimeout")) return CAT_FUTEX;
    if (match_sym(syms, num_frames, "io_schedule"))   return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "read_events"))   return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "vfs_read"))      return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "vfs_write"))     return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "blkdev"))        return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "do_sync_write")) return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "ext4"))          return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "xfs"))           return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "jbd2"))          return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "folio_wait_bit"))return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "filemap_wait"))  return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "file_write_and_wait")) return CAT_DISK_IO;
    if (match_sym(syms, num_frames, "tcp_recvmsg"))   return CAT_NET_IO;
    if (match_sym(syms, num_frames, "udp_recvmsg"))   return CAT_NET_IO;
    if (match_sym(syms, num_frames, "sk_wait_data"))  return CAT_NET_IO;
    if (match_sym(syms, num_frames, "nanosleep"))     return CAT_SLEEP;
    if (match_sym(syms, num_frames, "hrtimer_nanosleep")) return CAT_SLEEP;
    if (match_sym(syms, num_frames, "handle_mm_fault"))  return CAT_PGFAULT;
    if (match_sym(syms, num_frames, "io_uring"))      return CAT_IO_URING;
    if (match_sym(syms, num_frames, "wait_task"))     return CAT_WAITPID;
    if (match_sym(syms, num_frames, "do_wait"))       return CAT_WAITPID;
    if (match_sym(syms, num_frames, "sigsuspend"))    return CAT_SIGNAL;
    return CAT_OTHER;
}

int classify_waker_reason(int kstack_id, int num_frames, u64 *frames,
                          const char **syms)
{
    (void)kstack_id;
    (void)frames;
    if (match_sym(syms, num_frames, "futex_wake"))       return WCAT_THREAD;
    if (match_sym(syms, num_frames, "do_futex"))          return WCAT_THREAD;
    if (match_sym(syms, num_frames, "blk_update_request"))return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "scsi_end_request"))  return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "blk_mq_complete"))   return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "bio_endio"))         return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "folio_end_writeback"))return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "end_buffer_async"))  return WCAT_DISK_IO;
    if (match_sym(syms, num_frames, "tcp_v4_rcv"))        return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "tcp_v6_rcv"))        return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "udp_rcv"))           return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "netif_receive_skb")) return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "tcp_data_ready"))    return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "sock_def_readable")) return WCAT_NET_RX;
    if (match_sym(syms, num_frames, "hrtimer_interrupt")) return WCAT_TIMER;
    if (match_sym(syms, num_frames, "hrtimer_wakeup"))   return WCAT_TIMER;
    if (match_sym(syms, num_frames, "send_signal"))       return WCAT_SIGNAL;
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

static void format_ns(u64 ns, char *buf, size_t sz)
{
    if (ns < 1000ULL)
        snprintf(buf, sz, "%lluns", (unsigned long long)ns);
    else if (ns < 1000000ULL)
        snprintf(buf, sz, "%.1fus", (double)ns / 1e3);
    else if (ns < 1000000000ULL)
        snprintf(buf, sz, "%.1fms", (double)ns / 1e6);
    else
        snprintf(buf, sz, "%.2fs", (double)ns / 1e9);
}

int report_main(int argc, char **argv)
{
    const char *input = NULL;
    const char *outdir = ".";
    int gen_dot = 0;
    u32 min_count = 10;
    u64 min_ns = 1000000ULL;

    static struct option long_opts[] = {
        {"input",      required_argument, NULL, 'i'},
        {"output",     required_argument, NULL, 'o'},
        {"dot",        no_argument,       NULL, 'D'},
        {"min-count",  required_argument, NULL, 'c'},
        {"min-time",   required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "i:o:Dc:t:", long_opts, NULL)) != -1) {
        switch (c) {
        case 'i': input = optarg; break;
        case 'o': outdir = optarg; break;
        case 'D': gen_dot = 1; break;
        case 'c': min_count = (u32)atoi(optarg); break;
        case 't': min_ns = (u64)atol(optarg) * 1000000ULL; break;
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

    fseek(r->fp, (long)r->hdr.events_off, SEEK_SET);
    uint64_t total_bw = 0;

    for (uint64_t ei = 0; ei < r->hdr.num_events; ei++) {
        uint32_t evt_type, evt_len;
        if (fread(&evt_type, sizeof(evt_type), 1, r->fp) != 1) break;
        if (fread(&evt_len, sizeof(evt_len), 1, r->fp) != 1) break;

        union {
            struct block_wake_event bw;
            struct block_only_event bo;
            struct thread_create_event tc;
            struct thread_exit_event te;
        } evt;

        if (evt_len > sizeof(evt)) {
            fseek(r->fp, (long)evt_len, SEEK_CUR);
            continue;
        }
        if (fread(&evt, 1, evt_len, r->fp) != evt_len) break;

        if (evt_type == EVT_BLOCK_WAKE) {
            struct block_wake_event *bw = &evt.bw;
            u64 dur = bw->timestamp - bw->block_timestamp;
            total_bw++;

            int tidx = -1;
            for (int i = 0; i < ntstats; i++) {
                if (tstats[i].tid == bw->blocked_tid) { tidx = i; break; }
            }
            if (tidx < 0 && ntstats < max_threads) {
                tidx = ntstats++;
                tstats[tidx].tid = bw->blocked_tid;
                strncpy(tstats[tidx].comm, bw->blocked_comm, COMM_LEN);
                tstats[tidx].min_ns = UINT64_MAX;
            }
            if (tidx >= 0) {
                tstats[tidx].total_ns += dur;
                tstats[tidx].count++;
                if (dur < tstats[tidx].min_ns) tstats[tidx].min_ns = dur;
                if (dur > tstats[tidx].max_ns) tstats[tidx].max_ns = dur;
            }

            u64 *kframes = NULL;
            int knframes = 0;
            bt_reader_get_stack(r, bw->blocked_kstack_id, &kframes, &knframes);

            const char *ksyms[8] = {};
            for (int i = 0; i < knframes && i < 8; i++) {
                u64 off;
                ksyms[i] = ksym_lookup(&kt, kframes[i], &off);
            }

            int bcat = classify_block_reason(bw->blocked_kstack_id,
                                             knframes, kframes, ksyms);

            if (bw->blocked_kstack_id >= 0) {
                int si = -1;
                for (int i = 0; i < nsstats; i++) {
                    if (sstats[i].kstack_id == bw->blocked_kstack_id) { si = i; break; }
                }
                if (si < 0 && nsstats < max_stacks) {
                    si = nsstats++;
                    sstats[si].kstack_id = bw->blocked_kstack_id;
                    sstats[si].ustack_id = bw->blocked_ustack_id;
                    sstats[si].block_cat = bcat;
                }
                if (si >= 0) {
                    sstats[si].total_ns += dur;
                    sstats[si].count++;
                }
            }

            u64 *wkframes = NULL;
            int wknframes = 0;
            bt_reader_get_stack(r, bw->waker_kstack_id, &wkframes, &wknframes);

            const char *wksyms[8] = {};
            for (int i = 0; i < wknframes && i < 8; i++) {
                u64 off;
                wksyms[i] = ksym_lookup(&kt, wkframes[i], &off);
            }

            int wcat = classify_waker_reason(bw->waker_kstack_id,
                                             wknframes, wkframes, wksyms);

            u32 waker_tid = bw->waker_tid;
            char waker_comm[COMM_LEN];
            strncpy(waker_comm, bw->waker_comm, COMM_LEN);

            if (wcat != WCAT_THREAD) {
                waker_tid = 0;
                snprintf(waker_comm, COMM_LEN, "[%s]", waker_cat_name(wcat));
            }

            dep_graph_add(&graph, bw->blocked_tid, waker_tid,
                          bcat, wcat, dur,
                          bw->blocked_kstack_id, bw->blocked_ustack_id,
                          bw->waker_kstack_id, bw->waker_ustack_id,
                          bw->blocked_comm, waker_comm);
        }
    }

    double duration_s = (double)(r->hdr.end_time_ns - r->hdr.start_time_ns) / 1e9;

    printf("=== btrace report ===\n");
    printf("Target PID: %u  Duration: %.1fs  Events: %llu\n\n",
           r->hdr.target_pid, duration_s, (unsigned long long)total_bw);

    for (int i = 0; i < ntstats; i++) {
        if (tstats[i].min_ns == UINT64_MAX) tstats[i].min_ns = 0;
    }

    printf("Thread Summary:\n");
    printf("  %-8s %-16s %8s %12s %12s %12s\n",
           "TID", "Name", "Blocks", "Total Wait", "Avg Wait", "Max Wait");
    for (int i = 0; i < ntstats; i++) {
        struct thread_stat *ts = &tstats[i];
        char total_s[32], avg_s[32], max_s[32];
        format_ns(ts->total_ns, total_s, sizeof(total_s));
        format_ns(ts->count ? ts->total_ns / ts->count : 0, avg_s, sizeof(avg_s));
        format_ns(ts->max_ns, max_s, sizeof(max_s));
        printf("  %-8u %-16s %8u %12s %12s %12s\n",
               ts->tid, ts->comm, ts->count, total_s, avg_s, max_s);
    }

    printf("\nThread Dependency Graph (waiter -> blocker):\n");
    for (int i = 0; i < graph.edge_count; i++) {
        struct dep_edge *e = &graph.edges[i];
        char dur_s[32];
        format_ns(e->total_ns, dur_s, sizeof(dur_s));

        if (is_special_tid(e->to_tid)) {
            printf("  %u (%s) -> [%s]:  %s (%ux)  [%s]\n",
                   e->from_tid, e->from_comm,
                   waker_cat_name(e->waker_cat),
                   dur_s, e->count, block_cat_name(e->block_cat));
        } else {
            printf("  %u (%s) -> %u (%s):  %s (%ux)  [%s]\n",
                   e->from_tid, e->from_comm,
                   e->to_tid, e->to_comm,
                   dur_s, e->count, block_cat_name(e->block_cat));
        }
    }

    if (nsstats > 0) {
        for (int i = 0; i < nsstats - 1; i++) {
            for (int j = i + 1; j < nsstats; j++) {
                if (sstats[j].total_ns > sstats[i].total_ns) {
                    struct stack_stat tmp = sstats[i];
                    sstats[i] = sstats[j];
                    sstats[j] = tmp;
                }
            }
        }

        printf("\nTop Blocking Stacks:\n");
        int to_show = nsstats > 10 ? 10 : nsstats;
        for (int i = 0; i < to_show; i++) {
            struct stack_stat *ss = &sstats[i];
            char dur_s[32];
            format_ns(ss->total_ns, dur_s, sizeof(dur_s));
            printf("\n  [%s] %s (%ux)\n", block_cat_name(ss->block_cat), dur_s, ss->count);

            printf("    kernel:\n");
            u64 *frames = NULL;
            int nframes = 0;
            if (bt_reader_get_stack(r, ss->kstack_id, &frames, &nframes) == 0) {
                for (int j = 0; j < nframes && j < 12; j++) {
                    u64 off;
                    const char *name = ksym_lookup(&kt, frames[j], &off);
                    if (name)
                        printf("      %s+0x%llx\n", name, (unsigned long long)off);
                    else if (frames[j])
                        printf("      0x%llx\n", (unsigned long long)frames[j]);
                }
            }

            if (ss->ustack_id >= 0) {
                printf("    user:\n");
                frames = NULL;
                nframes = 0;
                if (bt_reader_get_stack(r, ss->ustack_id, &frames, &nframes) == 0) {
                    char ubuf[256];
                    for (int j = 0; j < nframes && j < 12; j++) {
                        u64 off;
                        const char *kname = ksym_lookup(&kt, frames[j], &off);
                        if (kname) continue;
                        const char *uname = sym_resolve_user(&sc, &mp, frames[j], ubuf, sizeof(ubuf));
                        if (uname)
                            printf("      %s\n", uname);
                        else if (frames[j])
                            printf("      0x%llx\n", (unsigned long long)frames[j]);
                    }
                }
            }
        }
    }

    if (gen_dot) {
        char dotpath[512];
        snprintf(dotpath, sizeof(dotpath), "%s/btrace.dot", outdir);
        if (dot_generate(&graph, dotpath, min_count, min_ns, r, &kt, &sc, &mp) == 0)
            fprintf(stderr, "DOT graph written to %s\n", dotpath);
        else
            fprintf(stderr, "Error writing DOT graph\n");
    }

    free(sstats);
    free(tstats);
    dep_graph_free(&graph);
    sym_cache_free(&sc);
    maps_free(&mp);
    ksym_free(&kt);
    bt_reader_close(r);
    return 0;
}
