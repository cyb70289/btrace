#include "record.h"
#include "btrace.h"
#include "btrace.skel.h"
#include "storage.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile bool stopping = false;

static void sig_handler(int sig) {
    (void)sig;
    stopping = true;
}

static void perf_lost(void *ctx, int cpu, unsigned long long cnt) {
    (void)ctx;
    fprintf(stderr, "Lost %llu events on CPU %d\n", cnt, cpu);
}

struct record_ctx {
    struct bt_writer *writer;
};

static void perf_event_cb(void *ctx, int cpu, void *data, unsigned int size) {
    (void)cpu;
    struct record_ctx *rctx = ctx;
    if (!rctx || !rctx->writer)
        return;

    if (size >= sizeof(struct block_wake_event))
        bt_writer_event(rctx->writer, data, sizeof(struct block_wake_event));
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int record_main(int argc, char **argv) {
    int pid = 0;
    const char *output = "btrace.out";

    static struct option long_opts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"output", required_argument, NULL, 'o'},
        {NULL, 0, NULL, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "p:o:", long_opts, NULL)) != -1) {
        switch (c) {
        case 'p':
            pid = atoi(optarg);
            break;
        case 'o':
            output = optarg;
            break;
        default:
            fprintf(stderr, "Usage: btrace record -p <PID> [-o <file>]\n");
            return 1;
        }
    }

    if (pid <= 0) {
        fprintf(stderr, "Error: -p <PID> is required\n");
        return 1;
    }

    uint64_t start_ns = now_ns();

    struct bt_writer *writer =
        bt_writer_create(output, (uint32_t)pid, start_ns);
    if (!writer) {
        fprintf(stderr, "Error: cannot create output file %s: %s\n", output,
                strerror(errno));
        return 1;
    }

    struct btrace_bpf *obj = btrace_bpf__open();
    if (!obj) {
        fprintf(stderr, "Error: failed to open BPF object\n");
        bt_writer_close(writer, start_ns);
        return 1;
    }

    if (btrace_bpf__load(obj) != 0) {
        fprintf(stderr, "Error: failed to load BPF object: %s\n",
                strerror(errno));
        btrace_bpf__destroy(obj);
        bt_writer_close(writer, start_ns);
        return 1;
    }

    {
        uint32_t key = 0, val = (uint32_t)pid;
        bpf_map__update_elem(obj->maps.target_map, &key, sizeof(key), &val,
                             sizeof(val), BPF_ANY);
    }

    if (btrace_bpf__attach(obj) != 0) {
        fprintf(stderr, "Error: failed to attach BPF programs: %s\n",
                strerror(errno));
        btrace_bpf__destroy(obj);
        bt_writer_close(writer, start_ns);
        return 1;
    }

    fprintf(stderr, "Recording PID %d ... Press Ctrl-C to stop\n", pid);

    struct record_ctx rctx = {.writer = writer};

    struct perf_buffer *pb =
        perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUF_PAGES,
                         perf_event_cb, perf_lost, &rctx, NULL);
    if (!pb) {
        fprintf(stderr, "Error: failed to create perf buffer: %s\n",
                strerror(errno));
        btrace_bpf__destroy(obj);
        bt_writer_close(writer, start_ns);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!stopping) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

    uint64_t end_ns = now_ns();

    fprintf(stderr, "\nFinalizing... \n");

    {
        uint32_t key = 0;
        uint64_t dropped = 0;
        if (bpf_map__lookup_elem(obj->maps.stats_map, &key, sizeof(key),
                                 &dropped, sizeof(dropped), BPF_ANY) == 0 &&
            dropped > 0) {
            fprintf(stderr, "Warning: %llu blocked events dropped\n",
                    (unsigned long long)dropped);
        }
    }

    bt_writer_dump_stacks(writer, bpf_map__fd(obj->maps.stack_map));
    bt_writer_close(writer, end_ns);

    perf_buffer__free(pb);
    btrace_bpf__destroy(obj);

    double dur = (double)(end_ns - start_ns) / 1e9;
    fprintf(stderr, "Done. Duration %.1fs, output: %s\n", dur, output);
    return 0;
}
