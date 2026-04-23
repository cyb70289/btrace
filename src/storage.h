#ifndef STORAGE_H
#define STORAGE_H

#include "btrace.h"
#include <stdio.h>

struct bt_writer *bt_writer_create(const char *path, uint32_t target_pid, uint64_t start_ns);
int bt_writer_event(struct bt_writer *w, uint32_t type, const void *data, uint32_t len);
int bt_writer_dump_stacks(struct bt_writer *w, int map_fd);
int bt_writer_dump_threads(struct bt_writer *w, uint32_t tgid);
int bt_writer_save_file(struct bt_writer *w, const char *path, const char *fallback);
int bt_writer_close(struct bt_writer *w, uint64_t end_ns);

struct bt_reader {
    FILE *fp;
    struct btrace_header hdr;
    u64 *stack_ips;
    int stack_count;
    struct bt_stack_entry *stack_entries;
    struct thread_entry *threads;
    int thread_count;
    char *maps;
    char *kallsyms;
};

struct bt_reader *bt_reader_open(const char *path);
int bt_reader_load_stacks(struct bt_reader *r);
int bt_reader_load_threads(struct bt_reader *r);
int bt_reader_load_maps(struct bt_reader *r);
int bt_reader_load_kallsyms(struct bt_reader *r);
int bt_reader_load_all(struct bt_reader *r);
int bt_reader_get_stack(struct bt_reader *r, int stack_id, u64 **frames, int *nframes);
void bt_reader_close(struct bt_reader *r);

#endif
