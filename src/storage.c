#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <bpf/bpf.h>

struct bt_writer {
    FILE *fp;
    struct btrace_header hdr;
    uint64_t events_count;

    char *maps_data;
    size_t maps_len;

    struct thread_entry *threads;
    uint32_t num_threads;
};

static int read_proc_file(const char *path, char **out, size_t *out_len)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return -1; }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); fclose(f); return -1; }
            buf = tmp;
        }
    }
    fclose(f);
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 0;
}

struct bt_writer *bt_writer_create(const char *path, uint32_t target_pid, uint64_t start_ns)
{
    struct bt_writer *w = calloc(1, sizeof(*w));
    if (!w) return NULL;

    w->fp = fopen(path, "wb");
    if (!w->fp) {
        free(w);
        return NULL;
    }

    memset(&w->hdr, 0, sizeof(w->hdr));
    memcpy(w->hdr.magic, BTRACE_MAGIC, 4);
    w->hdr.version = BTRACE_VERSION;
    w->hdr.target_pid = target_pid;
    w->hdr.start_time_ns = start_ns;
    w->hdr.events_off = BTRACE_HDR_SIZE;

    if (fseek(w->fp, BTRACE_HDR_SIZE, SEEK_SET) != 0) {
        fclose(w->fp);
        free(w);
        return NULL;
    }

    w->events_count = 0;

    {
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", target_pid);
        read_proc_file(maps_path, &w->maps_data, &w->maps_len);
    }

    {
        char task_path[256];
        snprintf(task_path, sizeof(task_path), "/proc/%u/task", target_pid);
        DIR *d = opendir(task_path);
        if (d) {
            uint32_t cap = 32;
            w->threads = calloc(cap, sizeof(struct thread_entry));
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                char *end;
                uint32_t tid = (uint32_t)strtoul(de->d_name, &end, 10);
                if (*end != '\0') continue;

                if (w->num_threads >= cap) {
                    cap *= 2;
                    w->threads = realloc(w->threads, cap * sizeof(struct thread_entry));
                }

                struct thread_entry *te = &w->threads[w->num_threads];
                te->tid = tid;
                te->tgid = target_pid;
                char comm_path[256];
                snprintf(comm_path, sizeof(comm_path), "/proc/%u/task/%u/comm", target_pid, tid);
                FILE *cf = fopen(comm_path, "r");
                if (cf) {
                    if (fgets(te->comm, COMM_LEN, cf)) {
                        char *nl = strchr(te->comm, '\n');
                        if (nl) *nl = '\0';
                    }
                    fclose(cf);
                }
                w->num_threads++;
            }
            closedir(d);
        }
    }

    w->hdr.num_threads = w->num_threads;

    return w;
}

int bt_writer_event(struct bt_writer *w, uint32_t type, const void *data, uint32_t len)
{
    if (!w || !w->fp) return -1;
    if (fwrite(&type, sizeof(type), 1, w->fp) != 1) return -1;
    if (fwrite(&len, sizeof(len), 1, w->fp) != 1) return -1;
    if (fwrite(data, 1, len, w->fp) != len) return -1;
    w->events_count++;
    return 0;
}

int bt_writer_dump_stacks(struct bt_writer *w, int map_fd)
{
    if (!w || !w->fp) return -1;

    w->hdr.stacks_off = (uint64_t)ftell(w->fp);
    uint32_t count = 0;

    struct {
        uint32_t id;
        uint64_t ips[MAX_STACK_DEPTH];
    } val;

    uint32_t key = 0, next_key;
    bool has_first = true;

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) != 0)
        has_first = false;

    while (has_first) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            int nframes = 0;
            for (int i = 0; i < MAX_STACK_DEPTH; i++) {
                if (val.ips[i] == 0) break;
                nframes++;
            }
            struct bt_stack_entry se = { .stack_id = (int32_t)next_key, .num_frames = (uint32_t)nframes };
            fwrite(&se, sizeof(se), 1, w->fp);
            fwrite(val.ips, sizeof(uint64_t), nframes, w->fp);
            count++;
        }
        key = next_key;
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0)
            break;
    }

    w->hdr.num_stacks = count;
    return 0;
}

int bt_writer_close(struct bt_writer *w, uint64_t end_ns)
{
    if (!w || !w->fp) return -1;

    w->hdr.threads_off = (uint64_t)ftell(w->fp);
    if (w->threads && w->num_threads > 0)
        fwrite(w->threads, sizeof(struct thread_entry), w->num_threads, w->fp);

    w->hdr.maps_off = (uint64_t)ftell(w->fp);
    if (w->maps_data && w->maps_len > 0)
        fwrite(w->maps_data, 1, w->maps_len, w->fp);
    char zero = 0;
    fwrite(&zero, 1, 1, w->fp);

    w->hdr.kallsyms_off = (uint64_t)ftell(w->fp);
    {
        char *ksyms = NULL;
        size_t kslen = 0;
        if (read_proc_file("/proc/kallsyms", &ksyms, &kslen) == 0 && ksyms) {
            fwrite(ksyms, 1, kslen, w->fp);
            free(ksyms);
        }
    }

    w->hdr.end_time_ns = end_ns;
    w->hdr.num_events = w->events_count;

    fseek(w->fp, 0, SEEK_SET);
    fwrite(&w->hdr, sizeof(w->hdr), 1, w->fp);
    fclose(w->fp);

    free(w->maps_data);
    free(w->threads);
    free(w);
    return 0;
}

struct bt_reader *bt_reader_open(const char *path)
{
    struct bt_reader *r = calloc(1, sizeof(*r));
    if (!r) return NULL;

    r->fp = fopen(path, "rb");
    if (!r->fp) { free(r); return NULL; }

    if (fread(&r->hdr, sizeof(r->hdr), 1, r->fp) != 1) {
        fclose(r->fp);
        free(r);
        return NULL;
    }

    if (memcmp(r->hdr.magic, BTRACE_MAGIC, 4) != 0) {
        fprintf(stderr, "Invalid btrace file (bad magic)\n");
        fclose(r->fp);
        free(r);
        return NULL;
    }

    if (r->hdr.version != BTRACE_VERSION) {
        fprintf(stderr, "Unsupported btrace version %u\n", r->hdr.version);
        fclose(r->fp);
        free(r);
        return NULL;
    }

    return r;
}

int bt_reader_load_stacks(struct bt_reader *r)
{
    if (!r || r->hdr.stacks_off == 0) return -1;

    fseek(r->fp, (long)r->hdr.stacks_off, SEEK_SET);

    r->stack_entries = calloc(r->hdr.num_stacks, sizeof(struct bt_stack_entry));
    if (!r->stack_entries) return -1;

    size_t ips_cap = (size_t)r->hdr.num_stacks * 8;
    if (ips_cap == 0) ips_cap = 256;
    r->stack_ips = calloc(ips_cap, sizeof(u64));
    if (!r->stack_ips) return -1;
    size_t ips_count = 0;

    for (uint32_t i = 0; i < r->hdr.num_stacks; i++) {
        if (fread(&r->stack_entries[i], sizeof(struct bt_stack_entry), 1, r->fp) != 1)
            return -1;
        u32 nf = r->stack_entries[i].num_frames;
        if (nf > MAX_STACK_DEPTH) return -1;
        while (ips_count + nf > ips_cap) {
            ips_cap *= 2;
            u64 *tmp = realloc(r->stack_ips, ips_cap * sizeof(u64));
            if (!tmp) return -1;
            r->stack_ips = tmp;
        }
        if (nf > 0 && fread(r->stack_ips + ips_count, sizeof(u64), nf, r->fp) != nf)
            return -1;
        ips_count += nf;
    }

    r->stack_count = (int)r->hdr.num_stacks;

    r->stack_id_to_idx = calloc(MAX_STACK_MAP, sizeof(int));
    if (r->stack_id_to_idx) {
        size_t ip_off = 0;
        for (int i = 0; i < r->stack_count; i++) {
            int id = r->stack_entries[i].stack_id;
            if (id >= 0 && id < MAX_STACK_MAP)
                r->stack_id_to_idx[id] = (int)(ip_off + 1);
            ip_off += r->stack_entries[i].num_frames;
        }
    }
    return 0;
}

int bt_reader_load_threads(struct bt_reader *r)
{
    if (!r || r->hdr.threads_off == 0 || r->hdr.num_threads == 0) return -1;

    fseek(r->fp, (long)r->hdr.threads_off, SEEK_SET);

    r->threads = calloc(r->hdr.num_threads, sizeof(struct thread_entry));
    if (!r->threads) return -1;

    if (fread(r->threads, sizeof(struct thread_entry), r->hdr.num_threads, r->fp)
        != r->hdr.num_threads)
        return -1;

    r->thread_count = (int)r->hdr.num_threads;
    return 0;
}

static char *read_section(struct bt_reader *r, uint64_t offset, uint64_t next_offset)
{
    if (offset == 0) return NULL;
    if (next_offset != 0 && offset >= next_offset) return NULL;

    fseek(r->fp, (long)offset, SEEK_SET);

    long len;
    if (next_offset != 0) {
        len = (long)(next_offset - offset);
    } else {
        long start = ftell(r->fp);
        fseek(r->fp, 0, SEEK_END);
        long end = ftell(r->fp);
        fseek(r->fp, start, SEEK_SET);
        len = end - start;
    }

    if (len <= 0) return NULL;
    char *buf = calloc(1, (size_t)len + 1);
    if (!buf) return NULL;
    if (fread(buf, 1, (size_t)len, r->fp) != (size_t)len) {
        free(buf);
        return NULL;
    }
    return buf;
}

int bt_reader_load_maps(struct bt_reader *r)
{
    r->maps = read_section(r, r->hdr.maps_off, r->hdr.kallsyms_off);
    return r->maps ? 0 : -1;
}

int bt_reader_load_kallsyms(struct bt_reader *r)
{
    r->kallsyms = read_section(r, r->hdr.kallsyms_off, 0);
    return r->kallsyms ? 0 : -1;
}

int bt_reader_load_all(struct bt_reader *r)
{
    int rc = 0;
    if (bt_reader_load_stacks(r) < 0) rc = -1;
    if (bt_reader_load_threads(r) < 0) rc = -1;
    if (bt_reader_load_maps(r) < 0) rc = -1;
    if (bt_reader_load_kallsyms(r) < 0) rc = -1;
    return rc;
}

int bt_reader_get_stack(struct bt_reader *r, int stack_id, u64 **frames, int *nframes)
{
    if (!r || stack_id < 0) return -1;

    if (r->stack_id_to_idx && stack_id < MAX_STACK_MAP) {
        int off = r->stack_id_to_idx[stack_id];
        if (off > 0) {
            for (int i = 0; i < r->stack_count; i++) {
                if (r->stack_entries[i].stack_id == stack_id) {
                    *frames = r->stack_ips + (off - 1);
                    *nframes = (int)r->stack_entries[i].num_frames;
                    return 0;
                }
            }
        }
    }

    size_t ip_off = 0;
    for (int i = 0; i < r->stack_count; i++) {
        if (r->stack_entries[i].stack_id == stack_id) {
            *frames = r->stack_ips + ip_off;
            *nframes = (int)r->stack_entries[i].num_frames;
            return 0;
        }
        ip_off += r->stack_entries[i].num_frames;
    }
    return -1;
}

void bt_reader_close(struct bt_reader *r)
{
    if (!r) return;
    if (r->fp) fclose(r->fp);
    free(r->stack_ips);
    free(r->stack_entries);
    free(r->stack_id_to_idx);
    free(r->threads);
    free(r->maps);
    free(r->kallsyms);
    free(r);
}
