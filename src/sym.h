#ifndef SYM_H
#define SYM_H

#include "btrace.h"
#include <stddef.h>

struct sym {
    u64  addr;
    u64  size;
    char *name;
};

struct sym_table {
    struct sym *syms;
    int count;
    int cap;
    char *path;
};

struct sym_cache {
    struct sym_table **tables;
    int count;
    int cap;
};

struct ksym_table {
    struct sym *syms;
    int count;
};

struct maps_entry {
    u64 start;
    u64 end;
    char perms[5];
    u64 offset;
    char path[512];
};

struct maps_parse {
    struct maps_entry *entries;
    int count;
};

void sym_cache_init(struct sym_cache *sc);
void sym_cache_free(struct sym_cache *sc);
struct sym_table *sym_cache_get(struct sym_cache *sc, const char *path);
struct sym_table *sym_load_elf(const char *path);

int ksym_load(struct ksym_table *kt, const char *kallsyms);
void ksym_free(struct ksym_table *kt);
const char *ksym_lookup(struct ksym_table *kt, u64 addr, u64 *offset);

int maps_parse(struct maps_parse *mp, const char *maps_text);
void maps_free(struct maps_parse *mp);
int maps_find(struct maps_parse *mp, u64 addr, struct maps_entry *out);

const char *sym_resolve_user(struct sym_cache *sc, struct maps_parse *mp,
                             u64 addr, char *buf, size_t bufsz);
int sym_resolve_source(const char *binary, u64 addr, char *func, size_t funcsz,
                       char *file, size_t filesz, int *line);

#endif
