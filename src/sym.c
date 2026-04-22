#include "sym.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <gelf.h>

void sym_cache_init(struct sym_cache *sc)
{
    memset(sc, 0, sizeof(*sc));
}

void sym_cache_free(struct sym_cache *sc)
{
    for (int i = 0; i < sc->count; i++) {
        struct sym_table *st = sc->tables[i];
        for (int j = 0; j < st->count; j++)
            free(st->syms[j].name);
        free(st->syms);
        free(st->path);
        free(st);
    }
    free(sc->tables);
}

struct sym_table *sym_cache_get(struct sym_cache *sc, const char *path)
{
    for (int i = 0; i < sc->count; i++) {
        if (strcmp(sc->tables[i]->path, path) == 0)
            return sc->tables[i];
    }
    return NULL;
}

static void cache_insert(struct sym_cache *sc, struct sym_table *st)
{
    if (sc->count >= sc->cap) {
        sc->cap = sc->cap ? sc->cap * 2 : 16;
        sc->tables = realloc(sc->tables, sc->cap * sizeof(struct sym_table *));
    }
    sc->tables[sc->count++] = st;
}

static int sym_cmp(const void *a, const void *b)
{
    const struct sym *sa = a, *sb = b;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return 1;
    return 0;
}

static int load_symtab(Elf *elf, struct sym_table *st, int is_64)
{
    Elf_Scn *scn = NULL;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) return -1;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        char *secname = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!secname) continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;

        size_t entsize = is_64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
        int nsyms = (int)(shdr.sh_size / entsize);

        for (int i = 0; i < nsyms; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, i, &sym) == NULL) continue;

            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                GELF_ST_TYPE(sym.st_info) != STT_OBJECT)
                continue;
            if (sym.st_value == 0) continue;

            if (st->count >= st->cap) {
                st->cap = st->cap ? st->cap * 2 : 256;
                st->syms = realloc(st->syms, st->cap * sizeof(struct sym));
            }

            char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name) continue;

            st->syms[st->count].addr = sym.st_value;
            st->syms[st->count].size = sym.st_size;
            st->syms[st->count].name = strdup(name);
            st->count++;
        }
    }

    if (st->count > 0)
        qsort(st->syms, st->count, sizeof(struct sym), sym_cmp);
    return 0;
}

struct sym_table *sym_load_elf(const char *path)
{
    static int elf_initialized = 0;
    if (!elf_initialized) {
        elf_version(EV_CURRENT);
        elf_initialized = 1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return NULL; }

    struct sym_table *st = calloc(1, sizeof(*st));
    if (!st) { elf_end(elf); close(fd); return NULL; }
    st->path = strdup(path);

    load_symtab(elf, st, 1);
    elf_end(elf);
    close(fd);
    return st;
}

static struct sym_table *get_or_load(struct sym_cache *sc, const char *path)
{
    struct sym_table *st = sym_cache_get(sc, path);
    if (st) return st;

    st = sym_load_elf(path);
    if (st) cache_insert(sc, st);
    return st;
}

static const char *sym_lookup_table(struct sym_table *st, u64 addr, u64 *offset)
{
    if (!st || st->count == 0) return NULL;

    int lo = 0, hi = st->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (st->syms[mid].addr <= addr)
            lo = mid + 1;
        else
            hi = mid - 1;
    }

    if (hi < 0) return NULL;
    struct sym *s = &st->syms[hi];
    if (s->size && addr >= s->addr + s->size) return NULL;
    if (offset) *offset = addr - s->addr;
    return s->name;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static u64 parse_hex(const char **pp)
{
    u64 val = 0;
    const char *p = *pp;
    int d;
    while ((d = hex_val(*p)) >= 0) {
        val = (val << 4) | (u64)d;
        p++;
    }
    *pp = p;
    return val;
}

int ksym_load(struct ksym_table *kt, const char *kallsyms)
{
    if (!kallsyms) return -1;

    kt->count = 0;
    kt->syms = NULL;
    int cap = 0;

    const char *p = kallsyms;
    while (*p) {
        while (*p == '\n' || *p == '\r') p++;
        if (*p == '\0') break;

        u64 addr = parse_hex(&p);

        while (*p == ' ' || *p == '\t') p++;
        if (*p) p++;

        while (*p == ' ' || *p == '\t') p++;

        const char *name_start = p;
        while (*p && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') p++;
        size_t name_len = (size_t)(p - name_start);
        if (name_len == 0) { while (*p && *p != '\n') p++; continue; }

        while (*p && *p != '\n') p++;

        if (kt->count >= cap) {
            cap = cap ? cap * 2 : 4096;
            kt->syms = realloc(kt->syms, cap * sizeof(struct sym));
        }

        kt->syms[kt->count].addr = addr;
        kt->syms[kt->count].size = 0;
        kt->syms[kt->count].name = strndup(name_start, name_len);
        kt->count++;
    }

    return 0;
}

void ksym_free(struct ksym_table *kt)
{
    for (int i = 0; i < kt->count; i++)
        free(kt->syms[i].name);
    free(kt->syms);
}

const char *ksym_lookup(struct ksym_table *kt, u64 addr, u64 *offset)
{
    if (!kt || kt->count == 0) return NULL;

    int lo = 0, hi = kt->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (kt->syms[mid].addr <= addr)
            lo = mid + 1;
        else
            hi = mid - 1;
    }

    if (hi < 0) return NULL;
    if (offset) *offset = addr - kt->syms[hi].addr;
    return kt->syms[hi].name;
}

int maps_parse(struct maps_parse *mp, const char *maps_text)
{
    if (!maps_text) return -1;

    mp->count = 0;
    mp->entries = NULL;
    int cap = 0;

    const char *p = maps_text;
    while (*p) {
        while (*p == '\n') p++;
        if (*p == '\0') break;

        if (mp->count >= cap) {
            cap = cap ? cap * 2 : 64;
            mp->entries = realloc(mp->entries, cap * sizeof(struct maps_entry));
        }

        struct maps_entry *e = &mp->entries[mp->count];
        memset(e, 0, sizeof(*e));

        int n = sscanf(p, "%lx-%lx %4s %lx %*x:%*x %*u %511[^\n]",
                       (unsigned long *)&e->start, (unsigned long *)&e->end,
                       e->perms, (unsigned long *)&e->offset, e->path);
        if (n < 4) { while (*p && *p != '\n') p++; continue; }

        if (e->path[0] == '[') { while (*p && *p != '\n') p++; continue; }

        char *s = e->path;
        while (*s == ' ') s++;
        if (s != e->path) memmove(e->path, s, strlen(s) + 1);

        mp->count++;
        while (*p && *p != '\n') p++;
    }

    return 0;
}

void maps_free(struct maps_parse *mp)
{
    free(mp->entries);
    mp->entries = NULL;
    mp->count = 0;
}

int maps_find(struct maps_parse *mp, u64 addr, struct maps_entry *out)
{
    for (int i = mp->count - 1; i >= 0; i--) {
        if (addr >= mp->entries[i].start && addr < mp->entries[i].end) {
            if (out) *out = mp->entries[i];
            return 0;
        }
    }
    return -1;
}

static const char *base_name(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

const char *sym_resolve_user(struct sym_cache *sc, struct maps_parse *mp,
                             u64 addr, char *buf, size_t bufsz)
{
    struct maps_entry me;
    if (maps_find(mp, addr, &me) < 0) {
        snprintf(buf, bufsz, "0x%lx", (unsigned long)addr);
        return buf;
    }

    const char *bname = base_name(me.path);
    struct sym_table *st = get_or_load(sc, me.path);
    if (!st) {
        snprintf(buf, bufsz, "%s+0x%lx", bname,
                 (unsigned long)(addr - me.start + me.offset));
        return buf;
    }

    u64 file_addr = addr - me.start + me.offset;
    u64 off;
    const char *name = sym_lookup_table(st, file_addr, &off);
    if (name)
        snprintf(buf, bufsz, "%s:%s+0x%lx", bname, name, (unsigned long)off);
    else
        snprintf(buf, bufsz, "%s+0x%lx", bname, (unsigned long)file_addr);

    return buf;
}

const char *sym_resolve_user_src(struct sym_cache *sc, struct maps_parse *mp,
                                 u64 addr, char *buf, size_t bufsz,
                                 char *src, size_t srcsz)
{
    struct maps_entry me;
    if (maps_find(mp, addr, &me) < 0) {
        snprintf(buf, bufsz, "0x%lx", (unsigned long)addr);
        src[0] = '\0';
        return buf;
    }

    const char *bname = base_name(me.path);
    struct sym_table *st = get_or_load(sc, me.path);
    u64 file_addr = addr - me.start + me.offset;

    if (!st) {
        snprintf(buf, bufsz, "%s+0x%lx", bname, (unsigned long)file_addr);
        src[0] = '\0';
        return buf;
    }

    u64 off;
    const char *name = sym_lookup_table(st, file_addr, &off);
    if (name)
        snprintf(buf, bufsz, "%s:%s+0x%lx", bname, name, (unsigned long)off);
    else
        snprintf(buf, bufsz, "%s+0x%lx", bname, (unsigned long)file_addr);

    char afunc[256], afile[256];
    int aline;
    if (sym_resolve_source(me.path, file_addr, afunc, sizeof(afunc),
                           afile, sizeof(afile), &aline) == 0) {
        const char *afbase = base_name(afile);
        if (aline > 0)
            snprintf(src, srcsz, "%s:%d", afbase, aline);
        else
            snprintf(src, srcsz, "%s", afbase);
    } else {
        src[0] = '\0';
    }

    return buf;
}

int sym_resolve_source(const char *binary, u64 addr, char *func, size_t funcsz,
                       char *file, size_t filesz, int *line)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "addr2line -e %s -f 0x%lx 2>/dev/null",
             binary, (unsigned long)addr);

    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    char line1[256] = "", line2[256] = "";
    if (fgets(line1, sizeof(line1), p) == NULL) { pclose(p); return -1; }
    if (fgets(line2, sizeof(line2), p) == NULL) { pclose(p); return -1; }
    pclose(p);

    char *nl = strchr(line1, '\n');
    if (nl) *nl = '\0';
    nl = strchr(line2, '\n');
    if (nl) *nl = '\0';

    if (func && funcsz > 0) {
        strncpy(func, line1, funcsz - 1);
        func[funcsz - 1] = '\0';
    }

    if (file && filesz > 0 && line) {
        char *colon = strrchr(line2, ':');
        if (colon) {
            *colon = '\0';
            strncpy(file, line2, filesz - 1);
            file[filesz - 1] = '\0';
            *line = atoi(colon + 1);
        } else {
            strncpy(file, line2, filesz - 1);
            file[filesz - 1] = '\0';
            *line = 0;
        }
    }

    return 0;
}
