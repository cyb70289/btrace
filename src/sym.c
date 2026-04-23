#include "sym.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <gelf.h>
#include <sys/wait.h>

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

static int find_build_id(Elf *elf, char *out, size_t outsz)
{
    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) != 0) return -1;

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, (int)i, &phdr) == NULL) continue;
        if (phdr.p_type != PT_NOTE || phdr.p_filesz == 0) continue;

        Elf_Scn *scn = gelf_offscn(elf, (GElf_Off)phdr.p_offset);
        if (!scn) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;

        size_t off = 0;
        while (off < data->d_size) {
            GElf_Nhdr nhdr;
            size_t name_off, desc_off;
            off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off);
            if (off == 0) break;
            if (nhdr.n_type == 3 && nhdr.n_descsz > 0 && nhdr.n_descsz <= 32) {
                const uint8_t *desc = (const uint8_t *)data->d_buf + desc_off;
                char *p = out;
                size_t left = outsz;
                for (size_t j = 0; j < nhdr.n_descsz && left >= 3; j++) {
                    p += snprintf(p, left, "%02x", desc[j]);
                    left = outsz - (size_t)(p - out);
                }
                return 0;
            }
        }
    }
    return -1;
}

static int load_debug_by_buildid(const char *path, struct sym_table *st)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return -1; }

    char buildid[68] = {};
    if (find_build_id(elf, buildid, sizeof(buildid)) != 0) {
        elf_end(elf); close(fd); return -1;
    }
    elf_end(elf);
    close(fd);

    char dbgpath[512];
    snprintf(dbgpath, sizeof(dbgpath),
             "/usr/lib/debug/.build-id/%.2s/%s.debug", buildid, buildid + 2);

    fd = open(dbgpath, O_RDONLY);
    if (fd < 0) return -1;

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return -1; }

    load_symtab(elf, st, 1);
    elf_end(elf);
    close(fd);
    return st->count > 0 ? 0 : -1;
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

    load_debug_by_buildid(path, st);

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

        if (e->path[0] == '[') {
            if (strncmp(e->path, "[vdso]", 6) != 0 &&
                strncmp(e->path, "[vvar]", 6) != 0) {
                while (*p && *p != '\n') p++;
                continue;
            }
        }

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
    int lo = 0, hi = mp->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr >= mp->entries[mid].start && addr < mp->entries[mid].end) {
            if (out) *out = mp->entries[mid];
            return 0;
        }
        if (addr < mp->entries[mid].start)
            hi = mid - 1;
        else
            lo = mid + 1;
    }
    return -1;
}

static const char *base_name(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static FILE *cplusfilt_in = NULL;
static FILE *cplusfilt_out = NULL;
static pid_t cplusfilt_pid = 0;

static void demangle_init(void)
{
    if (cplusfilt_pid) return;
    int pin[2], pout[2];
    if (pipe(pin) < 0 || pipe(pout) < 0) return;
    cplusfilt_pid = fork();
    if (cplusfilt_pid < 0) return;
    if (cplusfilt_pid == 0) {
        close(pin[1]); close(pout[0]);
        dup2(pin[0], 0); dup2(pout[1], 1);
        close(pin[0]); close(pout[1]);
        execlp("c++filt", "c++filt", "-p", NULL);
        _exit(1);
    }
    close(pin[0]); close(pout[1]);
    cplusfilt_in = fdopen(pin[1], "w");
    cplusfilt_out = fdopen(pout[0], "r");
}

static void demangle(const char *mangled, char *out, size_t outsz)
{
    if (!mangled) {
        snprintf(out, outsz, "%s", mangled);
        return;
    }
    const char *p = mangled;
    while (*p == '_') p++;
    if (*p != 'Z') {
        snprintf(out, outsz, "%s", mangled);
        return;
    }

    demangle_init();
    if (!cplusfilt_in || !cplusfilt_out) {
        snprintf(out, outsz, "%s", mangled);
        return;
    }

    fprintf(cplusfilt_in, "%s\n", mangled);
    fflush(cplusfilt_in);

    if (!fgets(out, (int)outsz, cplusfilt_out))
        snprintf(out, outsz, "%s", mangled);
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
}

struct a2l_cache_entry {
    char path[512];
    int has_source;
};

static struct a2l_cache_entry *a2l_cache;
static int a2l_cache_count;
static int a2l_cache_cap;

static int a2l_known_no_source(const char *path)
{
    for (int i = 0; i < a2l_cache_count; i++) {
        if (strcmp(a2l_cache[i].path, path) == 0)
            return !a2l_cache[i].has_source;
    }
    return 0;
}

static void a2l_mark_source(const char *path, int has_source)
{
    for (int i = 0; i < a2l_cache_count; i++) {
        if (strcmp(a2l_cache[i].path, path) == 0) {
            if (has_source) a2l_cache[i].has_source = 1;
            return;
        }
    }
    if (a2l_cache_count >= a2l_cache_cap) {
        a2l_cache_cap = a2l_cache_cap ? a2l_cache_cap * 2 : 16;
        a2l_cache = realloc(a2l_cache, (size_t)a2l_cache_cap * sizeof(*a2l_cache));
    }
    snprintf(a2l_cache[a2l_cache_count].path, sizeof(a2l_cache[a2l_cache_count].path), "%s", path);
    a2l_cache[a2l_cache_count].has_source = has_source;
    a2l_cache_count++;
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
    if (name) {
        char dname[256];
        demangle(name, dname, sizeof(dname));
        snprintf(buf, bufsz, "%s:%s+0x%lx", bname, dname, (unsigned long)off);
    } else
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
    if (name) {
        char dname[256];
        demangle(name, dname, sizeof(dname));
        snprintf(buf, bufsz, "%s:%s+0x%lx", bname, dname, (unsigned long)off);
    } else
        snprintf(buf, bufsz, "%s+0x%lx", bname, (unsigned long)file_addr);

    char afunc[256], afile[256];
    int aline;
    const char *a2l_binary = me.path;
    if (st && st->count > 0 && st->path && strcmp(st->path, me.path) != 0)
        a2l_binary = st->path;

    src[0] = '\0';
    if (!a2l_known_no_source(a2l_binary)) {
        if (sym_resolve_source(a2l_binary, file_addr, afunc, sizeof(afunc),
                               afile, sizeof(afile), &aline) == 0) {
            const char *afbase = base_name(afile);
            int useful = 0;
            if (aline > 0) {
                snprintf(src, srcsz, "%s:%d", afbase, aline);
                useful = 1;
            } else if (afbase[0] && afbase[0] != '?') {
                snprintf(src, srcsz, "%s", afbase);
                useful = 1;
            }
            if (useful)
                a2l_mark_source(a2l_binary, 1);
            else
                a2l_mark_source(a2l_binary, 0);
        } else {
            a2l_mark_source(a2l_binary, 0);
        }
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
