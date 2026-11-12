/*
 * em-trace: transparent Exchange Memory access tracer for the ESP32 BT
 * controller under QEMU.
 *
 * Logs (pc, physical address, EM offset, size, read/write, value) for CPU
 * loads/stores that fall inside the Exchange Memory window
 * 0x3ffb0000-0x3ffb7cd8 (end exclusive).  It is a normal TCG plugin and is
 * only active when loaded with -plugin, so untraced runs are unaffected.
 *
 * The public QEMU 8.0 plugin API does not expose the value of a memory
 * transaction, so the value is recovered on a best-effort basis by calling
 * QEMU's internal address_space_read_full() after the access has executed
 * (the plugin callback is emitted after the load/store op).  That symbol is
 * resolved from the running binary's own .symtab, because it is not part of
 * the public plugin ABI.  Pass value=off to disable the fallback and log
 * only pc/address/size/direction.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <link.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define EM_LO_DEFAULT 0x3ffb0000ULL
#define EM_HI_DEFAULT 0x3ffb7cd8ULL   /* exclusive */

static uint64_t em_lo = EM_LO_DEFAULT;
static uint64_t em_hi = EM_HI_DEFAULT;

typedef struct {
    uint64_t lo;
    uint64_t hi;                      /* exclusive */
} OffRange;

static GArray *ranges;                /* of OffRange, union semantics */
static GHashTable *hist;              /* offset+size -> OffStat */

typedef struct {
    uint64_t reads;
    uint64_t writes;
    uint64_t first;
    uint64_t last;
    unsigned size;
    bool have_val;
} OffStat;

static FILE *out;
static bool out_owned;
static FILE *events;
static bool events_owned;
static GMutex lock;
static bool want_value = true;
static bool want_hist;
static bool verbose;

static uint64_t seq_no;
static uint64_t n_seen;
static uint64_t n_logged;
static uint64_t n_reads;
static uint64_t n_writes;
static uint64_t sample_left;   /* debug: log this many accesses */
static bool sample_near;       /* debug: only sample near the EM window */
static bool use_vaddr = true;  /* filter on the virtual address (EM is identity-mapped) */

/* ------------------------------------------------------------------ */
/* Best-effort guest memory reader (non-public QEMU ABI).             */
/* ------------------------------------------------------------------ */

/*
 * Layout-compatible copy of exec/memattrs.h:MemTxAttrs (QEMU 8.0).
 * Only the `unspecified' bit is set.  The structure is 4 bytes and is
 * passed by value exactly as the real one.
 */
typedef struct {
    unsigned int unspecified:1;
    unsigned int secure:1;
    unsigned int user:1;
    unsigned int memory:1;
    unsigned int requester_id:16;
    unsigned int byte_swap:1;
    unsigned int target_tlb_bit0:1;
    unsigned int target_tlb_bit1:1;
    unsigned int target_tlb_bit2:1;
} EmTxnAttrs;

typedef uint32_t (*em_as_read_fn)(void *as, uint64_t addr, EmTxnAttrs attrs,
                                  void *buf, uint64_t len);

static em_as_read_fn em_as_read;
static void *em_as;
static bool value_ready;

static uint64_t elf_lookup_symbol(const char *wanted)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    struct stat st;
    uint8_t *m;
    Elf64_Ehdr *eh;
    Elf64_Shdr *sh;
    uint64_t result = 0;
    size_t sz;
    ssize_t got;

    if (fd < 0) {
        return 0;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return 0;
    }
    sz = (size_t)st.st_size;
    m = malloc(sz);
    if (!m) {
        close(fd);
        return 0;
    }
    got = read(fd, m, sz);
    close(fd);
    if (got != (ssize_t)sz) {
        free(m);
        return 0;
    }

    eh = (Elf64_Ehdr *)m;
    if (sz < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_shoff == 0 || eh->e_shentsize != sizeof(Elf64_Shdr) ||
        eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > sz) {
        free(m);
        return 0;
    }

    sh = (Elf64_Shdr *)(m + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum && result == 0; i++) {
        Elf64_Sym *syms;
        Elf64_Shdr *strsh;
        const char *str;
        uint64_t cnt;

        if (sh[i].sh_type != SHT_SYMTAB) {
            continue;
        }
        if (sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_link >= eh->e_shnum) {
            continue;
        }
        if (sh[i].sh_offset + sh[i].sh_size > sz) {
            continue;
        }
        syms = (Elf64_Sym *)(m + sh[i].sh_offset);
        cnt = sh[i].sh_size / sizeof(Elf64_Sym);
        strsh = &sh[sh[i].sh_link];
        if (strsh->sh_offset + strsh->sh_size > sz) {
            continue;
        }
        str = (const char *)(m + strsh->sh_offset);
        for (uint64_t j = 0; j < cnt; j++) {
            if (syms[j].st_name == 0 || syms[j].st_name >= strsh->sh_size) {
                continue;
            }
            if (strcmp(str + syms[j].st_name, wanted) == 0) {
                result = syms[j].st_value;
                break;
            }
        }
    }
    free(m);
    return result;
}

struct base_scan {
    bool have_first;
    uintptr_t first;
    bool have_main;
    uintptr_t main;
};

static int base_scan_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    struct base_scan *s = data;

    (void)size;
    if (!s->have_first) {
        s->have_first = true;
        s->first = (uintptr_t)info->dlpi_addr;
    }
    if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        s->have_main = true;
        s->main = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    return 0;
}

static uintptr_t main_load_base(void)
{
    struct base_scan s = { 0 };

    dl_iterate_phdr(base_scan_cb, &s);
    if (s.have_main) {
        return s.main;
    }
    return s.have_first ? s.first : 0;
}

static void init_value_reader(void)
{
    uintptr_t base = main_load_base();
    uint64_t sym_read = elf_lookup_symbol("address_space_read_full");
    uint64_t sym_as = elf_lookup_symbol("address_space_memory");

    if (sym_read != 0 && sym_as != 0) {
        em_as_read = (em_as_read_fn)(uintptr_t)(base + sym_read);
        em_as = (void *)(uintptr_t)(base + sym_as);
        value_ready = true;
    }
    if (verbose) {
        fprintf(stderr,
                "em-trace: value reader %s (base=0x%" PRIxPTR
                " read=0x%" PRIx64 " as=0x%" PRIx64 ")\n",
                value_ready ? "enabled" : "unavailable",
                base, sym_read, sym_as);
    }
}

static bool read_guest(uint64_t addr, unsigned size, uint64_t *val)
{
    uint8_t buf[16];
    EmTxnAttrs attrs;
    uint64_t v = 0;

    if (!value_ready || size == 0 || size > sizeof(buf)) {
        return false;
    }
    memset(&attrs, 0, sizeof(attrs));
    attrs.unspecified = 1;
    memset(buf, 0, sizeof(buf));
    if (em_as_read(em_as, addr, attrs, buf, size) != 0) {
        return false;
    }
    memcpy(&v, buf, size);            /* host and guest are little-endian */
    *val = v;
    return true;
}

static uint64_t bswap_sized(uint64_t v, unsigned size)
{
    switch (size) {
    case 2:
        return GUINT16_SWAP_LE_BE((uint16_t)v);
    case 4:
        return GUINT32_SWAP_LE_BE((uint32_t)v);
    case 8:
        return GUINT64_SWAP_LE_BE(v);
    default:
        return v;
    }
}

/* ------------------------------------------------------------------ */
/* Filtering and statistics.                                          */
/* ------------------------------------------------------------------ */

static bool off_matches(uint64_t off, unsigned size)
{
    uint64_t a = off;
    uint64_t b = off + size;

    if (!ranges || ranges->len == 0) {
        return true;
    }
    for (guint i = 0; i < ranges->len; i++) {
        OffRange *r = &g_array_index(ranges, OffRange, i);
        if (a < r->hi && b > r->lo) {
            return true;
        }
    }
    return false;
}

static gpointer stat_key(uint64_t off, unsigned size)
{
    return GSIZE_TO_POINTER((gsize)((off << 4) | (size & 0xf)));
}

static void hist_update(uint64_t off, unsigned size, bool store,
                        bool have_val, uint64_t val)
{
    gpointer key = stat_key(off, size);
    OffStat *s = g_hash_table_lookup(hist, key);

    if (!s) {
        s = g_new0(OffStat, 1);
        s->first = val;
        s->last = val;
        s->size = size;
        g_hash_table_insert(hist, key, s);
    }
    if (store) {
        s->writes++;
    } else {
        s->reads++;
    }
    if (have_val) {
        if (!s->have_val) {
            s->first = val;
        }
        s->last = val;
        s->have_val = true;
    }
}

/* ------------------------------------------------------------------ */
/* Plugin callbacks.                                                  */
/* ------------------------------------------------------------------ */

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    unsigned shift = qemu_plugin_mem_size_shift(info);
    unsigned size = 1u << shift;
    bool store = qemu_plugin_mem_is_store(info);
    bool big_endian = qemu_plugin_mem_is_big_endian(info);
    uint64_t phys = vaddr;
    uint64_t addr;
    uint64_t off;
    uint64_t val = 0;
    bool have_val;
    struct qemu_plugin_hwaddr *hw;

    (void)cpu_index;

    hw = qemu_plugin_get_hwaddr(info, vaddr);
    if (hw) {
        phys = qemu_plugin_hwaddr_phys_addr(hw);
    }
    addr = use_vaddr ? vaddr : phys;

    if (sample_left != 0 &&
        (!sample_near || (addr >= em_lo - 0x10000 && addr < em_hi + 0x10000))) {
        sample_left--;
        fprintf(stderr,
                "em-trace sample: vaddr=0x%" PRIx64 " phys=0x%" PRIx64
                " pc=0x%" PRIx64 " sz=%u %c\n",
                vaddr, phys, pc, size, store ? 'W' : 'R');
    }

    n_seen++;
    if (addr < em_lo || addr >= em_hi || addr + size > em_hi) {
        return;
    }
    off = addr - em_lo;
    if (!off_matches(off, size)) {
        return;
    }

    have_val = read_guest(vaddr, size, &val);
    if (have_val && big_endian) {
        val = bswap_sized(val, size);
    }

    g_mutex_lock(&lock);
    seq_no++;
    n_logged++;
    if (store) {
        n_writes++;
    } else {
        n_reads++;
    }
    fprintf(out, "%" PRIu64 " pc=0x%" PRIx64 " addr=0x%" PRIx64
            " off=0x%" PRIx64 " sz=%u %c",
            seq_no, pc, vaddr, off, size, store ? 'W' : 'R');
    if (have_val) {
        fprintf(out, " val=0x%" PRIx64 "\n", val);
    } else {
        fprintf(out, " val=?\n");
    }
    if (events) {
        fprintf(events, "{\"v\":1,\"source\":\"qemu\",\"t\":\"em\","
                "\"seq\":%" PRIu64
                ",\"pc\":%" PRIu64 ",\"addr\":%" PRIu64
                ",\"off\":%" PRIu64 ",\"sz\":%u,\"op\":\"%c\"",
                seq_no, pc, vaddr, off, size, store ? 'W' : 'R');
        if (have_val) {
            fprintf(events, ",\"value\":%" PRIu64 "}\n", val);
        } else {
            fputs(",\"value\":null}\n", events);
        }
    }
    if (want_hist) {
        hist_update(off, size, store, have_val, val);
    }
    g_mutex_unlock(&lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    (void)id;
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);

        /*
         * The instruction address is passed back as userdata, so the memory
         * callback knows the PC without a second per-instruction callback.
         */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW,
                                         (void *)(uintptr_t)pc);
    }
}

static gint cmp_u64(gconstpointer a, gconstpointer b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : (x > y ? 1 : 0);
}

static void dump_hist(void)
{
    GList *keys;
    GArray *sorted;
    GList *it;

    if (!hist) {
        return;
    }
    fprintf(out, "# histogram: off size reads writes first last\n");
    keys = g_hash_table_get_keys(hist);
    sorted = g_array_new(FALSE, FALSE, sizeof(uint64_t));
    for (it = keys; it != NULL; it = it->next) {
        uint64_t k = (uint64_t)(uintptr_t)it->data;
        g_array_append_val(sorted, k);
    }
    g_list_free(keys);
    g_array_sort(sorted, cmp_u64);
    for (guint i = 0; i < sorted->len; i++) {
        uint64_t k = g_array_index(sorted, uint64_t, i);
        OffStat *s = g_hash_table_lookup(hist, GSIZE_TO_POINTER((gsize)k));
        uint64_t off = k >> 4;
        unsigned size = (unsigned)(k & 0xf);

        if (!s) {
            continue;
        }
        fprintf(out, "0x%04" PRIx64 " %u %" PRIu64 " %" PRIu64,
                off, size, s->reads, s->writes);
        if (s->have_val) {
            fprintf(out, " 0x%" PRIx64 " 0x%" PRIx64 "\n", s->first, s->last);
        } else {
            fprintf(out, " - -\n");
        }
    }
    g_array_free(sorted, TRUE);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    (void)id;
    (void)p;
    g_mutex_lock(&lock);
    if (want_hist) {
        dump_hist();
    }
    fprintf(out, "# em-trace summary: seen=%" PRIu64 " logged=%" PRIu64
            " reads=%" PRIu64 " writes=%" PRIu64
            " lo=0x%" PRIx64 " hi=0x%" PRIx64
            " value=%s\n",
            n_seen, n_logged, n_reads, n_writes, em_lo, em_hi,
            value_ready ? "on" : "off");
    fflush(out);
    if (events) {
        fflush(events);
    }
    if (out_owned) {
        fclose(out);
        out = NULL;
        out_owned = false;
    }
    if (events_owned) {
        fclose(events);
        events = NULL;
        events_owned = false;
    }
    g_mutex_unlock(&lock);
}

/* ------------------------------------------------------------------ */
/* Option parsing and install.                                        */
/* ------------------------------------------------------------------ */

static uint64_t parse_u64(const char *s)
{
    return g_ascii_strtoull(s, NULL, 0);
}

static void add_range(const char *s)
{
    const char *dash = strchr(s, '-');
    OffRange r;

    if (dash) {
        char *lo = g_strndup(s, (gsize)(dash - s));
        r.lo = parse_u64(lo);
        r.hi = parse_u64(dash + 1);
        g_free(lo);
    } else {
        r.lo = parse_u64(s);
        r.hi = r.lo + 1;
    }
    if (r.hi <= r.lo) {
        r.hi = r.lo + 1;
    }
    if (!ranges) {
        ranges = g_array_new(FALSE, FALSE, sizeof(OffRange));
    }
    g_array_append_val(ranges, r);
}

static void usage(void)
{
    fprintf(stderr,
        "em-trace options:\n"
        "  lo=ADDR            EM base (default 0x3ffb0000)\n"
        "  hi=ADDR            EM end, exclusive (default 0x3ffb7cd8)\n"
        "  range=LO-HI        log only this EM-offset range (repeatable)\n"
        "  offset=OFF         log only accesses at this EM offset (repeatable)\n"
        "  value=on|off       best-effort value recovery (default on)\n"
        "  hist=on|off        per-offset histogram at exit (default off)\n"
        "  out=PATH           write the trace here (default stderr)\n"
        "  events=PATH        write typed NDJSON records here (default off)\n"
        "  vaddr=on|off       filter on vaddr (default on) or QEMU phys\n"
        "  verbose            print setup diagnostics to stderr\n");
}

static bool parse_bool(const char *s, bool *outv)
{
    if (g_ascii_strcasecmp(s, "on") == 0 ||
        g_ascii_strcasecmp(s, "yes") == 0 ||
        g_ascii_strcasecmp(s, "true") == 0 ||
        strcmp(s, "1") == 0) {
        *outv = true;
        return true;
    }
    if (g_ascii_strcasecmp(s, "off") == 0 ||
        g_ascii_strcasecmp(s, "no") == 0 ||
        g_ascii_strcasecmp(s, "false") == 0 ||
        strcmp(s, "0") == 0) {
        *outv = false;
        return true;
    }
    return false;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv);

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;

    g_mutex_init(&lock);
    out = stderr;

    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) tokens = g_strsplit(argv[i], "=", 2);
        const char *key = tokens[0];
        const char *val = tokens[1];

        if (g_strcmp0(key, "lo") == 0 && val) {
            em_lo = parse_u64(val);
        } else if (g_strcmp0(key, "hi") == 0 && val) {
            em_hi = parse_u64(val);
        } else if (g_strcmp0(key, "range") == 0 && val) {
            add_range(val);
        } else if ((g_strcmp0(key, "offset") == 0 ||
                    g_strcmp0(key, "desc") == 0) && val) {
            add_range(val);
        } else if (g_strcmp0(key, "value") == 0 && val) {
            if (!parse_bool(val, &want_value)) {
                fprintf(stderr, "em-trace: bad value= option: %s\n", val);
                return -1;
            }
        } else if (g_strcmp0(key, "hist") == 0 && val) {
            if (!parse_bool(val, &want_hist)) {
                fprintf(stderr, "em-trace: bad hist= option: %s\n", val);
                return -1;
            }
        } else if (g_strcmp0(key, "out") == 0 && val) {
            out = fopen(val, "w");
            if (!out) {
                fprintf(stderr, "em-trace: cannot open %s\n", val);
                return -1;
            }
            out_owned = true;
        } else if (g_strcmp0(key, "events") == 0 && val) {
            events = fopen(val, "w");
            if (!events) {
                fprintf(stderr, "em-trace: cannot open events file %s\n", val);
                return -1;
            }
            events_owned = true;
        } else if (g_strcmp0(key, "sample") == 0 && val) {
            sample_left = parse_u64(val);
        } else if (g_strcmp0(key, "near") == 0 && val) {
            if (!parse_bool(val, &sample_near)) {
                fprintf(stderr, "em-trace: bad near= option: %s\n", val);
                return -1;
            }
        } else if (g_strcmp0(key, "vaddr") == 0 && val) {
            if (!parse_bool(val, &use_vaddr)) {
                fprintf(stderr, "em-trace: bad vaddr= option: %s\n", val);
                return -1;
            }
        } else if (g_strcmp0(key, "verbose") == 0) {
            verbose = true;
        } else if (g_strcmp0(key, "help") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "em-trace: unknown option: %s\n", argv[i]);
            usage();
            return -1;
        }
    }

    if (em_hi <= em_lo) {
        fprintf(stderr, "em-trace: empty EM range\n");
        return -1;
    }
    if (want_hist) {
        hist = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    }
    if (want_value) {
        init_value_reader();
    }
    if (verbose) {
        fprintf(stderr,
                "em-trace: EM 0x%" PRIx64 "-0x%" PRIx64
                " (exclusive), value=%s hist=%s ranges=%u\n",
                em_lo, em_hi, value_ready ? "on" : "off",
                want_hist ? "on" : "off",
                ranges ? ranges->len : 0);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
