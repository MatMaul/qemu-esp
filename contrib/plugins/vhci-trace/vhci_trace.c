/*
 * vhci-trace: in-process VHCI H2C/C2H packet capture for the ESP32 BT model.
 *
 * A gdb breakpoint on every VHCI access slows the guest by an order of
 * magnitude.  That matters for the deterministic model clock: `bt-clock=model`
 * advances from the executed-instruction count while the guest's own timers
 * still advance with host virtual time, so a breakpoint desynchronises the two
 * clocks and the host stack cancels the inquiry before the modelled result
 * arrives.  This TCG plugin observes the same events without stopping the CPU.
 *
 * Three hooks, all cheap enough to leave the event timing intact:
 *
 *   stage=ADDR,stage-end=ADDR
 *       Guest stores inside the host VHCI staging function are sampled.  The
 *       controller's staging window (`env+0x28`, `env+0x4d8`, `env+0x4dc`) is
 *       short; a translation-block sampler misses it, a store callback does
 *       not.  The full packet is emitted once the staging write is complete.
 *
 *   send=ADDR
 *       The controller-to-host entry (`vhci_send`) is hooked at instruction
 *       granularity.  Its arguments are $a2 (buffer) and $a3 (length).  The
 *       public plugin ABI has no register read (QEMU 8.0), so the plugin
 *       resolves `qemu_get_cpu` from the running binary and reads the Xtensa
 *       register window from the CPU state:
 *
 *           CPUState *cpu = qemu_get_cpu(cpu_index);
 *           env  = *(void **)((char *)cpu + CPU_ENV_PTR_OFFSET);
 *           aN   = *(uint32_t *)((char *)env + CPU_REGS_OFFSET + 4 * N);
 *
 *       The offsets (544 and 8) come from the QEMU build's DWARF for
 *       CPUState.env_ptr and CPUArchState.regs.  This is QEMU-internal and is
 *       deliberately limited to reading two argument registers; override the
 *       offsets with env-ptr-offset= / regs-offset= when the QEMU build changes.
 *
 *   isr=ADDR (optional)
 *       The first execution of r_ld_fm_frame_isr emits the same RXFM status,
 *       current-descriptor and queue words as the historical gdb pass.
 *
 * Guest memory is read through QEMU's address_space_read_full(), resolved from
 * the running binary's own symbol table too (same approach as
 * contrib/plugins/em-trace).
 *
 * Usage:
 *   -plugin libvhci_trace.so,env=0xADDR,out=FILE[,verbose] \
 *       [,stage=0xADDR,stage-end=0xADDR] \
 *       [,send=0xADDR,arg-buf-index=2,arg-len-index=3] \
 *       [,env-ptr-offset=544,regs-offset=8] \
 *       [,isr=0xADDR,isr-status=0xADDR,isr-current=0xADDR,isr-queue=0xADDR,isr-desc=0xADDR]
 *
 * License: GNU GPL, version 2 or later.
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

#define VHCI_MIN(a, b) ((a) < (b) ? (a) : (b))

/* QEMU's address_space_read_full() signature for system emulation. */
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
} VhciAttrs;

typedef uint32_t (*as_read_fn)(void *as, uint64_t addr, VhciAttrs attrs,
                               void *buf, uint64_t len);
typedef void *(*get_cpu_fn)(int cpu_index);
typedef void (*anchor_fn_t)(void);

static as_read_fn as_read;
static void *as_memory;
static get_cpu_fn get_cpu;
static anchor_fn_t anchor_fn;
static bool reader_ready;

static uint64_t env_addr;
static uint64_t stage_addr;
static uint64_t stage_end;
static uint64_t send_addr;
static uint64_t isr_addr;
static uint64_t isr_status;
static uint64_t isr_current;
static uint64_t isr_queue;
static uint64_t isr_desc;
static unsigned long env_ptr_offset = 544;
static unsigned long regs_offset = 8;
static int arg_buf_index = 2;
static int arg_len_index = 3;

static FILE *out;
static bool out_owned;
static bool verbose;
static GMutex lock;
static uint64_t samples;
static uint32_t h2c_key;
static bool isr_dumped;

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
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_shoff == 0 ||
        eh->e_shentsize != sizeof(Elf64_Shdr) ||
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

        if (sh[i].sh_type != SHT_SYMTAB ||
            sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_link >= eh->e_shnum ||
            sh[i].sh_offset + sh[i].sh_size > sz) {
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
    return s.have_main ? s.main : (s.have_first ? s.first : 0);
}

static void init_reader(void)
{
    uintptr_t base = main_load_base();
    uint64_t sym_read = elf_lookup_symbol("address_space_read_full");
    uint64_t sym_as = elf_lookup_symbol("address_space_memory");

    if (sym_read != 0 && sym_as != 0) {
        as_read = (as_read_fn)(uintptr_t)(base + sym_read);
        as_memory = (void *)(uintptr_t)(base + sym_as);
        reader_ready = true;
    }

    {
        uint64_t sym_anchor =
            elf_lookup_symbol("esp32_bt_model_anchor_from_plugin");

        if (sym_anchor != 0) {
            anchor_fn = (anchor_fn_t)(uintptr_t)(base + sym_anchor);
        }
    }

    if (send_addr) {
        uint64_t sym_cpu = elf_lookup_symbol("qemu_get_cpu");

        if (sym_cpu != 0) {
            get_cpu = (get_cpu_fn)(uintptr_t)(base + sym_cpu);
        }
        if (verbose) {
            fprintf(stderr, "vhci-trace: qemu_get_cpu=0x%" PRIx64 "\n", sym_cpu);
        }
    }

    if (verbose) {
        fprintf(stderr, "vhci-trace: reader %s base=0x%" PRIxPTR
                " read=0x%" PRIx64 " as=0x%" PRIx64 "\n",
                reader_ready ? "enabled" : "unavailable", base, sym_read, sym_as);
    }
}

static bool read_guest(uint64_t addr, void *buf, unsigned int len)
{
    VhciAttrs attrs;

    if (!reader_ready || !addr || !len) {
        return false;
    }
    memset(&attrs, 0, sizeof(attrs));
    attrs.unspecified = 1;
    return as_read(as_memory, addr, attrs, buf, len) == 0;
}

static uint32_t u32_at(uint64_t addr)
{
    uint32_t v = 0;

    read_guest(addr, &v, sizeof(v));
    return v;
}

static uint16_t u16_at(uint64_t addr)
{
    uint16_t v = 0;

    read_guest(addr, &v, sizeof(v));
    return v;
}

/*
 * Read a guest register from the executing vCPU.  This is the only non-public
 * access in the plugin: QEMU 8.0 has no plugin register API, and the guest's
 * $a2/$a3 are the only values the VHCI event entry exposes without stopping
 * the CPU.  The offsets are documented at the top of this file.
 */
static bool read_arg(unsigned int cpu_index, int index, uint32_t *value)
{
    void *cpu;
    void *env;

    if (!get_cpu) {
        return false;
    }
    cpu = get_cpu((int)cpu_index);
    if (!cpu) {
        return false;
    }
    env = *(void **)((char *)cpu + env_ptr_offset);
    if (!env) {
        return false;
    }
    *value = *(uint32_t *)((char *)env + regs_offset + 4 * index);
    return true;
}

static uint32_t packet_key(const uint8_t *buf, uint32_t len)
{
    uint32_t h = 2166136261u;
    uint32_t n = VHCI_MIN(len, 24u);

    for (uint32_t i = 0; i < n; i++) {
        h = (h ^ buf[i]) * 16777619u;
    }
    return h ^ (len * 2654435761u);
}

static void emit(const char *dir, uint64_t addr, uint32_t len)
{
    uint8_t buf[256];
    uint32_t n = VHCI_MIN(len, sizeof(buf));
    uint32_t i;

    if (!read_guest(addr, buf, n)) {
        return;
    }
    fprintf(out, "%s len=%u", dir, len);
    for (i = 0; i < n; i++) {
        fprintf(out, " %02x", buf[i]);
    }
    fprintf(out, "\n%s len=%u hdr=%02x %02x %02x\n", dir, len, buf[0],
            n > 1 ? buf[1] : 0, n > 2 ? buf[2] : 0);
    fprintf(out, "%s dump", dir);
    for (i = 0; i < n; i++) {
        fprintf(out, " 0x%02x", buf[i]);
    }
    fprintf(out, "\n");
    fflush(out);
}

/*
 * H2C: the host staging function copies the packet into the controller's VHCI
 * env (+0x28) and then stores the count (+0x4d8) and offset (+0x4dc).  Sample
 * after any staging store; emit the full packet once offset is zero.
 */
static void sample_h2c(void)
{
    uint32_t env, count, offset, key;
    uint8_t head[24];

    env = u32_at(env_addr);
    if (!env) {
        return;
    }
    count = u32_at(env + 0x4d8);
    offset = u32_at(env + 0x4dc);
    if (offset == 0 && count > 0 && count < 4096) {
        read_guest(env + 0x28, head, VHCI_MIN(count, sizeof(head)));
        /*
         * The model's own VHCI sampler can miss this short staging window.
         * Tell the deterministic clock that HCI_Inquiry has arrived so it can
         * anchor its instruction-count base (bt-clock-anchor=inquiry).
         */
        if (anchor_fn && count >= 3 && head[0] == 0x01 && head[1] == 0x01 &&
            head[2] == 0x04) {
            anchor_fn();
        }
        key = packet_key(head, count);
        if (key != h2c_key) {
            h2c_key = key;
            emit("H2C", env + 0x28, count);
        }
    } else {
        h2c_key = 0;
    }
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    (void)cpu_index;
    (void)info;
    (void)vaddr;
    (void)udata;

    if (!reader_ready) {
        return;
    }
    g_mutex_lock(&lock);
    samples++;
    sample_h2c();
    g_mutex_unlock(&lock);
}

/* C2H: vhci_send(buffer, length, callback, context). */
static void vcpu_send(unsigned int cpu_index, void *udata)
{
    uint32_t buf, len;

    (void)udata;

    if (!read_arg(cpu_index, arg_buf_index, &buf) ||
        !read_arg(cpu_index, arg_len_index, &len)) {
        return;
    }
    if (!buf || len == 0 || len >= 4096) {
        return;
    }
    g_mutex_lock(&lock);
    samples++;
    emit("C2H", buf, len);
    g_mutex_unlock(&lock);
}

/* RXFM: the first frame-ISR dispatch, matching the historical gdb pass. */
static void vcpu_isr(unsigned int cpu_index, void *udata)
{
    uint32_t status, current, queue;
    unsigned int i;

    (void)cpu_index;
    (void)udata;

    if (isr_dumped) {
        return;
    }
    g_mutex_lock(&lock);
    if (isr_dumped) {
        g_mutex_unlock(&lock);
        return;
    }
    isr_dumped = true;
    status = u32_at(isr_status);
    current = u32_at(isr_current);
    queue = u32_at(isr_queue);
    fprintf(out, "RXFM hit=1 pc=0x%" PRIx64
            " status=%08x current=%08x fmq=%08x\n",
            isr_addr, status, current, queue);
    fprintf(out, "RXFM desc0=");
    for (i = 0; i < 7; i++) {
        fprintf(out, "%s%04x", i ? " " : "",
                (unsigned)u16_at(isr_desc + 2 * i));
    }
    fprintf(out, "\n");
    fflush(out);
    g_mutex_unlock(&lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    (void)id;
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

        if (stage_addr && vaddr >= stage_addr && vaddr < stage_end) {
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             QEMU_PLUGIN_MEM_W, NULL);
        }
        if (send_addr && vaddr == send_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_send,
                                                   QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        if (isr_addr && vaddr == isr_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_isr,
                                                   QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    (void)id;
    (void)p;

    if (verbose) {
        fprintf(stderr, "vhci-trace: %" PRIu64 " samples, env=0x%" PRIx64 "\n",
                samples, env_addr);
    }
    if (out_owned && out) {
        fclose(out);
        out = NULL;
    }
}

static void usage(void)
{
    fprintf(stderr,
            "vhci-trace options:\n"
            "  env=ADDR            guest address of the vhci_env_p pointer (required)\n"
            "  out=PATH            write H2C/C2H/RXFM lines here (default stderr)\n"
            "  stage=ADDR          host VHCI staging function entry (H2C store hook)\n"
            "  stage-end=ADDR      end of the staging function (exclusive)\n"
            "  send=ADDR           vhci_send entry (C2H register hook)\n"
            "  arg-buf-index=N     Xtensa register index of the buffer (default 2)\n"
            "  arg-len-index=N     Xtensa register index of the length (default 3)\n"
            "  env-ptr-offset=N    CPUState.env_ptr offset (default 544)\n"
            "  regs-offset=N       CPUArchState.regs offset (default 8)\n"
            "  isr=ADDR            r_ld_fm_frame_isr entry (RXFM dump)\n"
            "  isr-status=ADDR     RWBT 0x010 status word\n"
            "  isr-current=ADDR    RWBT 0x02c current RX descriptor\n"
            "  isr-queue=ADDR      ld_fm_env+0x14 program queue\n"
            "  isr-desc=ADDR       EM RX descriptor 0 base\n"
            "  verbose             print setup/exit diagnostics to stderr\n");
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

        if (g_strcmp0(key, "env") == 0 && val) {
            env_addr = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "out") == 0 && val) {
            out = fopen(val, "w");
            if (!out) {
                fprintf(stderr, "vhci-trace: cannot open %s\n", val);
                return -1;
            }
            out_owned = true;
        } else if (g_strcmp0(key, "stage") == 0 && val) {
            stage_addr = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "stage-end") == 0 && val) {
            stage_end = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "send") == 0 && val) {
            send_addr = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "arg-buf-index") == 0 && val) {
            arg_buf_index = (int)g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "arg-len-index") == 0 && val) {
            arg_len_index = (int)g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "env-ptr-offset") == 0 && val) {
            env_ptr_offset = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "regs-offset") == 0 && val) {
            regs_offset = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "isr") == 0 && val) {
            isr_addr = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "isr-status") == 0 && val) {
            isr_status = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "isr-current") == 0 && val) {
            isr_current = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "isr-queue") == 0 && val) {
            isr_queue = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "isr-desc") == 0 && val) {
            isr_desc = g_ascii_strtoull(val, NULL, 0);
        } else if (g_strcmp0(key, "verbose") == 0) {
            verbose = true;
        } else if (g_strcmp0(key, "help") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "vhci-trace: unknown option: %s\n", argv[i]);
            usage();
            return -1;
        }
    }

    if (!env_addr) {
        fprintf(stderr, "vhci-trace: env=ADDR is required\n");
        return -1;
    }
    if (stage_addr && stage_end <= stage_addr) {
        fprintf(stderr, "vhci-trace: stage-end must be above stage\n");
        return -1;
    }
    init_reader();
    if (!reader_ready) {
        fprintf(stderr, "vhci-trace: guest memory reader unavailable\n");
        return -1;
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
