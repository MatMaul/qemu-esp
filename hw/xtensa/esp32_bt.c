/*
 * ESP32 Bluetooth (BR/EDR + BLE) register trace model
 *
 * The proprietary Bluetooth controller blob is a RivieraWaves/CEVA
 * dual-mode baseband.  Its register interface is undocumented by Espressif.
 * This device deliberately implements only enough semantics to let the blob
 * run and to log every access (with a call stack when QEMU is in singlestep
 * mode, see xtensa_trace_mmio.c).
 *
 * It is a reverse-engineering aid, not a faithful hardware model.
 *
 * Layout (offsets within the 0x3ff71000 RWBT/RWBLE window):
 *
 *   0x000..0x1ff  RWBT   (BR/EDR MAC)
 *   0x200..0x3ff  RWBLE  (BLE link layer; base 0x3ff71200)
 *
 * Both blocks are driven by the same ROM (r_rwbt_* / r_rwble_*), and both use
 * the shared register at 0x064 as an interrupt enable/ack.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/xtensa/esp32_bt.h"
#include "xtensa_trace_mmio.h"

/* RWBT register offsets observed in libbtdm_app.a / the ESP32 ROM. */
#define RWBT_CTRL          0x000
#define RWBT_VERSION_RXPTR 0x004
#define RWBT_IRQ_STATUS    0x010
#define RWBT_IRQ_CLEAR     0x018
#define RWBT_INT_MASK      0x00c
#define RWBT_CLK_UPD       0x01c
#define RWBT_SLEEP_CTRL    0x030
#define RWBT_SLEEP_TIMER   0x034
#define RWBT_CLK_LO        0x038
#define RWBT_SLEEP_TIME    0x040
#define RWBT_WAKEUP_TIME   0x044
#define RWBT_EVENT         0x060
#define RWBT_ISR_ENABLE    0x064
#define RWBT_IRQ_ACK       0x064
#define RWBT_SLEEP_REQUEST 0x80000000u

/*
 * 0x030 sleep/wakeup control and status bits (working names).
 *
 *   31   sleep request (software, r_rwbt_sleep_enter)
 *   15   baseband asleep / sleep acknowledged (read by r_rw_schedule and
 *        btdm_wakeup_request)
 *   4    wakeup request (software, btdm_wakeup_request)
 *   3    wakeup in progress (r_rwbt_sleep_wakeup)
 *   0-2  RF sleep config (rf_rw_sleep)
 */
#define RWBT_SLEEP_STATE   0x00008000u
#define RWBT_WAKEUP_REQ    0x00000010u

/*
 * RWBT interrupt status bits used by the sleep state machine:
 *   bit 2 -> r_rwip_wakeup()      (via modules_funcs[0x170])
 *   bit 0 -> r_rwip_wakeup_end()  (via modules_funcs[0x178])
 */
#define RWBT_IRQ_WAKEUP      0x00000004u
#define RWBT_IRQ_WAKEUP_END  0x00000001u

/* RWBLE register offsets (absolute 0x3ff71200 + n). */
#define RWBLE_BASE         0x200
#define RWBLE_CTRL         0x200
#define RWBLE_VERSION      0x204
#define RWBLE_IRQ_STATUS   0x210
#define RWBLE_IRQ_CLEAR    0x218
#define RWBLE_WAKEUP_BOUND 0x21c
#define RWBLE_CLK_LO       0x220
#define RWBLE_CLK_HI       0x224
#define RWBLE_IRQ_ACK      0x22c
#define RWBLE_INIT_CTRL    0x250
#define RWBLE_STATUS       0x260

/*
 * Default RWBLE probe trigger: 0x2a0 is written once by r_lld_adv_start when
 * advertising is programmed (baseline: "RWBLE write 02a0 <- 000005dc" just
 * before "BLE: Advertising started").  The probe is disabled unless
 * rwble-probe-bit is set, so this default has no side effect.
 */
#define RWBLE_PROBE_TRIGGER_ADV 0x2a0

/*
 * Opt-in baseband RX descriptor model.
 *
 * The BR/EDR hardware RX ring is four 14-byte descriptors at EM 0x2382,
 * 0x2390, 0x239e and 0x23ac (docs/04 §3.1/§3.3).  RWBT 0x02c bits 14:0 name
 * the descriptor the baseband currently owns.  The real hardware fills the
 * descriptor, advances 0x02c and raises an RWBT status bit; that write order
 * is not observable from the CPU side, so this model synthesises one frame.
 *
 * Trigger: a guest write to RWBT 0x00c that raises bit 10 (0x400).  The
 * inquiry start path writes 0x3cc02 (the baseline 0x3c802 plus bit 10) just
 * before it pushes the inquiry frame-manager program.  The default status bit
 * is RWBT status bit 1, which r_rwbt_isr() dispatches to r_ld_fm_rx_isr()
 * (docs/03 §2.3).  Every value below is a QEMU property so another activity
 * can be modelled without editing the device.
 */
#define RWBT_CURRENT_RXDESC 0x02c
#define RWBT_EA_TARGET      0x0b8
#define RWBT_RXDESC_BASE     0x2382u
#define RWBT_RXDESC_LAST     0x23acu
#define RWBT_RXDESC_STRIDE   0x0eu
#define RWBT_RX_TRIGGER_OFF  0x00c
#define RWBT_RX_TRIGGER_BIT  10   /* inquiry activity bit (0x3cc02) */
#define RWBT_RX_STATUS_BIT   1
#define RWBT_EA_STATUS_BIT   9
#define RWBT_SW_STATUS_BIT   16
#define RWBT_EA_MAX_TICKS    400

/*
 * Fine-timer clock units.
 *
 * RWBT 0x01c is the hardware native clock; one tick is half a Bluetooth slot
 * (312.5 us).  The ROM's r_ld_read_clock() and r_ea_time_get_halfslot_rounded()
 * mask 0x01c with 0x0fffffff and shift right by one, so the event arbiter works
 * in 625 us slot units.  ea_prog_timer() writes that slot-unit target to RWBT
 * 0x0b8 (docs/03 §2.1, docs/09 §3.8).  The 27-bit wrapping range and the
 * "already due" half-range below are the constants ea_prog_timer uses.
 */
#define ESP32_BT_CLK_TICK_NS     312500ull
#define ESP32_BT_EA_SLOT_NS      625000ull
#define ESP32_BT_EA_TIME_MASK    0x0fffffffu
#define ESP32_BT_EA_WRAP_MASK    0x7ffffffu
#define ESP32_BT_EA_HALF_RANGE   0x4000000u

/* The BB block exposes the exchange-memory base at 0x0a0 (docs/03 §3). */
#define ESP32_BT_BB_EM_BASE  0x0a0
#define RWBT_EM_BASE_DEFAULT 0x3ffb0000u

/*
 * Both RWBT_CTRL and RWBLE_CTRL use bits 31/30 as self-clearing
 * reset/handshake bits:
 *
 *   bit 31: master soft reset.  ble_master_soft_rst() and
 *           r_rwip_reset_ext() set it and poll until it reads 0.
 *   bit 30: second handshake.  r_rwip_reset_ext() sets it and polls until
 *           it reads 0.
 *
 * Firmware spins on these bits with the cache disabled, so keeping them set
 * would hang the controller.
 */
#define BT_CTRL_SELF_CLEAR 0xC0000000u

/* Bits in *_WAKEUP_BOUND that are also write-only/self-clearing. */
#define BT_WAKEUP_SELF_CLEAR 0x80000000u

/*
 * Device log helpers.  With bt-trace=on the device writes its own lines to the
 * -D log without enabling QEMU's global -d unimp mask, so the RX-model
 * generator can trace only the BT block and keep the guest at full speed.
 * Without the property the historical -d unimp behaviour is unchanged.
 *
 * When `bt-events=PATH` is set, ESP32_BT_LOG() additionally writes one typed
 * NDJSON record per semantic line to that sidecar.  MMIO sites use
 * ESP32_BT_TEXT_LOG() so they can emit their own typed record instead of a
 * duplicate text-shaped `bt` record.
 */
static void esp32_bt_events_json_string(FILE *fp, const char *text)
{
    const unsigned char *p;

    for (p = (const unsigned char *)text; *p; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", fp);
            break;
        case '\\':
            fputs("\\\\", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*p < 0x20) {
                fprintf(fp, "\\u%04x", *p);
            } else {
                fputc(*p, fp);
            }
            break;
        }
    }
}

static void esp32_bt_events_log(Esp32BtState *s, const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

static void esp32_bt_events_log(Esp32BtState *s, const char *fmt, ...)
{
    char msg[1024];
    const char *text = msg;
    va_list ap;
    int n;

    if (!s->bt_events_fp) {
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if (n >= (int)sizeof(msg)) {
        msg[sizeof(msg) - 1] = '\0';
    }
    if (strncmp(text, "esp32_bt: ", 10) == 0) {
        text += 10;
    }
    fprintf(s->bt_events_fp,
            "{\"v\":1,\"source\":\"qemu\",\"t\":\"bt\","
            "\"seq\":%" PRIu64 ",\"message\":\"",
            ++s->bt_events_seq);
    esp32_bt_events_json_string(s->bt_events_fp, text);
    fputs("\"}\n", s->bt_events_fp);
}

static void esp32_bt_events_mmio(Esp32BtState *s, const char *dev, bool write,
                                 uint32_t off, uint32_t value)
{
    if (!s->bt_events_fp) {
        return;
    }
    fprintf(s->bt_events_fp,
            "{\"v\":1,\"source\":\"qemu\",\"t\":\"mmio\","
            "\"seq\":%" PRIu64 ",\"dev\":\"%s\","
            "\"op\":\"%s\",\"off\":%u,\"value\":%u}\n",
            ++s->bt_events_seq, dev, write ? "write" : "read", off, value);
}

#define ESP32_BT_TEXT_LOG(s, ...) do { \
    if ((s)->bt_trace) { \
        qemu_log(__VA_ARGS__); \
    } else { \
        qemu_log_mask(LOG_UNIMP, __VA_ARGS__); \
    } \
} while (0)

#define ESP32_BT_LOG(s, ...) do { \
    if ((s)->bt_events_fp) { \
        esp32_bt_events_log((s), __VA_ARGS__); \
    } \
    ESP32_BT_TEXT_LOG((s), __VA_ARGS__); \
} while (0)

/*
 * Deterministic model clock.
 *
 * `bt-clock=model` replaces QEMU_CLOCK_VIRTUAL with a timebase advanced by
 * guest-visible BT register activity.  Every modelled timer has a deadline in
 * this timebase and is fired synchronously from esp32_bt_model_advance(); no
 * QEMU timer is armed in model mode.  The host clock remains the default.
 */
enum {
    /* Priority order matters only when two deadlines are exactly equal. */
    ESP32_BT_TMR_EA_FINE = 0,
    ESP32_BT_TMR_RX_INJECT,
    ESP32_BT_TMR_SW_TICK,
    ESP32_BT_TMR_EA_TICK,
    ESP32_BT_TMR_RX_WATCH,
    ESP32_BT_TMR_SLEEP_ACK,
    ESP32_BT_TMR_WAKEUP,
    ESP32_BT_TMR_WAKEUP_START,
    ESP32_BT_TMR_WAKEUP_END,
    ESP32_BT_TMR_RWBLE_PROBE,
    ESP32_BT_TMR_TX_WATCH,
    ESP32_BT_TMR_TX_COMPLETE,
    ESP32_BT_TMR_COUNT,
};

static bool esp32_bt_model_clock(Esp32BtState *s)
{
    return s->bt_clock && strcmp(s->bt_clock, "model") == 0;
}

static bool esp32_bt_model_boot_start(Esp32BtState *s)
{
    return s->bt_clock_start && strcmp(s->bt_clock_start, "boot") == 0;
}

static uint64_t esp32_bt_guest_instructions(void)
{
    uint64_t count = 0;

    for (int i = 0; i < 16; i++) {
        count += qemu_guest_instruction_count[i];
    }
    return count;
}

static uint64_t esp32_bt_now_ns(Esp32BtState *s)
{
    if (esp32_bt_model_clock(s) && s->model_started) {
        uint64_t count;

        if (s->model_anchor_hold) {
            return s->model_ns;
        }
        count = esp32_bt_guest_instructions();

        if (count < s->model_base_count) {
            count = s->model_base_count;
        }
        return s->model_base_ns +
               (count - s->model_base_count) *
               (s->bt_clock_step_ns ? s->bt_clock_step_ns : 1);
    }
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void esp32_bt_sched(Esp32BtState *s, int id, QEMUTimer *timer,
                           uint64_t delay_ns)
{
    if (esp32_bt_model_clock(s) && s->model_started) {
        s->model_deadline[id] = s->model_ns + delay_ns;
        s->model_active[id] = true;
    } else {
        timer_mod(timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns);
    }
}

static void esp32_bt_cancel(Esp32BtState *s, int id, QEMUTimer *timer)
{
    if (esp32_bt_model_clock(s) && s->model_started) {
        s->model_active[id] = false;
    } else {
        timer_del(timer);
    }
}

static void esp32_bt_model_advance(Esp32BtState *s);
static void esp32_bt_model_anchor(Esp32BtState *s, const char *why);
static void esp32_bt_model_anchor_release(Esp32BtState *s);
static Esp32BtState *esp32_bt_plugin_state;

static uint32_t esp32_bt_bt_clk(Esp32BtState *s)
{
    /* BR/EDR and BLE native clock: one tick is 312.5 us. */
    uint64_t now_ns = esp32_bt_now_ns(s);
    uint64_t clk = now_ns / 312500;

    /*
     * r_ea_finetimer_isr only runs the EA element whose programmed target
     * equals the half-slot clock it reads (a3 == a5 at 0x4001571c).  Real
     * hardware raises the fine-timer interrupt inside the target slot, so the
     * read-back clock is still the target.  A host-time clock keeps advancing
     * between the model's fire and the guest's read, which would make the
     * comparison miss by one and drop the event.  Hold the clock at the fired
     * target for a short latency window (well under one 625 us slot) so
     * r_ea_finetimer_isr sees the slot it was woken for.  This is a model
     * consistency aid, not a timing claim.
     */
    if (now_ns < s->clock_hold_until) {
        return s->clock_floor;
    }
    if (clk < s->clock_floor) {
        clk = s->clock_floor;
    }
    return (uint32_t)clk;
}

static const char *esp32_bt_block(uint32_t off)
{
    return off >= RWBLE_BASE ? "RWBLE" : "RWBT ";
}

/* Same split without the text-log padding; used by the NDJSON sidecar. */
static const char *esp32_bt_block_name(uint32_t off)
{
    return off >= RWBLE_BASE ? "RWBLE" : "RWBT";
}

static Property esp32_bt_properties[];

static void esp32_bt_update_irqs(Esp32BtState *s)
{
    /*
     * The real block gates status bits through the per-slot ack/enable
     * register at 0x064/0x22c.  Their bit layout is not understood, so this
     * model asserts the line whenever any status bit is pending.  Marked H in
     * docs/03 and docs/09.
     */
    qemu_set_irq(s->irq_rwbt, s->rwbt_irq_status != 0);
    qemu_set_irq(s->irq_rwble, s->rwble_irq_status != 0);
}

/*
 * Opt-in RWBLE status-bit probe (parent project Q4e).
 *
 * These functions are inert unless the user selected a bit with the
 * rwble-probe-bit device property (0..31).  The probe raises exactly one bit
 * in RWBLE_IRQ_STATUS (0x210) so that r_rwble_isr() dispatches it.
 * It does not synthesise any accompanying baseband event; some handlers may
 * therefore read stale EM state.  This is a diagnostic injection only.
 */
static void esp32_bt_rwble_probe_fire(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t mask;

    s->rwble_probe_armed = false;
    if (s->rwble_probe_bit >= 32 || s->rwble_probe_fired) {
        return;
    }

    s->rwble_probe_fired = true;
    mask = 1u << s->rwble_probe_bit;
    s->rwble_irq_status |= mask;
    ESP32_BT_LOG(s,
                  "esp32_bt: RWBLE probe inject bit %u mask=%08x "
                  "status=%08x\n",
                  s->rwble_probe_bit, mask, s->rwble_irq_status);
    esp32_bt_update_irqs(s);
}

static void esp32_bt_rwble_probe_arm(Esp32BtState *s, uint64_t delay_ns)
{
    if (s->rwble_probe_bit >= 32 || s->rwble_probe_fired ||
        s->rwble_probe_armed) {
        return;
    }

    s->rwble_probe_armed = true;
    esp32_bt_sched(s, ESP32_BT_TMR_RWBLE_PROBE, s->rwble_probe_timer,
                   delay_ns);
    ESP32_BT_LOG(s,
                  "esp32_bt: RWBLE probe armed: bit %u delay=%" PRIu64
                  " ns\n",
                  s->rwble_probe_bit, delay_ns);
}

/*
 * Arm the "delay from boot" variant on the first RWBT/RWBLE access.  The
 * device reset hook may run before qdev applies -global properties, so it
 * cannot reliably arm this timer itself; the first guest access always comes
 * after property setup.  esp32_bt_rwble_probe_arm() is idempotent, so this is
 * harmless when reset already armed it.
 */
static void esp32_bt_rwble_probe_arm_start(Esp32BtState *s)
{
    if (s->rwble_probe_start_ns > 0) {
        esp32_bt_rwble_probe_arm(s, s->rwble_probe_start_ns);
    }
    if (s->bb_sw_inject && !s->bb_sw_armed) {
        s->bb_sw_armed = true;
        esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                       s->bb_sw_interval_ns);
    }
}

/*
 * Baseband RX descriptor model.
 *
 * EM is ordinary DRAM at the CPU's virtual/physical address, so the device
 * reaches it through address_space_memory.  The base is taken from the BB EM
 * base register when the guest has programmed it; otherwise the ESP32 default
 * is used.  These helpers are only called from the opt-in timer path.
 */
static uint32_t esp32_bt_em_base(Esp32BtState *s)
{
    uint32_t base = s->bb[ESP32_BT_BB_EM_BASE / 4];

    if (base == 0 || (base & 0xfu) != 0) {
        return RWBT_EM_BASE_DEFAULT;
    }
    return base;
}

static uint16_t esp32_bt_em_read16(Esp32BtState *s, uint32_t off)
{
    uint16_t v = 0;

    address_space_read(&address_space_memory,
                       esp32_bt_em_base(s) + off,
                       MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
    return v;
}

static uint32_t esp32_bt_read32(uint32_t addr)
{
    uint32_t v = 0;

    address_space_read(&address_space_memory, addr,
                       MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
    return v;
}

static void esp32_bt_em_write16(Esp32BtState *s, uint32_t off, uint16_t v)
{
    address_space_write(&address_space_memory,
                        esp32_bt_em_base(s) + off,
                        MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
}

static void esp32_bt_em_write8(Esp32BtState *s, uint32_t off, uint8_t v)
{
    address_space_write(&address_space_memory,
                        esp32_bt_em_base(s) + off,
                        MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
}

/*
 * Synthetic inquiry/FHS record.  The values are deliberately recognisable in
 * the trace and in the guest's HCI event; they are not a real peer's FHS.
 *
 * The controller does not parse the raw on-air bit stream here: ROM
 * r_ld_util_fhs_unpk (0x40040e54) unpacks the 20-byte record that the
 * descriptor's +0x0c field points at, with a byte-aligned layout (verified
 * from the disassembly and from the emitted Inquiry Result):
 *
 *   +0x04  u32   bits 2..25  = LAP (the LAP is stored shifted left by two)
 *   +0x07        bits 5..4   = page-scan repetition mode
 *   +0x08  u8    UAP
 *   +0x09  u16   NAP
 *   +0x0b  u24   Class of Device
 *   +0x0e  u32   bits 2..0 = LT_ADDR, bits 28..3 = CLK27-2
 *
 * The values below encode BD_ADDR 06:05:04:03:02:01 (HCI byte order
 * 01 02 03 04 05 06) and Class of Device 0x007a020c, a valid format-type-1
 * phone COD.  The bt_discovery app cancels the inquiry after the first
 * result for a phone/AV device, which exercises the HCI_Inquiry_Cancel /
 * Command Complete path.
 * 18 bytes is the FHS payload size in bytes (144 bits).
 */
static const uint8_t esp32_bt_rx_pattern[20] = {
    0x00, 0x00, 0x00, 0x00,               /* +0x00: record word 0 */
    0x04, 0x08, 0x0c, 0x00,               /* +0x04: LAP 0x030201 << 2 */
    0x04,                                 /* +0x08: UAP */
    0x05, 0x06,                           /* +0x09: NAP */
    0x0c, 0x02, 0x7a,                     /* +0x0b: COD 0x007a020c */
    0x00, 0x00, 0x00, 0x00,               /* +0x0e: LT_ADDR + CLK27-2 */
    0x00,                                 /* +0x12: pad */
};

static bool esp32_bt_rxdesc_valid(uint32_t off)
{
    return off >= RWBT_RXDESC_BASE && off <= RWBT_RXDESC_LAST &&
           ((off - RWBT_RXDESC_BASE) % RWBT_RXDESC_STRIDE) == 0;
}

static void esp32_bt_rx_frame_inject(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t desc, next, payload_off, staging_off;
    uint32_t i, len;
    uint16_t act_word;

    s->bb_rx_armed = false;
    if (!s->bb_rx_inject || s->bb_rx_fired) {
        return;
    }
    s->bb_rx_fired = true;
    esp32_bt_cancel(s, ESP32_BT_TMR_EA_TICK, s->bb_ea_timer);

    desc = s->rwbt[RWBT_CURRENT_RXDESC / 4] & 0x7fffu;
    if (!esp32_bt_rxdesc_valid(desc)) {
        ESP32_BT_LOG(s,
                      "esp32_bt: RX inject skipped: current desc %04x "
                      "is outside the 0x2382 ring\n", desc);
        return;
    }

    /*
     * Follow the ring's own next pointer.  r_ld_reset()/r_ld_init() wrote
     * each descriptor's bits 14:0 to the next EM offset, so this also
     * demonstrates that the model consumes the software-built ring rather
     * than a hard-coded sequence.
     */
    next = esp32_bt_em_read16(s, desc) & 0x7fffu;
    if (!esp32_bt_rxdesc_valid(next)) {
        next = desc == RWBT_RXDESC_LAST ?
               RWBT_RXDESC_BASE : desc + RWBT_RXDESC_STRIDE;
    }

    payload_off = esp32_bt_em_read16(s, desc + 0x0a);
    staging_off = esp32_bt_em_read16(s, desc + 0x0c);
    len = MIN(s->bb_rx_payload_len, sizeof(esp32_bt_rx_pattern));

    /*
     * DMA order: payload first, then the descriptor words, then the owner
     * pointer, then the status bit.  The guest callback only observes the
     * final state, but the trace records this order for the claim.
     */
    for (i = 0; i < len; i++) {
        esp32_bt_em_write8(s, payload_off + i, esp32_bt_rx_pattern[i]);
    }
    for (i = 0; i < 20; i++) {
        esp32_bt_em_write8(s, staging_off + i,
                           i < len ? esp32_bt_rx_pattern[i] : 0);
    }

    act_word = (uint16_t)(((s->bb_rx_activity & 0x1fu) << 11) |
                          (s->bb_rx_status_low & 0x7ffu));
    esp32_bt_em_write16(s, desc + 0x00, (uint16_t)(next | 0x8000u));
    esp32_bt_em_write16(s, desc + 0x02, act_word);
    esp32_bt_em_write16(s, desc + 0x04,
                        (uint16_t)((s->bb_rx_packet_type & 0x0fu) << 3));
    esp32_bt_em_write16(s, desc + 0x06, (uint16_t)((len & 0xffu) << 3));
    /*
     * +0x08: r_ld_inq_frm_cbk copies its low byte to the result record, which
     * r_modules_funcs_p+0xc4 emits as the Inquiry Result with RSSI byte.
     */
    esp32_bt_em_write16(s, desc + 0x08, (uint16_t)(s->bb_rx_rssi & 0xffu));

    s->rwbt[RWBT_CURRENT_RXDESC / 4] = next;
    s->rwbt_irq_status |= 1u << (s->bb_rx_status_bit & 31u);

    ESP32_BT_LOG(s,
                  "esp32_bt: RX frame inject desc=%04x next=%04x "
                  "activity=%u type=%u len=%u rssi=%u payload=%04x "
                  "staging=%04x fmq=%08x status=%08x clock=%u\n",
                  desc, next, s->bb_rx_activity, s->bb_rx_packet_type,
                  len, s->bb_rx_rssi & 0xffu, payload_off, staging_off,
                  esp32_bt_read32(0x3ffb8298), s->rwbt_irq_status,
                  esp32_bt_bt_clk(s));
    esp32_bt_update_irqs(s);
}

/*
 * Synthetic EA fine-timer tick.  r_rwbt_isr() dispatches RWBT status bit 9
 * to r_ea_finetimer_isr(), which advances the controller's event scheduler.
 * Without a baseband, the inquiry event-start callback never runs and the
 * frame-manager program is never pushed.  The ticks are bounded and opt-in.
 */
static void esp32_bt_ea_tick(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    if (!s->bb_ea_inject || s->bb_rx_fired ||
        s->bb_ea_ticks >= RWBT_EA_MAX_TICKS) {
        return;
    }
    s->bb_ea_ticks++;
    s->rwbt_irq_status |= 1u << RWBT_EA_STATUS_BIT;
    ESP32_BT_LOG(s,
                  "esp32_bt: EA tick %u, status=%08x\n",
                  s->bb_ea_ticks, s->rwbt_irq_status);
    esp32_bt_update_irqs(s);
    esp32_bt_sched(s, ESP32_BT_TMR_EA_TICK, s->bb_ea_timer,
                   s->bb_ea_interval_ns);
}

/*
 * Optional periodic software-interrupt tick (RWBT status bit 16).
 * r_rwbt_isr dispatches bit 16 to r_ip_funcs_p+0xfc (r_ea_sw_isr), which walks
 * the software EA list.  This is a diagnostic probe for checking whether a
 * frame-manager program is run through that path; it is off by default.
 */
static void esp32_bt_sw_tick(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    if (!s->bb_sw_inject) {
        return;
    }
    /*
     * A synthetic SW tick must not preempt a released RX frame.  If bit 16 is
     * already pending when r_rwbt_isr acknowledges the frame status, the
     * guest walks the software EA list before the frame handler and the
     * inquiry result is never emitted.  Keep the cadence but skip the edge
     * while the frame window is open; the next tick after the guest reads
     * RWBT 0x02c still exercises the bit-16 path.
     */
    if (s->bb_rx_window) {
        esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                       s->bb_sw_interval_ns);
        return;
    }
    s->rwbt_irq_status |= 1u << RWBT_SW_STATUS_BIT;
    ESP32_BT_LOG(s, "esp32_bt: SW tick n=%u status=%08x\n",
                  s->bb_sw_ticks, s->rwbt_irq_status);
    s->bb_sw_ticks++;
    esp32_bt_update_irqs(s);
    esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                   s->bb_sw_interval_ns);
}

static void esp32_bt_ea_start(Esp32BtState *s)
{
    if (!s->bb_ea_inject || s->bb_ea_ticks != 0) {
        return;
    }
    esp32_bt_sched(s, ESP32_BT_TMR_EA_TICK, s->bb_ea_timer,
                   s->bb_ea_interval_ns);
}

/*
 * Hardware fine-timer model.
 *
 * The ROM programs an absolute slot-unit target in RWBT 0x0b8 and enables the
 * fine-target interrupt mask (0x00c bit 9).  The hardware compares it with the
 * native clock and raises RWBT status bit 9; r_rwbt_isr() acknowledges it with
 * a 0x018 = 0x200 write and dispatches r_ea_finetimer_isr().  This model
 * reproduces that half of the contract so the controller's event arbiter can
 * advance and the inquiry event-start callback can push the frame-manager
 * program.  The payload/air behaviour is still not modelled.
 */
static uint32_t esp32_bt_ea_now_slot(Esp32BtState *s)
{
    uint32_t raw = esp32_bt_bt_clk(s) & ESP32_BT_EA_TIME_MASK;

    /* r_ea_time_get_halfslot_rounded(): ((raw & 0x0fffffff) + 1) >> 1. */
    return ((raw + 1) >> 1) & ESP32_BT_EA_WRAP_MASK;
}

static void esp32_bt_ea_fire(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    s->ea_armed = false;
    if (!s->bb_ea_model) {
        return;
    }
    s->ea_status_pending = true;
    s->ea_target_valid = false;  /* consumed by this expiry */
    s->ea_fires++;
    {
        uint64_t target_ticks = (uint64_t)s->ea_target * 2u;

        if (target_ticks > s->clock_floor) {
            s->clock_floor = target_ticks;
        }
        s->clock_hold_until = esp32_bt_now_ns(s) + 200000;
    }
    s->rwbt_irq_status |= 1u << RWBT_EA_STATUS_BIT;
    ESP32_BT_LOG(s,
                  "esp32_bt: EA fine fire n=%u target=%08x now=%08x "
                  "status=%08x clock=%u\n",
                  s->ea_fires, s->ea_target, esp32_bt_ea_now_slot(s),
                  s->rwbt_irq_status, esp32_bt_bt_clk(s));
    esp32_bt_update_irqs(s);
}

static void esp32_bt_ea_rearm(Esp32BtState *s)
{
    uint64_t delay_ns;
    uint32_t now_slot, delta;

    if (!s->bb_ea_model) {
        return;
    }
    if (!s->ea_mask_enabled || !s->ea_target_valid || s->ea_status_pending) {
        esp32_bt_cancel(s, ESP32_BT_TMR_EA_FINE, s->bb_fine_timer);
        s->ea_armed = false;
        return;
    }

    now_slot = esp32_bt_ea_now_slot(s);
    delta = (s->ea_target - now_slot) & ESP32_BT_EA_WRAP_MASK;
    if (delta == 0 || delta > ESP32_BT_EA_HALF_RANGE) {
        /*
         * The target is due or already in the past.  ea_prog_timer() treats
         * the same condition as "already due" and returns through its assert
         * path; the model expires the timer on the next timer slice instead
         * of scheduling a huge wrapped delay.
         */
        delay_ns = 1000;
    } else {
        delay_ns = (uint64_t)delta * ESP32_BT_EA_SLOT_NS;
    }

    esp32_bt_sched(s, ESP32_BT_TMR_EA_FINE, s->bb_fine_timer, delay_ns);
    if (!s->ea_armed) {
        ESP32_BT_LOG(s,
                      "esp32_bt: EA fine armed target=%08x now=%08x "
                      "delta=%u delay=%" PRIu64 "ns clock=%u\n",
                      s->ea_target, now_slot, delta, delay_ns,
                      esp32_bt_bt_clk(s));
    }
    s->ea_armed = true;
}

/*
 * State-based RX injection trigger.
 *
 * Poll a guest address and arm the one-shot frame injection only after the
 * value becomes non-zero.  The rx-model generator points this at
 * ld_fm_env+0x14, the frame-manager program queue that r_ld_fm_prog_push()
 * fills when the inquiry event-start callback runs.  This keeps the frame
 * delivery after r_ld_inq_start() without depending on a host-time delay.
 */
static void esp32_bt_rx_inject_arm(Esp32BtState *s);

static void esp32_bt_rx_watch_poll(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t v = 0;

    if (!s->bb_rx_inject || s->bb_rx_fired) {
        s->bb_rx_watch_armed = false;
        return;
    }

    address_space_read(&address_space_memory, s->bb_rx_watch_addr,
                       MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
    if (s->bb_rx_watch_offset != 0xffffffffu) {
        /*
         * Two-level watch: the address holds a pointer, and the observable is
         * a byte at ptr+offset.  The rx-model generator uses ld_inq_env
         * (0x3ffb82e4) and inq_state (event+0x3a), which
         * ld_inq_evt_start_cbk() sets to 1 immediately after it pushes the
         * frame-manager program.
         */
        if (v != 0) {
            uint8_t state = 0;

            address_space_read(&address_space_memory,
                               v + s->bb_rx_watch_offset,
                               MEMTXATTRS_UNSPECIFIED, &state,
                               sizeof(state));
            v = state;
        }
    }

    if (v != 0) {
        uint32_t m = v & s->bb_rx_watch_mask;

        if (m != 0 &&
            (s->bb_rx_watch_value == 0 || m == s->bb_rx_watch_value)) {
            if (s->bb_rx_watch_after_ea) {
                /*
                 * The watched state becomes valid before the event starts
                 * (r_ld_inq_start registers the inquiry event).  Wait for a
                 * subsequent fine-timer expiry, which is what runs
                 * ld_inq_evt_start_cbk() and pushes the frame-manager program.
                 */
                if (!s->bb_rx_watch_gated) {
                    s->bb_rx_watch_gated = true;
                    s->bb_rx_watch_fires = s->ea_fires;
                    ESP32_BT_LOG(s,
                                  "esp32_bt: RX watch gated addr=%08x "
                                  "value=%08x ea_fires=%u clock=%u\n",
                                  s->bb_rx_watch_addr, v, s->ea_fires,
                                  esp32_bt_bt_clk(s));
                } else if (s->ea_fires > s->bb_rx_watch_fires) {
                    s->bb_rx_watch_armed = false;
                    s->bb_rx_watch_done = true;
                    ESP32_BT_LOG(s,
                                  "esp32_bt: RX watch fired addr=%08x "
                                  "value=%08x offset=%08x ea_fires=%u "
                                  "clock=%u\n",
                                  s->bb_rx_watch_addr, v,
                                  s->bb_rx_watch_offset, s->ea_fires,
                                  esp32_bt_bt_clk(s));
                    esp32_bt_rx_inject_arm(s);
                    return;
                }
            } else {
                s->bb_rx_watch_armed = false;
                s->bb_rx_watch_done = true;
                ESP32_BT_LOG(s,
                              "esp32_bt: RX watch fired addr=%08x "
                              "value=%08x offset=%08x clock=%u\n",
                              s->bb_rx_watch_addr, v, s->bb_rx_watch_offset,
                              esp32_bt_bt_clk(s));
                esp32_bt_rx_inject_arm(s);
                return;
            }
        }
    }

    esp32_bt_sched(s, ESP32_BT_TMR_RX_WATCH, s->bb_rx_watch_timer,
                   s->bb_rx_watch_poll_ns);
}

static void esp32_bt_rx_watch_arm_start(Esp32BtState *s)
{
    if (!s->bb_rx_inject || s->bb_rx_watch_addr == 0 ||
        s->bb_rx_watch_armed || s->bb_rx_watch_done || s->bb_rx_fired) {
        return;
    }
    s->bb_rx_watch_armed = true;
    ESP32_BT_LOG(s,
                  "esp32_bt: RX watch armed addr=%08x poll=%" PRIu64
                  "ns clock=%u\n",
                  s->bb_rx_watch_addr, s->bb_rx_watch_poll_ns,
                  esp32_bt_bt_clk(s));
    esp32_bt_rx_watch_poll(s);
}

static void esp32_bt_rx_inject_arm(Esp32BtState *s)
{
    if (!s->bb_rx_inject || s->bb_rx_fired || s->bb_rx_armed) {
        return;
    }
    s->bb_rx_armed = true;
    s->bb_rx_window = true;
    if (s->bt_clock_anchor && strcmp(s->bt_clock_anchor, "rx") == 0) {
        esp32_bt_model_anchor(s, "RX inject arm");
    }
    esp32_bt_ea_start(s);
    esp32_bt_sched(s, ESP32_BT_TMR_RX_INJECT, s->bb_rx_timer,
                   s->bb_rx_delay_ns);
    ESP32_BT_LOG(s,
                  "esp32_bt: RX inject armed (delay=%" PRIu64 " ns, clock=%u)\n",
                  s->bb_rx_delay_ns, esp32_bt_bt_clk(s));
}

/*
 * Opt-in baseband TX completion model.
 *
 * The BR/EDR TX control block is an array of 10-byte records at EM 0x23ba,
 * indexed by 10*(2*link_id + queue) (spec/04 §3.2b).  Software posts a packet
 * by setting bit 15 of the record's +0x00 link word; ld_acl_tx() at
 * 0x4002ffdc sends only a record whose bit 15 is set, and the real baseband
 * clears that bit when the packet leaves the slot.  The clear is a
 * hardware-owned write that CPU-only EM tracing cannot see, so this model
 * polls one guest link word, clears the configured owner bit after a
 * configurable transmission delay and raises the selected status bit.  The
 * address, bit positions and target block are properties: another ring or
 * another image can be modelled without editing the device, and nothing here
 * claims the real silicon polarity.
 */
static void esp32_bt_tx_complete(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t before = 0, after;
    uint32_t mask;

    s->bb_tx_armed = false;
    if (!s->bb_tx_inject || s->bb_tx_fired) {
        return;
    }
    s->bb_tx_fired = true;

    address_space_read(&address_space_memory, s->bb_tx_watch_addr,
                       MEMTXATTRS_UNSPECIFIED, &before, sizeof(before));
    mask = 1u << (s->bb_tx_owner_bit & 31u);
    after = before & ~mask;
    address_space_write(&address_space_memory, s->bb_tx_watch_addr,
                        MEMTXATTRS_UNSPECIFIED, &after, sizeof(after));

    if (s->bb_tx_rwble) {
        s->rwble_irq_status |= 1u << (s->bb_tx_status_bit & 31u);
    } else {
        s->rwbt_irq_status |= 1u << (s->bb_tx_status_bit & 31u);
    }
    s->bb_tx_completions++;

    ESP32_BT_LOG(s,
                  "esp32_bt: TX complete n=%u addr=%08x owner=bit%u "
                  "before=%08x after=%08x status=%08x block=%s\n",
                  s->bb_tx_completions, s->bb_tx_watch_addr,
                  s->bb_tx_owner_bit, before, after,
                  s->bb_tx_rwble ? s->rwble_irq_status : s->rwbt_irq_status,
                  s->bb_tx_rwble ? "RWBLE" : "RWBT");
    esp32_bt_update_irqs(s);
}

static void esp32_bt_tx_watch_poll(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t v = 0;

    if (!s->bb_tx_inject || s->bb_tx_fired) {
        s->bb_tx_watch_armed = false;
        return;
    }

    address_space_read(&address_space_memory, s->bb_tx_watch_addr,
                       MEMTXATTRS_UNSPECIFIED, &v, sizeof(v));
    if ((v & s->bb_tx_watch_mask) ==
        (s->bb_tx_watch_value & s->bb_tx_watch_mask) &&
        (v & s->bb_tx_watch_mask) != 0) {
        s->bb_tx_watch_armed = false;
        s->bb_tx_armed = true;
        ESP32_BT_LOG(s,
                      "esp32_bt: TX watch fired addr=%08x value=%08x "
                      "mask=%08x delay=%" PRIu64 "ns clock=%u\n",
                      s->bb_tx_watch_addr, v, s->bb_tx_watch_mask,
                      s->bb_tx_delay_ns, esp32_bt_bt_clk(s));
        esp32_bt_sched(s, ESP32_BT_TMR_TX_COMPLETE, s->bb_tx_timer,
                       s->bb_tx_delay_ns);
        return;
    }

    esp32_bt_sched(s, ESP32_BT_TMR_TX_WATCH, s->bb_tx_watch_timer,
                   s->bb_tx_poll_ns);
}

static void esp32_bt_tx_watch_arm_start(Esp32BtState *s)
{
    if (!s->bb_tx_inject || s->bb_tx_watch_addr == 0 ||
        s->bb_tx_watch_armed || s->bb_tx_armed || s->bb_tx_fired) {
        return;
    }
    s->bb_tx_watch_armed = true;
    ESP32_BT_LOG(s,
                  "esp32_bt: TX watch armed addr=%08x mask=%08x value=%08x "
                  "poll=%" PRIu64 "ns clock=%u\n",
                  s->bb_tx_watch_addr, s->bb_tx_watch_mask,
                  s->bb_tx_watch_value, s->bb_tx_poll_ns,
                  esp32_bt_bt_clk(s));
    esp32_bt_tx_watch_poll(s);
}

/*
 * Sleep/wakeup synthesis.
 *
 * Sequence:
 *   1. software sets 0x030 bit 31 (r_rwbt_sleep_enter), and rf_rw_sleep()
 *      ORs bits 0-2;
 *   2. this model acknowledges the sleep by setting 0x030 bit 15 shortly
 *      afterwards and arms the (synthetic) sleep timer;
 *   3. on sleep-timer expiry, or when software sets the wakeup request
 *      (0x030 bit 4, from btdm_wakeup_request), the wakeup is delivered as
 *      two separate RWBT status events: bit 2 first (r_rwip_wakeup), then
 *      bit 0 (r_rwip_wakeup_end).  The blob's r_rwip_wakeup_end only acts
 *      when the RWIP prevent-sleep bit set by r_rwip_wakeup is present, so
 *      raising bit 0 alone is a no-op.
 */
static uint32_t *esp32_bt_sleep_ctrl(Esp32BtState *s)
{
    return &s->rwbt[RWBT_SLEEP_CTRL / 4];
}

static void esp32_bt_begin_wakeup(Esp32BtState *s)
{
    if (s->wake_in_progress) {
        return;
    }
    s->wake_in_progress = true;
    s->wakeup_ack_seen = false;
    s->wakeup_end_armed = false;
    esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP, s->wakeup_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP_END, s->wakeup_end_timer);
    esp32_bt_sched(s, ESP32_BT_TMR_WAKEUP_START, s->wakeup_start_timer,
                   s->wakeup_start_ns);
    ESP32_BT_LOG(s, "esp32_bt: wakeup requested\n");
}

static void esp32_bt_sleep_ack(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    *esp32_bt_sleep_ctrl(s) |= RWBT_SLEEP_STATE;
    ESP32_BT_LOG(s, "esp32_bt: sleep ack, 0x030 -> %08x\n",
                  *esp32_bt_sleep_ctrl(s));

    if (s->wakeup_interval_ns) {
        esp32_bt_sched(s, ESP32_BT_TMR_WAKEUP, s->wakeup_timer,
                       s->wakeup_interval_ns);
    }
}

static void esp32_bt_wakeup_timer(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    if (!(*esp32_bt_sleep_ctrl(s) & RWBT_SLEEP_STATE)) {
        /* Not asleep: try again later rather than spinning. */
        if (s->wakeup_interval_ns) {
            esp32_bt_sched(s, ESP32_BT_TMR_WAKEUP, s->wakeup_timer,
                           s->wakeup_interval_ns);
        }
        return;
    }

    ESP32_BT_LOG(s, "esp32_bt: sleep timer expiry\n");
    esp32_bt_begin_wakeup(s);
}

static void esp32_bt_wakeup_start(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    s->wakeup_end_armed = false;
    s->rwbt_irq_status |= RWBT_IRQ_WAKEUP;
    ESP32_BT_LOG(s,
                  "esp32_bt: RWBT wakeup start, status=%08x\n",
                  s->rwbt_irq_status);
    esp32_bt_update_irqs(s);
    /*
     * The "wakeup end" event is only raised after software has serviced
     * and acknowledged the wakeup-start bit (0x018 write).  Raising it
     * blindly tends to collapse into the same ISR invocation, and the ISR
     * tests status bit 0 before bit 2, which turns r_rwip_wakeup_end() into
     * a no-op and leaves the controller stuck in the wakeup state.
     */
}

static void esp32_bt_wakeup_end(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t *ctrl = esp32_bt_sleep_ctrl(s);

    s->wakeup_end_armed = false;
    s->wakeup_ack_seen = false;
    s->rwbt_irq_status |= RWBT_IRQ_WAKEUP_END;
    *ctrl &= ~(RWBT_SLEEP_STATE | RWBT_WAKEUP_REQ);
    s->wake_in_progress = false;
    ESP32_BT_LOG(s,
                  "esp32_bt: RWBT wakeup end, status=%08x 0x030=%08x\n",
                  s->rwbt_irq_status, *ctrl);
    esp32_bt_update_irqs(s);
}

static void esp32_bt_fire_one(Esp32BtState *s, int id)
{
    switch (id) {
    case ESP32_BT_TMR_EA_FINE:
        esp32_bt_ea_fire(s);
        break;
    case ESP32_BT_TMR_RX_INJECT:
        esp32_bt_rx_frame_inject(s);
        break;
    case ESP32_BT_TMR_SW_TICK:
        esp32_bt_sw_tick(s);
        break;
    case ESP32_BT_TMR_EA_TICK:
        esp32_bt_ea_tick(s);
        break;
    case ESP32_BT_TMR_RX_WATCH:
        esp32_bt_rx_watch_poll(s);
        break;
    case ESP32_BT_TMR_SLEEP_ACK:
        esp32_bt_sleep_ack(s);
        break;
    case ESP32_BT_TMR_WAKEUP:
        esp32_bt_wakeup_timer(s);
        break;
    case ESP32_BT_TMR_WAKEUP_START:
        esp32_bt_wakeup_start(s);
        break;
    case ESP32_BT_TMR_WAKEUP_END:
        esp32_bt_wakeup_end(s);
        break;
    case ESP32_BT_TMR_RWBLE_PROBE:
        esp32_bt_rwble_probe_fire(s);
        break;
    case ESP32_BT_TMR_TX_WATCH:
        esp32_bt_tx_watch_poll(s);
        break;
    case ESP32_BT_TMR_TX_COMPLETE:
        esp32_bt_tx_complete(s);
        break;
    }
}

static void esp32_bt_model_process_due(Esp32BtState *s)
{
    int guard = 0;

    while (guard++ < 10000) {
        int best = -1;
        uint64_t best_deadline = UINT64_MAX;

        for (int i = 0; i < ESP32_BT_TMR_COUNT; i++) {
            if (!s->model_active[i]) {
                continue;
            }
            if (s->model_deadline[i] <= s->model_ns &&
                s->model_deadline[i] < best_deadline) {
                best = i;
                best_deadline = s->model_deadline[i];
            }
        }
        if (best < 0) {
            break;
        }
        s->model_active[best] = false;
        esp32_bt_fire_one(s, best);
    }
}

/*
 * Advance the deterministic model clock and fire every due event in deadline
 * order before the guest access is handled.  Ties keep the enum priority:
 * the fine timer is processed before RX injection and the software tick, which
 * preserves the fine-timer -> 0x024 -> FHS -> Inquiry Result ordering.
 */
static void esp32_bt_model_advance(Esp32BtState *s)
{
    if (!esp32_bt_model_clock(s)) {
        return;
    }
    if (!s->model_started) {
        if (esp32_bt_model_boot_start(s)) {
            /* The boot path keeps host timing until the first fine target. */
            return;
        }
        s->model_started = true;
        s->model_base_ns = 0;
        s->model_base_count = esp32_bt_guest_instructions();
    }
    if (s->model_anchor_hold) {
        if (qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >=
            s->model_anchor_hold_deadline_ns) {
            esp32_bt_model_anchor_release(s);
        } else {
            return;
        }
    }
    if (!s->model_idle_armed) {
        s->model_idle_armed = true;
        timer_mod(s->model_idle_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
    }
    s->model_ns = esp32_bt_now_ns(s);
    esp32_bt_model_process_due(s);
}

/*
 * Idle backstop for the model clock.
 *
 * The controller can sleep on a BT interrupt without touching a BT register,
 * so a clock advanced only by BT accesses would deadlock.  This virtual-time
 * timer fires every millisecond and advances the model time by one step only
 * when no BT access happened since the previous tick.  During BT activity the
 * timer is inert, so the model trajectory remains access-driven; the idle
 * amount is fixed, so the event order is stable even though the wall-clock
 * moment of the tick is not.
 */
static void esp32_bt_model_idle(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    if (!esp32_bt_model_clock(s)) {
        return;
    }
    if (!s->model_started) {
        if (esp32_bt_model_boot_start(s)) {
            timer_mod(s->model_idle_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
            return;
        }
        s->model_started = true;
        s->model_base_ns = 0;
        s->model_base_count = esp32_bt_guest_instructions();
    }
    if (s->model_anchor_hold) {
        if (qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >=
            s->model_anchor_hold_deadline_ns) {
            esp32_bt_model_anchor_release(s);
        } else {
            timer_mod(s->model_idle_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
            return;
        }
    }
    s->model_ns = esp32_bt_now_ns(s);
    esp32_bt_model_process_due(s);
    timer_mod(s->model_idle_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
}

static uint32_t esp32_bt_vhci_hash(const uint8_t *buf, uint32_t len)
{
    uint32_t h = 2166136261u;
    uint32_t n = MIN(len, 24u);

    for (uint32_t i = 0; i < n; i++) {
        h = (h ^ buf[i]) * 16777619u;
    }
    return h ^ (len * 2654435761u);
}

static void esp32_bt_events_hci(Esp32BtState *s, const char *dir,
                                uint32_t len, const uint8_t *buf, uint32_t n)
{
    uint32_t header = 0;
    uint32_t i;

    if (!s->bt_events_fp) {
        return;
    }
    if (n > 0) {
        switch (buf[0]) {
        case 0x01:  /* command: type + 16-bit opcode */
        case 0x03:  /* SCO: type + handle/length */
            header = 3;
            break;
        case 0x04:  /* event: type + event code */
            header = 2;
            break;
        case 0x02:  /* ACL: type + handle/length */
            header = 4;
            break;
        default:
            header = 0;
            break;
        }
    }
    fprintf(s->bt_events_fp,
            "{\"v\":1,\"source\":\"qemu\",\"t\":\"hci\","
            "\"seq\":%" PRIu64 ",\"dir\":\"%s\","
            "\"len\":%u,\"bytes\":[",
            ++s->bt_events_seq, dir, len);
    for (i = 0; i < n; i++) {
        fprintf(s->bt_events_fp, "%s%u", i ? "," : "", (unsigned)buf[i]);
    }
    fputs("],\"payload\":[", s->bt_events_fp);
    for (i = header; i < n; i++) {
        fprintf(s->bt_events_fp, "%s%u", i > header ? "," : "",
                (unsigned)buf[i]);
    }
    fputc(']', s->bt_events_fp);
    if (n >= 1 && buf[0] == 0x01 && len >= 3) {
        fprintf(s->bt_events_fp, ",\"opcode\":%u",
                (unsigned)(buf[1] | (buf[2] << 8)));
    }
    if (n >= 1 && buf[0] == 0x04 && len >= 2) {
        fprintf(s->bt_events_fp, ",\"event\":%u", (unsigned)buf[1]);
    }
    fputs("}\n", s->bt_events_fp);
}

static void esp32_bt_vhci_log(Esp32BtState *s, const char *dir, uint32_t addr,
                              uint32_t len)
{
    uint8_t buf[256];
    uint32_t n = MIN(len, sizeof(buf));
    uint32_t i;

    if (n == 0) {
        return;
    }
    address_space_read(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                       buf, n);
    /*
     * Three shapes so both historical claim families keep working:
     *   H2C len=4 01 03 0c 00            (hci-capture)
     *   H2C len=4 hdr=01 03 0c           (rx-model)
     *   H2C dump 0x01 0x03 0x0c 0x00     (rx-model byte dump)
     */
    qemu_log("%s len=%u", dir, len);
    for (i = 0; i < n; i++) {
        qemu_log(" %02x", buf[i]);
    }
    qemu_log("\n");
    qemu_log("%s len=%u hdr=%02x %02x %02x\n", dir, len, buf[0],
             n > 1 ? buf[1] : 0, n > 2 ? buf[2] : 0);
    qemu_log("%s dump", dir);
    for (i = 0; i < n; i++) {
        qemu_log(" 0x%02x", buf[i]);
    }
    qemu_log("\n");
    esp32_bt_events_hci(s, dir, len, buf, n);
}

/*
 * Anchor the deterministic timebase at the host's HCI_Inquiry command.
 *
 * The boot path before the BT model runs under host virtual time, so the
 * instruction count at which the host issues the inquiry varies with host
 * speed.  The controller then programs fine-timer targets relative to that
 * count, which changes the pre-inquiry event phase and sometimes lets the
 * pre-armed periodic slot fire before the inquiry event, losing the result.
 * Freezing the model clock between the staged HCI_Inquiry and the controller's
 * target write makes that schedule identical on every run.  The absolute clock
 * is still model-defined, not silicon.
 */
static void esp32_bt_model_anchor(Esp32BtState *s, const char *why)
{
    if (!esp32_bt_model_clock(s) || !s->model_started || s->model_anchored) {
        return;
    }
    if (!s->bt_clock_anchor ||
        (strcmp(s->bt_clock_anchor, "inquiry") != 0 &&
         strcmp(s->bt_clock_anchor, "rx") != 0)) {
        return;
    }
    s->model_anchored = true;

    if (strcmp(why, "HCI_Inquiry") == 0) {
        /*
         * Freeze the timebase from the staging of HCI_Inquiry until the
         * controller programs the inquiry fine-timer target.  The controller
         * computes that target from the clock it reads, so holding the clock
         * makes the target, and therefore the event phase, identical on every
         * boot regardless of how the host-timed scheduler interleaved the
         * command.  Without the hold the pre-armed periodic slot can fire
         * first once enough instructions have run, which moves the inquiry
         * event out of its result window.
         */
        s->model_ns = esp32_bt_now_ns(s);
        s->model_anchor_hold = true;
        s->model_anchor_hold_deadline_ns =
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500000000;
        ESP32_BT_LOG(s, "esp32_bt: model clock held at %s\n", why);
        return;
    }

    /*
     * rx: keep the model timebase where it is and re-base only the synthetic
     * software-tick cadence, so bit 16 cannot land at a host-speed-dependent
     * phase.
     */
    s->model_base_count = esp32_bt_guest_instructions();
    s->model_base_ns = s->model_ns;
    s->bb_sw_ticks = 0;
    s->bb_sw_armed = true;
    esp32_bt_cancel(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer);
    esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                   s->bb_sw_interval_ns);
    ESP32_BT_LOG(s, "esp32_bt: model clock anchored at %s\n", why);
}

/*
 * Resume the timebase at the frozen model time once the controller programs
 * the inquiry target.  The instruction count consumed while held is discarded;
 * the controller computed the target against the frozen clock, so the event
 * schedule stays relative to the anchor instead of the host-timed interleaving.
 */
static void esp32_bt_model_anchor_release(Esp32BtState *s)
{
    if (!s->model_anchor_hold) {
        return;
    }
    s->model_anchor_hold = false;
    s->model_base_count = esp32_bt_guest_instructions();
    s->model_base_ns = s->model_ns;
    s->bb_sw_ticks = 0;
    s->bb_sw_armed = true;
    esp32_bt_cancel(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer);
    esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                   s->bb_sw_interval_ns);
    ESP32_BT_LOG(s, "esp32_bt: model clock released at inquiry target write\n");
}

/*
 * Plugin entry point.  The vhci-trace TCG plugin observes the H2C staging
 * window more reliably than the device-side sampler, so it calls this when the
 * host stages HCI_Inquiry.  Only the explicit `bt-clock-anchor=inquiry` mode
 * reacts; the default model clock is unchanged.
 */
void esp32_bt_model_anchor_from_plugin(void);

void esp32_bt_model_anchor_from_plugin(void)
{
    Esp32BtState *s = esp32_bt_plugin_state;

    if (s && s->bt_clock_anchor &&
        strcmp(s->bt_clock_anchor, "inquiry") == 0) {
        esp32_bt_model_anchor(s, "HCI_Inquiry");
    }
}

/*
 * Sample the VHCI environment.  The host-to-controller packet is staged at
 * env+0x28 with length/offset at +0x4d8/+0x4dc; the controller-to-host packet
 * pointer/length is at env+0x00/+0x04 (vhci_send).  A key suppresses repeated
 * samples of the same packet while it is still present; clearing the buffer
 * resets the key so an identical later packet is logged again.
 */
static void esp32_bt_vhci_sample(Esp32BtState *s)
{
    uint32_t env, count, offset, ptr, len, key;
    uint8_t head[24];

    if (!s->vhci_env_addr) {
        return;
    }
    env = esp32_bt_read32(s->vhci_env_addr);
    if (!env) {
        return;
    }

    count = esp32_bt_read32(env + 0x4d8);
    offset = esp32_bt_read32(env + 0x4dc);
    if (offset == 0 && count > 0 && count < 4096) {
        address_space_read(&address_space_memory, env + 0x28,
                           MEMTXATTRS_UNSPECIFIED, head,
                           MIN(count, sizeof(head)));
        key = esp32_bt_vhci_hash(head, count);
        if (key != s->vhci_rx_key) {
            s->vhci_rx_key = key;
            esp32_bt_vhci_log(s, "H2C", env + 0x28, count);
            if (count >= 3 && head[0] == 0x01 && head[1] == 0x01 &&
                head[2] == 0x04) {
                if (s->bt_clock_anchor && strcmp(s->bt_clock_anchor, "inquiry") == 0) {
                    esp32_bt_model_anchor(s, "HCI_Inquiry");
                }
            }
        }
    } else {
        s->vhci_rx_key = 0;
    }

    ptr = esp32_bt_read32(env);
    len = esp32_bt_read32(env + 4);
    if (ptr && len > 0 && len < 4096) {
        address_space_read(&address_space_memory, ptr, MEMTXATTRS_UNSPECIFIED,
                           head, MIN(len, sizeof(head)));
        key = esp32_bt_vhci_hash(head, len) ^ ptr;
        if (key != s->vhci_tx_key) {
            s->vhci_tx_key = key;
            esp32_bt_vhci_log(s, "C2H", ptr, len);
        }
    } else {
        s->vhci_tx_key = 0;
    }
}

static uint64_t esp32_bt_rwbt_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t r;
    uint32_t off = addr & ~3u;

    esp32_bt_model_advance(s);
    esp32_bt_rwble_probe_arm_start(s);
    esp32_bt_rx_watch_arm_start(s);
    esp32_bt_tx_watch_arm_start(s);

    switch (off) {
    case RWBT_CTRL:
    case RWBLE_CTRL:
        r = s->rwbt[off / 4] & ~BT_CTRL_SELF_CLEAR;
        break;
    case RWBT_VERSION_RXPTR:
        /*
         * Read-only identification/pointer register.  Version 8 in the
         * upper byte, initial RX descriptor offset 0xb00 below it.
         * r_ld_reset() asserts equality with 0x08000b00.
         */
        r = 0x08000b00;
        break;
    case RWBLE_VERSION:
        /*
         * r_rwble_version() reads this and stores it byte-for-byte in the
         * caller's rw_version struct.  The dual-mode blob asserts it equals
         * 0x08000900 in lld.c (observed as ASSERT_PARAM(0x08000900,
         * <actual>) during the first BTDM boot).  Version 8.0.9.0.
         */
        r = 0x08000900;
        break;
    case RWBT_IRQ_STATUS:
        r = s->rwbt_irq_status;
        break;
    case RWBT_INT_MASK:
        /*
         * Bits 9/10 are the bt_intcntl fine-target / ke-timer interrupt
         * masks.  The ROM's ea_prog_timer() asserts that the fine-target
         * mask is set when the target it is asked to program is already due
         * (ea.c:497).  With a host-time virtual clock the emulated scheduling
         * path can cross the target before ea_prog_timer() runs, so the model
         * reports the fine-target mask as enabled (hardware-owned).  The
         * opt-in fine-timer model treats that reported state as the real
         * mask state and re-arms its target timer, so the ROM's later
         * "already enabled" early return still schedules the expiry.
         */
        r = s->rwbt[off / 4] | 0x200u;
        if (s->bb_ea_model) {
            s->ea_mask_enabled = true;
            esp32_bt_ea_rearm(s);
        }
        break;
    case RWBLE_IRQ_STATUS:
        r = s->rwble_irq_status;
        break;
    case RWBT_CLK_UPD:
        /*
         * r_ld_read_clock() reads this register, ORs bit 31 (clock-update
         * command), writes it back, polls until bit 31 clears, then reads
         * again.  The low 31 bits are the hardware-owned native clock, so a
         * write must not overwrite them.  Returning 0 here stalls the EA
         * scheduler: every event stays in the future and the frame-manager
         * program is never pushed (docs/03 §2.1).
         */
        r = esp32_bt_bt_clk(s) & 0x7fffffffu;
        break;
    case RWBLE_WAKEUP_BOUND:
        r = s->rwbt[off / 4] & ~BT_WAKEUP_SELF_CLEAR;
        break;
    case RWBT_CLK_LO:
    case RWBLE_CLK_LO:
        r = esp32_bt_bt_clk(s);
        break;
    case RWBLE_CLK_HI:
        r = 0;
        break;
    case RWBT_CURRENT_RXDESC:
        /*
         * The guest consumes the injected frame by reading the current RX
         * descriptor.  Close the SW-tick suppression window here so later
         * bit-16 ticks keep advancing the frame-manager program.
         */
        r = s->rwbt[off / 4];
        s->bb_rx_window = false;
        break;
    default:
        r = s->rwbt[off / 4];
        break;
    }

    ESP32_BT_TEXT_LOG(s, "esp32_bt: %s read  %04x -> %08x\n",
                      esp32_bt_block(off), (uint32_t)off, r);
    esp32_bt_events_mmio(s, esp32_bt_block_name(off), false,
                         (uint32_t)off, r);
    log_mmio_access(ESP32_BT_RWBT_BASE + off, r, false);
    esp32_bt_vhci_sample(s);
    return r;
}

static void esp32_bt_rwbt_write(void *opaque, hwaddr addr,
                                uint64_t value, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t v = (uint32_t)value;
    uint32_t prev = s->rwbt[off / 4];

    esp32_bt_model_advance(s);
    esp32_bt_rwble_probe_arm_start(s);
    esp32_bt_rx_watch_arm_start(s);
    esp32_bt_tx_watch_arm_start(s);

    switch (off) {
    case RWBT_CTRL:
    case RWBLE_CTRL:
        /* Self-clearing reset/handshake bits: keep the rest. */
        s->rwbt[off / 4] = v & ~BT_CTRL_SELF_CLEAR;
        break;
    case RWBT_IRQ_STATUS:
        s->rwbt_irq_status = v;
        esp32_bt_update_irqs(s);
        break;
    case RWBLE_IRQ_STATUS:
        s->rwble_irq_status = v;
        esp32_bt_update_irqs(s);
        break;
    case RWBT_IRQ_CLEAR:
        s->rwbt_irq_status &= ~v;
        s->rwbt[off / 4] = v;
        esp32_bt_update_irqs(s);

        /*
         * r_rwbt_isr() acknowledges the fine-timer status with 0x018 = 0x200
         * before it dispatches r_ea_finetimer_isr().  Clear the pending
         * marker so the next programmed target can arm again.
         */
        if (v & (1u << RWBT_EA_STATUS_BIT)) {
            s->ea_status_pending = false;
            esp32_bt_ea_rearm(s);
        }

        /*
         * Wakeup sequence handshake.
         *
         * The wakeup-start bit (2) is acknowledged with a 0x018 write.
         * The blob then runs r_rwbt_sleep_wakeup(), which writes
         * 0x018 = -1 (clear all) while still inside the same ISR, wiping any
         * status bit raised meanwhile.  Therefore the "wakeup end" event is
         * only raised after that last clear-all write, with a delay long
         * enough for the ISR to return.  The acknowledge time is used as a
         * fallback in case no clear-all write follows.
         */
        if ((v & RWBT_IRQ_WAKEUP) && s->wake_in_progress) {
            s->wakeup_ack_seen = true;
            if (!s->wakeup_end_armed) {
                esp32_bt_sched(s, ESP32_BT_TMR_WAKEUP_END,
                               s->wakeup_end_timer, 20000000);
            }
        }
        if (v == 0xffffffffu && s->wake_in_progress &&
            s->wakeup_ack_seen) {
            s->wakeup_end_armed = true;
            esp32_bt_sched(s, ESP32_BT_TMR_WAKEUP_END,
                           s->wakeup_end_timer, s->wakeup_end_ns);
        }
        break;
    case RWBLE_IRQ_CLEAR:
        s->rwble_irq_status &= ~v;
        s->rwbt[off / 4] = v;
        esp32_bt_update_irqs(s);
        break;
    case RWBT_ISR_ENABLE:
        s->rwbt_irq_enable = v;
        break;
    case RWBT_INT_MASK:
        s->rwbt[off / 4] = v;
        s->ea_mask_enabled = (v >> RWBT_EA_STATUS_BIT) & 1u;
        esp32_bt_ea_rearm(s);
        break;
    case RWBT_EA_TARGET:
        /* The inquiry command programs its first fine target here. */
        esp32_bt_model_anchor_release(s);
        s->rwbt[off / 4] = v;
        s->ea_target = v;
        s->ea_target_valid = true;
        if (esp32_bt_model_clock(s) && !s->model_started &&
            esp32_bt_model_boot_start(s)) {
            /*
             * Start the deterministic clock at the guest's first fine-timer
             * target.  The boot path therefore ran under host timing, and the
             * model begins one 625 us slot before the programmed target, so
             * the first expiry is relative and reproducible while the guest's
             * own "target == clock" check still passes.
             */
            uint32_t slot = v & ESP32_BT_EA_WRAP_MASK;

            s->model_base_ns = slot ?
                (uint64_t)(slot - 1) * ESP32_BT_EA_SLOT_NS : 0;
            s->model_base_count = esp32_bt_guest_instructions();
            s->model_ns = s->model_base_ns;
            s->model_started = true;
            s->model_accesses = 0;
            /* Drop timers armed under host timing; re-arm the model ones. */
            timer_del(s->sleep_ack_timer);
            timer_del(s->wakeup_timer);
            timer_del(s->wakeup_start_timer);
            timer_del(s->wakeup_end_timer);
            timer_del(s->rwble_probe_timer);
            timer_del(s->bb_rx_timer);
            timer_del(s->bb_ea_timer);
            timer_del(s->bb_sw_timer);
            timer_del(s->bb_fine_timer);
            timer_del(s->bb_rx_watch_timer);
            timer_del(s->bb_tx_watch_timer);
            timer_del(s->bb_tx_timer);
            for (int i = 0; i < ESP32_BT_TMR_COUNT; i++) {
                s->model_active[i] = false;
            }
            s->bb_tx_watch_armed = false;
            s->bb_tx_armed = false;
            if (s->bb_tx_inject && !s->bb_tx_fired) {
                esp32_bt_tx_watch_arm_start(s);
            }
            if (s->bb_sw_inject && s->bb_sw_armed) {
                esp32_bt_sched(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer,
                               s->bb_sw_interval_ns);
            }
            if (s->bb_ea_inject) {
                esp32_bt_sched(s, ESP32_BT_TMR_EA_TICK, s->bb_ea_timer,
                               s->bb_ea_interval_ns);
            }
            if (!s->model_idle_armed) {
                s->model_idle_armed = true;
                timer_mod(s->model_idle_timer,
                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
            }
            ESP32_BT_LOG(s,
                          "esp32_bt: model clock start target=%08x clock=%u\n",
                          v, esp32_bt_bt_clk(s));
        }
        esp32_bt_ea_rearm(s);
        break;
    case RWBLE_IRQ_ACK:
        s->rwble_irq_enable = v;
        break;
    case RWBT_SLEEP_CTRL:
    {
        uint32_t old = s->rwbt[off / 4];

        /*
         * Bit 15 is a baseband status bit, not a software field: preserve the
         * modelled value across guest read-modify-writes and only let the
         * sleep state machine change it.
         */
        v = (v & ~RWBT_SLEEP_STATE) | (old & RWBT_SLEEP_STATE);

        if (!(old & RWBT_SLEEP_REQUEST) &&
            (v & RWBT_SLEEP_REQUEST)) {
            /* New sleep request: the baseband is no longer "asleep" yet. */
            v &= ~RWBT_SLEEP_STATE;
            esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP, s->wakeup_timer);
            esp32_bt_sched(s, ESP32_BT_TMR_SLEEP_ACK, s->sleep_ack_timer,
                           s->sleep_ack_ns);
            ESP32_BT_LOG(s, "esp32_bt: sleep request\n");
        }

        s->rwbt[off / 4] = v;

        if (!(old & RWBT_WAKEUP_REQ) && (v & RWBT_WAKEUP_REQ)) {
            esp32_bt_begin_wakeup(s);
        }
        break;
    }
    case RWBT_CLK_UPD:
        /* Clock-update command: hardware-owned and self-clearing. */
        break;
    case RWBLE_WAKEUP_BOUND:
        s->rwbt[off / 4] = v & ~BT_WAKEUP_SELF_CLEAR;
        break;
    default:
        s->rwbt[off / 4] = v;
        break;
    }

    ESP32_BT_TEXT_LOG(s, "esp32_bt: %s write %04x <- %08x\n",
                      esp32_bt_block(off), (uint32_t)off, v);
    esp32_bt_events_mmio(s, esp32_bt_block_name(off), true,
                         (uint32_t)off, v);
    log_mmio_access(ESP32_BT_RWBT_BASE + off, v, true);
    esp32_bt_vhci_sample(s);

    /*
     * Arm the opt-in RWBLE probe on the selected RWBLE register write.
     * Disabled by default (rwble_probe_bit == 0xffffffff).  When
     * rwble-probe-start-ns is set, the reset-time timer is used instead and
     * this register trigger is ignored.
     */
    if (s->rwble_probe_bit < 32 && s->rwble_probe_start_ns == 0 &&
        off >= RWBLE_BASE && off == s->rwble_probe_trigger_off) {
        esp32_bt_rwble_probe_arm(s, s->rwble_probe_delay_ns);
    }

    /*
     * Opt-in baseband RX model: without a state watch address, arm on the
     * selected register's bit 0->1 transition.  The frame-manager enable path
     * writes 0x00c values such as 0x05 just after programming the inquiry/ACL
     * activity.  When bb-rx-watch-addr is set the EM state watch above is the
     * trigger instead.
     */
    if (s->bb_rx_inject && s->bb_rx_watch_addr == 0 &&
        off == s->bb_rx_trigger_off && s->bb_rx_trigger_bit < 32) {
        uint32_t bit = 1u << s->bb_rx_trigger_bit;

        if ((v & bit) != 0 && (prev & bit) == 0) {
            esp32_bt_rx_inject_arm(s);
        }
    }
}

static uint64_t esp32_bt_bb_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t r = s->bb[off / 4];

    esp32_bt_model_advance(s);
    esp32_bt_tx_watch_arm_start(s);

    ESP32_BT_TEXT_LOG(s, "esp32_bt: BB    read  %04x -> %08x\n",
                      (uint32_t)off, r);
    esp32_bt_events_mmio(s, "BB", false, (uint32_t)off, r);
    log_mmio_access(ESP32_BT_BB_BASE + off, r, false);
    return r;
}

static void esp32_bt_bb_write(void *opaque, hwaddr addr,
                              uint64_t value, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t v = (uint32_t)value;

    esp32_bt_model_advance(s);
    esp32_bt_tx_watch_arm_start(s);
    s->bb[off / 4] = v;
    ESP32_BT_TEXT_LOG(s, "esp32_bt: BB    write %04x <- %08x\n",
                      (uint32_t)off, v);
    esp32_bt_events_mmio(s, "BB", true, (uint32_t)off, v);
    log_mmio_access(ESP32_BT_BB_BASE + off, v, true);
}

static const MemoryRegionOps esp32_bt_rwbt_ops = {
    .read = esp32_bt_rwbt_read,
    .write = esp32_bt_rwbt_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
};

static const MemoryRegionOps esp32_bt_bb_ops = {
    .read = esp32_bt_bb_read,
    .write = esp32_bt_bb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
};

static void esp32_bt_reset(DeviceState *dev)
{
    Esp32BtState *s = ESP32_BT(dev);

    memset(s->rwbt, 0, sizeof(s->rwbt));
    memset(s->bb, 0, sizeof(s->bb));
    s->rwbt_irq_status = 0;
    s->rwble_irq_status = 0;
    s->rwbt_irq_enable = 0;
    s->rwble_irq_enable = 0;
    s->wake_in_progress = false;
    s->wakeup_ack_seen = false;
    s->wakeup_end_armed = false;
    esp32_bt_cancel(s, ESP32_BT_TMR_SLEEP_ACK, s->sleep_ack_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP, s->wakeup_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP_START, s->wakeup_start_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_WAKEUP_END, s->wakeup_end_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_RWBLE_PROBE, s->rwble_probe_timer);
    s->rwble_probe_armed = false;
    s->rwble_probe_fired = false;
    esp32_bt_cancel(s, ESP32_BT_TMR_RX_INJECT, s->bb_rx_timer);
    s->bb_rx_armed = false;
    s->bb_rx_fired = false;
    s->bb_rx_window = false;
    s->model_anchored = false;
    esp32_bt_cancel(s, ESP32_BT_TMR_EA_TICK, s->bb_ea_timer);
    s->bb_ea_ticks = 0;
    esp32_bt_cancel(s, ESP32_BT_TMR_SW_TICK, s->bb_sw_timer);
    s->bb_sw_armed = false;
    s->bb_sw_ticks = 0;
    esp32_bt_cancel(s, ESP32_BT_TMR_EA_FINE, s->bb_fine_timer);
    s->ea_target = 0;
    s->ea_target_valid = false;
    s->ea_mask_enabled = false;
    s->ea_status_pending = false;
    s->ea_armed = false;
    s->ea_fires = 0;
    s->clock_floor = 0;
    s->clock_hold_until = 0;
    esp32_bt_cancel(s, ESP32_BT_TMR_RX_WATCH, s->bb_rx_watch_timer);
    s->bb_rx_watch_armed = false;
    s->bb_rx_watch_gated = false;
    s->bb_rx_watch_done = false;
    s->bb_rx_watch_fires = 0;
    esp32_bt_cancel(s, ESP32_BT_TMR_TX_WATCH, s->bb_tx_watch_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_TX_COMPLETE, s->bb_tx_timer);
    s->bb_tx_watch_armed = false;
    s->bb_tx_armed = false;
    s->bb_tx_fired = false;
    s->bb_tx_completions = 0;
    s->model_ns = 0;
    s->model_base_ns = 0;
    s->model_base_count = 0;
    s->model_started = false;
    s->model_anchor_hold = false;
    s->model_anchor_hold_deadline_ns = 0;
    s->model_accesses = 0;
    s->vhci_rx_key = 0;
    s->vhci_tx_key = 0;
    s->model_idle_armed = false;
    timer_del(s->model_idle_timer);
    for (int i = 0; i < ESP32_BT_TMR_COUNT; i++) {
        s->model_deadline[i] = 0;
        s->model_active[i] = false;
    }
    esp32_bt_update_irqs(s);

    /* Best-effort reset-time arm; the first guest access arms it otherwise. */
    if (s->rwble_probe_bit < 32 && s->rwble_probe_start_ns > 0) {
        esp32_bt_rwble_probe_arm(s, s->rwble_probe_start_ns);
    }

    /*
     * RWBT version/current-RX-descriptor-pointer register.  The ROM
     * r_ld_reset() asserts that this reads back as 0x08000b00 for the
     * BR/EDR EM layout: version 8 in the upper byte, RX descriptor
     * offset 0xb00 in the lower 24 bits.
     */
    s->rwbt[RWBT_VERSION_RXPTR / 4] = 0x08000b00;
}

static void esp32_bt_init(Object *obj)
{
    Esp32BtState *s = ESP32_BT(obj);

    esp32_bt_plugin_state = s;
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem_rwbt, obj, &esp32_bt_rwbt_ops, s,
                          TYPE_ESP32_BT ".rwbt", ESP32_BT_RWBT_SIZE);
    sysbus_init_mmio(sbd, &s->iomem_rwbt);

    memory_region_init_io(&s->iomem_bb, obj, &esp32_bt_bb_ops, s,
                          TYPE_ESP32_BT ".bb", ESP32_BT_BB_SIZE);
    sysbus_init_mmio(sbd, &s->iomem_bb);

    sysbus_init_irq(sbd, &s->irq_rwbt);
    sysbus_init_irq(sbd, &s->irq_rwble);
    s->sleep_ack_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      esp32_bt_sleep_ack, s);
    s->wakeup_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                   esp32_bt_wakeup_timer, s);
    s->wakeup_start_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         esp32_bt_wakeup_start, s);
    s->wakeup_end_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       esp32_bt_wakeup_end, s);
    s->rwble_probe_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        esp32_bt_rwble_probe_fire, s);
    s->bb_rx_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  esp32_bt_rx_frame_inject, s);
    s->bb_ea_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  esp32_bt_ea_tick, s);
    s->bb_sw_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  esp32_bt_sw_tick, s);
    s->bb_fine_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                    esp32_bt_ea_fire, s);
    s->bb_rx_watch_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        esp32_bt_rx_watch_poll, s);
    s->bb_tx_watch_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        esp32_bt_tx_watch_poll, s);
    s->bb_tx_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  esp32_bt_tx_complete, s);
    s->model_idle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       esp32_bt_model_idle, s);
}

static void esp32_bt_realize(DeviceState *dev, Error **errp)
{
    Esp32BtState *s = ESP32_BT(dev);

    if (!s->bt_events || s->bt_events[0] == '\0') {
        return;
    }
    s->bt_events_fp = fopen(s->bt_events, "w");
    if (!s->bt_events_fp) {
        error_setg_errno(errp, errno, "esp32_bt: cannot open %s",
                         s->bt_events);
    }
}

static void esp32_bt_unrealize(DeviceState *dev)
{
    Esp32BtState *s = ESP32_BT(dev);

    if (s->bt_events_fp) {
        fclose(s->bt_events_fp);
        s->bt_events_fp = NULL;
    }
}

static void esp32_bt_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->reset = esp32_bt_reset;
    dc->realize = esp32_bt_realize;
    dc->unrealize = esp32_bt_unrealize;
    device_class_set_props(dc, esp32_bt_properties);
}

static Property esp32_bt_properties[] = {
    /* Trace only this device to the -D log without -d unimp. */
    DEFINE_PROP_BOOL("bt-trace", Esp32BtState, bt_trace, false),
    /* Optional NDJSON sidecar path; empty disables it. */
    DEFINE_PROP_STRING("bt-events", Esp32BtState, bt_events),

    /*
     * Opt-in deterministic model clock.  `host` (default) keeps
     * the historical QEMU_CLOCK_VIRTUAL timing.  `model` advances a model
     * timebase on every BT register access and processes due events from it,
     * so tracing or gdb cannot change the event order.  bt-clock-step-ns is
     * the time added per access.
     */
    DEFINE_PROP_STRING("bt-clock", Esp32BtState, bt_clock),
    DEFINE_PROP_STRING("bt-clock-start", Esp32BtState, bt_clock_start),
    DEFINE_PROP_STRING("bt-clock-anchor", Esp32BtState, bt_clock_anchor),
    DEFINE_PROP_UINT32("vhci-env", Esp32BtState, vhci_env_addr, 0),
    DEFINE_PROP_UINT64("bt-clock-step-ns", Esp32BtState,
                       bt_clock_step_ns, 4),
    DEFINE_PROP_UINT64("bt-clock-idle-step-ns", Esp32BtState,
                       bt_clock_idle_step_ns, 0),

    /*
     * Synthetic sleep-timer period.  The real block wakes up when the timer
     * programmed through 0x034 expires; this model instead wakes periodically
     * while 0x030 bit 15 (asleep) is set.  It is also the fallback that keeps
     * the controller making progress if a wakeup request is missed.
     */
    DEFINE_PROP_UINT64("wakeup-interval-ns", Esp32BtState,
                       wakeup_interval_ns, 1000000),
    /* Delay from the sleep request to the modelled "asleep" status. */
    DEFINE_PROP_UINT64("sleep-ack-ns", Esp32BtState, sleep_ack_ns, 1000),
    /* Delay from a wakeup trigger to RWBT status bit 2 (r_rwip_wakeup). */
    DEFINE_PROP_UINT64("wakeup-start-ns", Esp32BtState,
                       wakeup_start_ns, 1000),
    /* Delay from bit 2 to RWBT status bit 0 (r_rwip_wakeup_end). */
    DEFINE_PROP_UINT64("wakeup-end-ns", Esp32BtState, wakeup_end_ns, 500000),

    /*
     * Opt-in RWBLE status-bit probe (parent project Q4e).  Disabled by default
     * (rwble-probe-bit = 0xffffffff).  Set it to a bit index 0..31 to raise
     * that one bit in RWBLE_IRQ_STATUS (0x210) and let r_rwble_isr()
     * dispatch it.  The trigger is a guest write to the RWBLE register at
     * rwble-probe-trigger-off (default 0x2a0, written by r_lld_adv_start
     * when advertising is programmed); rwble-probe-start-ns > 0 instead
     * arms the probe from the first RWBT/RWBLE access (approximately boot)
     * and ignores the register trigger.  rwble-probe-delay-ns is applied
     * after the trigger.
     */
    DEFINE_PROP_UINT32("rwble-probe-bit", Esp32BtState,
                       rwble_probe_bit, 0xffffffffu),
    DEFINE_PROP_UINT32("rwble-probe-trigger-off", Esp32BtState,
                       rwble_probe_trigger_off, RWBLE_PROBE_TRIGGER_ADV),
    DEFINE_PROP_UINT64("rwble-probe-delay-ns", Esp32BtState,
                       rwble_probe_delay_ns, 1000000),
    DEFINE_PROP_UINT64("rwble-probe-start-ns", Esp32BtState,
                       rwble_probe_start_ns, 0),

    /*
     * Opt-in baseband RX descriptor model.  Disabled by default:
     * without -global driver=misc.esp32.bt,property=bb-rx-inject,value=on the
     * device behaves exactly as before.  bb-rx-trigger-off selects the RWBT
     * register whose bit 0 0->1 transition arms the one-shot injection;
     * bb-rx-delay-ns lets the guest finish programming the activity first.
     */
    DEFINE_PROP_BOOL("bb-rx-inject", Esp32BtState, bb_rx_inject, false),
    DEFINE_PROP_UINT32("bb-rx-trigger-off", Esp32BtState,
                       bb_rx_trigger_off, RWBT_RX_TRIGGER_OFF),
    DEFINE_PROP_UINT32("bb-rx-trigger-bit", Esp32BtState,
                       bb_rx_trigger_bit, RWBT_RX_TRIGGER_BIT),
    DEFINE_PROP_UINT64("bb-rx-delay-ns", Esp32BtState,
                       bb_rx_delay_ns, 10000000),
    DEFINE_PROP_UINT32("bb-rx-activity", Esp32BtState,
                       bb_rx_activity, 7),
    DEFINE_PROP_UINT32("bb-rx-packet-type", Esp32BtState,
                       bb_rx_packet_type, 2),
    DEFINE_PROP_UINT32("bb-rx-payload-len", Esp32BtState,
                       bb_rx_payload_len, 18),
    DEFINE_PROP_UINT32("bb-rx-rssi", Esp32BtState,
                       bb_rx_rssi, 0),
    DEFINE_PROP_UINT32("bb-rx-status-low", Esp32BtState,
                       bb_rx_status_low, 0),
    DEFINE_PROP_UINT32("bb-rx-status-bit", Esp32BtState,
                       bb_rx_status_bit, RWBT_RX_STATUS_BIT),
    DEFINE_PROP_BOOL("bb-ea-inject", Esp32BtState, bb_ea_inject, false),
    DEFINE_PROP_BOOL("bb-sw-inject", Esp32BtState, bb_sw_inject, false),
    DEFINE_PROP_UINT64("bb-sw-interval-ns", Esp32BtState,
                       bb_sw_interval_ns, 10000000),
    DEFINE_PROP_UINT64("bb-ea-interval-ns", Esp32BtState,
                       bb_ea_interval_ns, 1000000),

    /*
     * Opt-in hardware fine-timer model.  Disabled by default.
     * Tracks RWBT 0x0b8 and 0x00c bit 9 and raises RWBT status bit 9 when the
     * 625 us slot target is reached; see docs/09 §3.8.
     */
    DEFINE_PROP_BOOL("bb-ea-timer", Esp32BtState, bb_ea_model, false),

    /*
     * Opt-in state-based RX trigger.  When bb-rx-watch-addr is
     * non-zero the one-shot frame injection is armed only after that 32-bit
     * guest word becomes non-zero.  The rx-model generator uses 0x3ffb8298
     * (ld_fm_env+0x14, the frame-manager program queue).
     */
    DEFINE_PROP_UINT32("bb-rx-watch-addr", Esp32BtState,
                       bb_rx_watch_addr, 0),
    DEFINE_PROP_UINT32("bb-rx-watch-mask", Esp32BtState,
                       bb_rx_watch_mask, 0xffffffffu),
    DEFINE_PROP_UINT32("bb-rx-watch-offset", Esp32BtState,
                       bb_rx_watch_offset, 0xffffffffu),
    DEFINE_PROP_UINT32("bb-rx-watch-value", Esp32BtState,
                       bb_rx_watch_value, 0),
    DEFINE_PROP_UINT64("bb-rx-watch-poll-ns", Esp32BtState,
                       bb_rx_watch_poll_ns, 200000),
    DEFINE_PROP_BOOL("bb-rx-watch-after-ea", Esp32BtState,
                     bb_rx_watch_after_ea, false),

    /*
     * Opt-in baseband TX completion model.  Disabled by default.  It polls the
     * guest link word at bb-tx-watch-addr and, when its masked value matches
     * bb-tx-watch-value (non-zero), clears bb-tx-owner-bit and raises
     * bb-tx-status-bit in RWBT (or RWBLE when bb-tx-rwble=on).  The default
     * watch target is the first BR/EDR TX link word at EM 0x23ba with owner
     * bit 15 set (spec/04 §3.2b).
     */
    DEFINE_PROP_BOOL("bb-tx-inject", Esp32BtState, bb_tx_inject, false),
    DEFINE_PROP_UINT32("bb-tx-watch-addr", Esp32BtState,
                       bb_tx_watch_addr, 0),
    DEFINE_PROP_UINT32("bb-tx-watch-mask", Esp32BtState,
                       bb_tx_watch_mask, 0x8000u),
    DEFINE_PROP_UINT32("bb-tx-watch-value", Esp32BtState,
                       bb_tx_watch_value, 0x8000u),
    DEFINE_PROP_UINT32("bb-tx-owner-bit", Esp32BtState,
                       bb_tx_owner_bit, 15),
    DEFINE_PROP_UINT32("bb-tx-status-bit", Esp32BtState,
                       bb_tx_status_bit, 14),
    DEFINE_PROP_BOOL("bb-tx-rwble", Esp32BtState, bb_tx_rwble, false),
    DEFINE_PROP_UINT64("bb-tx-poll-ns", Esp32BtState,
                       bb_tx_poll_ns, 200000),
    DEFINE_PROP_UINT64("bb-tx-delay-ns", Esp32BtState,
                       bb_tx_delay_ns, 1000000),
    DEFINE_PROP_END_OF_LIST(),
};

static const TypeInfo esp32_bt_info = {
    .name = TYPE_ESP32_BT,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32BtState),
    .instance_init = esp32_bt_init,
    .class_init = esp32_bt_class_init,
};

static void esp32_bt_register_types(void)
{
    type_register_static(&esp32_bt_info);
}

type_init(esp32_bt_register_types)
