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
/*
 * KE (kernel event) timer comparator.
 *
 * ke_timer_hw_set() programs the absolute 10 ms target in RWBT 0x0b4 and
 * enables the mask at RWBT 0x00c bit 10.  ke_time() is
 * r_ea_time_get_halfslot_rounded() >> 4 masked to 23 bits, so the target and
 * that time source share units.  The real block raises status bit 10 at the
 * target; r_rwbt_isr() dispatches it to r_ke_event_set().  The opt-in
 * bb-ke-timer model reproduces that comparator so the controller's own
 * software timers (supervision timeout, channel assessment, ...) expire.
 */
#define RWBT_KE_TARGET       0x0b4
#define RWBT_KE_STATUS_BIT   10
#define RWBT_KE_MASK         (1u << RWBT_KE_STATUS_BIT)
#define ESP32_BT_KE_UNIT_NS  10000000ull
#define ESP32_BT_KE_WRAP     0x7fffffu
#define ESP32_BT_KE_HALF     0x3fffffu
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
    ESP32_BT_TMR_BLE_EVT_WATCH,
    ESP32_BT_TMR_BLE_EVT_START,
    ESP32_BT_TMR_BLE_EVT_END,
    ESP32_BT_TMR_KE,
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
static uint32_t esp32_bt_guest_read(Esp32BtState *s, uint32_t addr, size_t size);
static void esp32_bt_guest_write(Esp32BtState *s, uint32_t addr, uint32_t v,
                                 size_t size);
static bool esp32_bt_ble_evt_state(Esp32BtState *s, uint32_t *link_out,
                                   uint32_t *tx_out);
static bool esp32_bt_ble_evt_program(Esp32BtState *s, uint32_t link,
                                     uint32_t tx, uint32_t *idx_out,
                                     uint32_t *hdr_out, uint32_t *bufidx_out,
                                     uint32_t *pend_out);
static void esp32_bt_ble_evt_move_inflight(Esp32BtState *s, uint32_t link,
                                           uint32_t tx);
static Esp32BtState *esp32_bt_plugin_state;

/*
 * Convert an event duration in microseconds to 625 us slot units with the
 * same 0xd1b71759 multiply-high and >>9 step the ROM uses in
 * r_lld_evt_move_to_master and r_lld_evt_restart.  Keeping the arithmetic
 * identical makes the modelled RX window the value the LLD itself derives
 * from `link + 0x12`.
 */
static uint32_t esp32_bt_ble_evt_slots(uint32_t us)
{
    return (uint32_t)((((uint64_t)us * 0xd1b71759ull) >> 32) >> 9);
}

/*
 * Decode the LLD's RX-window end.  `link + 0x78` is a 32-bit word whose low
 * half is the slot-unit timestamp at which the radio closes the receive
 * window and whose high half (`link + 0x7a`) is the connection-event counter
 * the LLD maintains for the activity.  `r_lld_evt_schedule` derives
 * `rxwinsz = window_end - target` from the same word.  A zero or implausibly
 * wrapped window cannot describe the upcoming event, so the caller supplies
 * the fallback (the LLD duration converted to slots).
 */
static uint32_t esp32_bt_ble_evt_window(Esp32BtState *s, uint32_t link,
                                        uint32_t target, uint32_t *count_out,
                                        uint32_t fallback)
{
    uint32_t word = esp32_bt_guest_read(s, link + s->bb_ble_evt_window_off, 4);
    uint32_t win = ((word & 0xffffu) - (target & 0xffffu)) & 0xffffu;

    *count_out = word >> 16;
    if (win == 0 || win > 0x3fffu) {
        return fallback;
    }
    return win;
}

static uint32_t esp32_bt_bt_clk(Esp32BtState *s)
{
    /* BR/EDR and BLE native clock: one tick is 312.5 us. */
    uint64_t now_ns = esp32_bt_now_ns(s);
    uint64_t clk = now_ns / 312500;

    /*
     * r_ea_finetimer_isr only runs the EA element whose programmed target
     * equals the half-slot clock it reads (a3 == a5 at 0x4001571c).  The ISR
     * reads that clock once at entry, and on silicon the interrupt is taken
     * inside the target slot, so the read-back clock is still the target.  A
     * host-time clock keeps advancing between the model's fire and the guest's
     * read, which would make the comparison miss by one or more slots and drop
     * the event.  Hold the clock at the fired target for the read at ISR
     * entry, keeping the floor monotonic afterwards.  This is a model
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
 * Opt-in KE timer comparator (bb-ke-timer).
 *
 * The controller's ke_time() is
 * ((((RWBT_0x01c & 0x0fffffff) + 1) >> 1) >> 4) & 0x7fffff, i.e. 10 ms units
 * (r_ea_time_get_halfslot_rounded() followed by a >> 4 in ROM ke_time).
 * ke_timer_hw_set() stores the absolute target in RWBT 0x0b4 and enables the
 * interrupt at 0x00c bit 10.  The model schedules one expiry and raises
 * RWBT status bit 10, which r_rwbt_isr() dispatches to r_ke_event_set(); the
 * controller then runs its own timer list.  This is opt-in so the earlier
 * slices keep their captured behaviour.
 */
static uint32_t esp32_bt_ke_now(Esp32BtState *s)
{
    uint32_t raw = esp32_bt_bt_clk(s) & ESP32_BT_EA_TIME_MASK;

    /* r_ea_time_get_halfslot_rounded() >> 4, masked like ROM ke_time(). */
    return ((((raw + 1) >> 1) >> 4) & ESP32_BT_KE_WRAP);
}

/*
 * Walk the controller's KE timer list (ke_env+40) for the modelled timer.
 * The list is sorted by target and every node stores next at +0, task id at
 * +4, timer id at +6 and the absolute target at +8 (ROM ke_timer_schedule and
 * r_ke_timer_set).  Only the matching timer is modelled; the LLD/LLM periodic
 * timers drive activities whose baseband side is absent, and expiring them
 * resets the controller.
 */
static uint32_t esp32_bt_ke_find(Esp32BtState *s)
{
    uint32_t node;
    int i;

    if (s->bb_ke_env_addr == 0) {
        return 0;
    }
    node = esp32_bt_guest_read(s, s->bb_ke_env_addr + 40, 4);
    for (i = 0; i < 16 && node != 0; i++) {
        uint32_t task = esp32_bt_guest_read(s, node + 4, 2);
        uint32_t id = esp32_bt_guest_read(s, node + 6, 2);

        if ((s->bb_ke_task == 0xffffffffu || task == s->bb_ke_task) &&
            (s->bb_ke_timer_id == 0xffffffffu ||
             id == s->bb_ke_timer_id)) {
            return node;
        }
        node = esp32_bt_guest_read(s, node, 4);
    }
    return 0;
}

static void esp32_bt_ke_fire(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t node, head;

    if (!s->bb_ke_timer || !s->ke_target_valid) {
        return;
    }
    node = s->ke_node;
    if (node == 0 || esp32_bt_ke_find(s) != node) {
        return;
    }
    head = esp32_bt_guest_read(s, s->bb_ke_env_addr + 40, 4);
    if (node != head) {
        /*
         * Promote the supervision timer to the list head so the controller's
         * ke_timer_schedule() sees it as the earliest entry.  Its earlier
         * neighbours are LLD/LLM housekeeping timers whose baseband side is
         * not modelled; leaving them ahead would make the controller process
         * those first.
         */
        esp32_bt_guest_write(s, node, head, 4);
        esp32_bt_guest_write(s, s->bb_ke_env_addr + 40, node, 4);
    }
    esp32_bt_guest_write(s, node + 8,
                         esp32_bt_ke_now(s) & ESP32_BT_KE_WRAP, 4);
    s->ke_pending = true;
    s->ke_target_valid = false;
    s->ke_node = 0;
    s->rwbt_irq_status |= RWBT_KE_MASK;
    ESP32_BT_LOG(s,
                  "esp32_bt: KE supervision expire node=%08x target=%08x "
                  "now=%08x status=%08x clock=%u\n",
                  node, s->ke_target, esp32_bt_ke_now(s), s->rwbt_irq_status,
                  esp32_bt_bt_clk(s));
    esp32_bt_update_irqs(s);
}

static void esp32_bt_ke_arm(Esp32BtState *s)
{
    uint32_t now;
    uint32_t delta;
    uint64_t delay_ns;

    if (!s->bb_ke_timer || !s->ke_target_valid || s->ke_pending) {
        esp32_bt_cancel(s, ESP32_BT_TMR_KE, s->ke_timer);
        return;
    }
    now = esp32_bt_ke_now(s);
    delta = (s->ke_target - now) & ESP32_BT_KE_WRAP;
    if (delta == 0 || delta > ESP32_BT_KE_HALF) {
        delay_ns = 1000000;  /* due: let the guest leave the caller first */
    } else {
        delay_ns = (uint64_t)delta * ESP32_BT_KE_UNIT_NS;
    }
    esp32_bt_sched(s, ESP32_BT_TMR_KE, s->ke_timer, delay_ns);
}

static void esp32_bt_ke_scan(Esp32BtState *s)
{
    uint32_t node;

    if (!s->bb_ke_timer) {
        return;
    }
    node = esp32_bt_ke_find(s);
    if (node == 0) {
        s->ke_node = 0;
        s->ke_target_valid = false;
        esp32_bt_cancel(s, ESP32_BT_TMR_KE, s->ke_timer);
        return;
    }
    if (s->ke_node == node && s->ke_target_valid) {
        uint32_t target = esp32_bt_guest_read(s, node + 8, 4);

        if (target == s->ke_target) {
            return;
        }
    }
    s->ke_node = node;
    s->ke_target = esp32_bt_guest_read(s, node + 8, 4);
    s->ke_target_valid = true;
    s->ke_pending = false;
    esp32_bt_ke_arm(s);
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

#define ESP32_BT_RX_MAX_PAYLOAD 1024

/*
 * Decode a hex payload property ("0102" or "01:02").  Returns the number of
 * bytes written, or 0 when the string is empty, odd-length or malformed.
 */
static uint32_t esp32_bt_parse_hex_payload(const char *text, uint8_t *out,
                                           uint32_t max)
{
    uint32_t n = 0;
    int hi = -1;

    for (; *text; text++) {
        int v;

        if (*text == ':' || *text == ' ' || *text == '-') {
            continue;
        }
        if (*text >= '0' && *text <= '9') {
            v = *text - '0';
        } else if (*text >= 'a' && *text <= 'f') {
            v = *text - 'a' + 10;
        } else if (*text >= 'A' && *text <= 'F') {
            v = *text - 'A' + 10;
        } else {
            return 0;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= max) {
                return 0;
            }
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return hi < 0 ? n : 0;
}

static void esp32_bt_rx_frame_inject(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t desc, next, payload_off, staging_off;
    uint32_t i, len, pattern_len;
    const uint8_t *pattern = esp32_bt_rx_pattern;
    uint8_t hex_payload[ESP32_BT_RX_MAX_PAYLOAD];
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

    pattern_len = sizeof(esp32_bt_rx_pattern);
    if (s->bb_rx_payload && s->bb_rx_payload[0]) {
        uint32_t n = esp32_bt_parse_hex_payload(s->bb_rx_payload,
                                                hex_payload,
                                                sizeof(hex_payload));

        if (n == 0) {
            ESP32_BT_LOG(s,
                          "esp32_bt: RX inject skipped: invalid "
                          "bb-rx-payload\n");
            return;
        }
        pattern = hex_payload;
        pattern_len = n;
        len = n;
    } else {
        len = MIN(s->bb_rx_payload_len, pattern_len);
    }

    /*
     * DMA order: payload first, then the descriptor words, then the owner
     * pointer, then the status bit.  The guest callback only observes the
     * final state, but the trace records this order for the claim.
     */
    for (i = 0; i < len; i++) {
        esp32_bt_em_write8(s, payload_off + i, pattern[i]);
    }
    for (i = 0; i < 20; i++) {
        esp32_bt_em_write8(s, staging_off + i, i < len ? pattern[i] : 0);
    }

    act_word = (uint16_t)(((s->bb_rx_activity & 0x1fu) << 11) |
                          (s->bb_rx_status_low & 0x7ffu));
    esp32_bt_em_write16(s, desc + 0x00, (uint16_t)(next | 0x8000u));
    esp32_bt_em_write16(s, desc + 0x02, act_word);
    esp32_bt_em_write16(s, desc + 0x04,
                        (uint16_t)((s->bb_rx_packet_type & 0x0fu) << 3));
    esp32_bt_em_write16(s, desc + 0x06,
                        (uint16_t)(((len & 0x3ffu) << 3) |
                                   (s->bb_rx_len_flags & 0x3u)));
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
    s->ea_diag_pending = true;
    {
        uint64_t target_ticks = (uint64_t)s->ea_target * 2u;

        if (target_ticks > s->clock_floor) {
            s->clock_floor = target_ticks;
        }
        /*
         * The ROM's r_ea_time_get_halfslot_rounded() samples the native
         * clock once at ISR entry; on silicon the fine-timer interrupt is
         * taken inside the target slot.  r_ea_finetimer_isr then requires the
         * sampled half-slot to equal the element start exactly.  Under TCG the
         * guest can service the interrupt a millisecond or more after the
         * model raises it, so a sub-slot hold lets the clock move past the
         * target and the due check fails.  Pin the guest-visible clock to the
         * fired target until the ISR has run (bounded, so a lost interrupt
         * cannot freeze the clock).
         */
        s->clock_hold_until = esp32_bt_now_ns(s) + 5000000;
    }
    if (s->bb_ea_rwble) {
        s->rwble_irq_status |= 1u << (s->bb_ea_ble_status_bit & 31u);
    } else {
        s->rwbt_irq_status |= 1u << RWBT_EA_STATUS_BIT;
    }
    ESP32_BT_LOG(s,
                  "esp32_bt: EA fine fire n=%u target=%08x now=%08x "
                  "status=%08x clock=%u\n",
                  s->ea_fires, s->ea_target, esp32_bt_ea_now_slot(s),
                  s->bb_ea_rwble ? s->rwble_irq_status : s->rwbt_irq_status,
                  esp32_bt_bt_clk(s));
    if (s->bb_ble_evt_ea_env_addr != 0) {
        /*
         * Name the elements the controller's arbiter will run.  ea_env+0 is
         * the list head, ea_env+0x14 the current element; an element carries
         * next at +0, target at +8, interval at +0xc, flags at +0x10,
         * durations at +0x18/+0x19/+0x1a, the start callback at +0x1c and the
         * stop/cancel callbacks at +0x20/+0x24 (from r_ea_elt_insert and
         * r_ea_finetimer_isr).  Logged so the EA hand-off is observable
         * without a gdb pass.
         */
        uint32_t elt = esp32_bt_guest_read(s, s->bb_ble_evt_ea_env_addr, 4);
        uint32_t curr = esp32_bt_guest_read(s,
                             s->bb_ble_evt_ea_env_addr +
                             s->bb_ble_evt_ea_curr_off, 4);
        uint32_t sw = esp32_bt_guest_read(s,
                             s->bb_ble_evt_ea_env_addr + 0x40, 4);
        int i;

        ESP32_BT_LOG(s,
                      "esp32_bt: EA fine list head=%08x curr=%08x "
                      "sw=%08x clock=%u\n",
                      elt, curr, sw, esp32_bt_bt_clk(s));
        for (i = 0; i < 4 && elt != 0; i++) {
            uint32_t next = esp32_bt_guest_read(s, elt, 4);
            uint32_t target = esp32_bt_guest_read(s, elt + 8, 4);
            uint32_t interval = esp32_bt_guest_read(s, elt + 0xc, 4);
            uint32_t flags = esp32_bt_guest_read(s, elt + 0x10, 2);
            uint32_t start = esp32_bt_guest_read(s, elt + 0x1c, 4);
            uint32_t stop = esp32_bt_guest_read(s, elt + 0x20, 4);
            uint32_t cancel = esp32_bt_guest_read(s, elt + 0x24, 4);

            ESP32_BT_LOG(s,
                          "esp32_bt: EA fine elt[%d]=%08x next=%08x "
                          "target=%08x interval=%08x flags=%04x "
                          "start=%08x stop=%08x cancel=%08x "
                          "b16=%02x b17=%02x b18=%02x b19=%02x\n",
                          i, elt, next, target, interval, flags,
                          start, stop, cancel,
                          esp32_bt_guest_read(s, elt + 0x16, 1),
                          esp32_bt_guest_read(s, elt + 0x17, 1),
                          esp32_bt_guest_read(s, elt + 0x18, 1),
                          esp32_bt_guest_read(s, elt + 0x19, 1));
            elt = next;
        }
    }

    /*
     * Baseband activity-start condition.  The controller's event arbiter only
     * runs an element's start callback; it does not mark the activity active.
     * In silicon the baseband starts the activity at the programmed target
     * and transitions it to its running state before the callback sees it.  For a connection that is the per-activity LL-PDU descriptor, the
     * link id and the active event state, so model them here, before the
     * fine-timer interrupt lets r_ea_finetimer_isr pop the element and call
     * r_lld_evt_schedule with the link already active.
     */
    if (s->bb_ble_evt_ctrl_start && s->bb_ble_evt_inject &&
        !s->bb_ble_evt_fired && !s->bb_ble_evt_started &&
        s->bb_ble_evt_ea_env_addr != 0) {
        uint32_t link = 0, tx = 0;
        bool have_link = esp32_bt_ble_evt_state(s, &link, &tx);
        uint32_t head = esp32_bt_guest_read(s, s->bb_ble_evt_ea_env_addr, 4);
        uint32_t target = link ? esp32_bt_guest_read(s, link + 8, 4) : 0;
        uint32_t dur = link ? esp32_bt_guest_read(s, link + 0x19, 1) : 0;
        uint32_t start = (target - dur) & ESP32_BT_EA_WRAP_MASK;

        ESP32_BT_LOG(s,
                      "esp32_bt: BLE start condition link=%08x have=%d tx=%08x "
                      "head=%08x target=%08x start=%08x fire=%08x clock=%u\n",
                      link, have_link, tx, head, target, start,
                      s->ea_target, esp32_bt_bt_clk(s));
        if (have_link &&
            (tx != 0 || s->bb_ble_evt_empty_start || s->bb_ble_evt_peer) &&
            head == link) {
            if (start == (s->ea_target & ESP32_BT_EA_WRAP_MASK)) {
                uint32_t idx, hdr, bufidx, pend;
                uint32_t win_us = 0, win_slots = 0, interval = 0;

                s->bb_ble_evt_started = true;
                s->bb_ble_evt_wait = 0;
                esp32_bt_ble_evt_program(s, link, tx, &idx, &hdr, &bufidx,
                                         &pend);
                esp32_bt_ble_evt_move_inflight(s, link, tx);
                s->bb_ble_evt_tx = tx;
                esp32_bt_guest_write(s, link + s->bb_ble_evt_lid_off,
                                     s->bb_ble_evt_handle & 0xffffu, 2);
                if (s->bb_ble_evt_ctrl_timing) {
                    /*
                     * Derive the event window and duration from the LLD's
                     * own event state instead of the model constants.
                     *
                     * `link + 0x12` is the event duration in microseconds
                     * that r_lld_evt_move_to_master hands to the radio
                     * descriptor (it converts it to slots with the same
                     * 0xd1b71759 / 2^41 step used here).  The RX window end
                     * at `link + 0x78` follows the arbiter duration, so the
                     * baseband programming matches the value the LLD will
                     * read back in r_lld_evt_schedule.  `link + 0x94` is the
                     * connection interval in slot units, which the controller
                     * adds to the target for the next event; it is logged so
                     * the interval advance is attributable to controller state.
                     */
                    win_us = esp32_bt_guest_read(
                        s, link + s->bb_ble_evt_duration_off, 2);
                    win_slots = esp32_bt_ble_evt_slots(win_us);
                    if (win_slots == 0) {
                        win_slots = 1;
                    }
                    interval = esp32_bt_guest_read(
                        s, link + s->bb_ble_evt_interval_off, 2);
                    if (s->bb_ble_evt_end_cond) {
                        /*
                         * Reuse the window end the controller maintained for
                         * the previous event when it still describes this
                         * target.  r_lld_evt_restart writes `+0x78` after the
                         * event it just finished, so the field is usually one
                         * event behind; seed it from the LLD duration only
                         * when it cannot describe this target.
                         */
                        uint32_t count = 0;
                        uint32_t win = esp32_bt_ble_evt_window(
                            s, link, target, &count, 0);

                        if (win == 0) {
                            win = win_slots;
                            esp32_bt_guest_write(
                                s, link + s->bb_ble_evt_window_off,
                                (((target + win) & 0xffffu) |
                                 (count << 16)), 4);
                        }
                        s->bb_ble_evt_window_slots = win;
                        s->bb_ble_evt_window_count = count;
                    } else {
                        esp32_bt_guest_write(
                            s, link + s->bb_ble_evt_window_off,
                            (target + win_slots) & 0xffffu, 2);
                    }
                    ESP32_BT_LOG(s,
                                  "esp32_bt: BLE event timing win=%uus "
                                  "wslots=%u interval=%04x end=%08x "
                                  "clock=%u\n",
                                  win_us, win_slots, interval,
                                  esp32_bt_guest_read(
                                      s, link + s->bb_ble_evt_window_off, 4),
                                  esp32_bt_bt_clk(s));
                } else if (s->bb_ble_evt_rxwinsz != 0) {
                    /*
                     * The LLD event-start path derives the RX window size
                     * from link+0x78 minus the event target.  In silicon the
                     * baseband fills that field when it activates the
                     * activity; without it r_lld_evt_schedule asserts on the
                     * window size.
                     */
                    esp32_bt_guest_write(
                        s, link + s->bb_ble_evt_window_off,
                        (target + s->bb_ble_evt_rxwinsz) & 0xffffu, 2);
                }
                esp32_bt_guest_write(s, link + s->bb_ble_evt_state_off,
                                     s->bb_ble_evt_state_value, 1);
                if (tx == 0) {
                    ESP32_BT_LOG(s,
                                  "esp32_bt: BLE baseband empty event "
                                  "start link=%08x lid=%04x target=%08x "
                                  "start=%08x state=%02x clock=%u\n",
                                  link, s->bb_ble_evt_handle & 0xffffu,
                                  target, start,
                                  esp32_bt_guest_read(
                                      s, link + s->bb_ble_evt_state_off, 1),
                                  esp32_bt_bt_clk(s));
                } else {
                    ESP32_BT_LOG(s,
                                  "esp32_bt: BLE baseband event start "
                                  "link=%08x lid=%04x desc=%02x hdr=%04x "
                                  "off=%04x buf=%02x pend=%02x target=%08x "
                                  "start=%08x state=%02x clock=%u\n",
                                  link, s->bb_ble_evt_handle & 0xffffu, idx,
                                  hdr, s->bb_ble_evt_txbuf_off, bufidx, pend,
                                  target, start,
                                  esp32_bt_guest_read(
                                      s, link + s->bb_ble_evt_state_off, 1),
                                  esp32_bt_bt_clk(s));
                }
            }
        }
    }
    esp32_bt_update_irqs(s);
}

static void esp32_bt_ea_rearm(Esp32BtState *s)
{
    uint64_t delay_ns;
    uint32_t now_slot, delta;

    if (!s->bb_ea_model) {
        return;
    }
    /*
     * Controller-driven BLE event start: hold the fine timer only while the
     * LLM create-connection transaction is in flight.  llm_elt+4 holds the
     * pending request element and returns to zero when r_llm_con_req_tx_cfm
     * consumes it.  Firing the initiator event tears down the state that the
     * harness-injected peer confirmation needs, so the model waits for that
     * transaction and leaves every other activity to the controller's own
     * arbiter.
     */
    if (s->bb_ble_evt_ctrl_start) {
        bool ready = true;
        bool gate_active = false;
        uint32_t gate_link = 0;
        uint32_t gate_target = 0;

        if (s->bb_ble_evt_llm_elt_addr != 0) {
            uint32_t cur = esp32_bt_guest_read(
                s, s->bb_ble_evt_llm_elt_addr + 4, 4);

            /*
             * r_lld_con_start publishes the initiator request element at
             * llm_elt+4 and r_llm_con_req_tx_cfm consumes it, which clears
             * the word before the established link stores its own element.
             * Only hold the arbiter once that transaction has started: an
             * initiator event would otherwise end before the harness-injected
             * peer confirmation arrives, while holding the timer from boot
             * stalls the inquiry/scan scheduling and can wedge the controller.
             */
            if (cur != 0) {
                s->bb_ble_evt_init_elt = cur;
            } else if (s->bb_ble_evt_init_elt != 0) {
                s->bb_ble_con_pending = true;
            }
            if (s->bb_ble_evt_init_elt != 0) {
                gate_active = true;
                if (!s->bb_ble_con_pending) {
                    ready = false;
                }
            }
        }
        if (gate_active && ready) {
            uint32_t link = 0, tx = 0;

            if (esp32_bt_ble_evt_state(s, &link, &tx)) {
                gate_link = link;
                gate_target = esp32_bt_guest_read(s, link + 8, 4);
            }
        }
        if (gate_active && !ready) {
            if (s->bb_ble_evt_gate_waits++ < 1000) {
                esp32_bt_cancel(s, ESP32_BT_TMR_EA_FINE, s->bb_fine_timer);
                s->ea_armed = false;
                ESP32_BT_LOG(s,
                              "esp32_bt: EA gate hold pending=%d seen=%d "
                              "link=%08x elt_target=%08x target=%08x "
                              "clock=%u\n",
                              s->bb_ble_evt_llm_elt_addr != 0 ?
                              (int)esp32_bt_guest_read(s,
                                  s->bb_ble_evt_llm_elt_addr + 4, 4) : -1,
                              s->bb_ble_con_pending, gate_link, gate_target,
                              s->ea_target, esp32_bt_bt_clk(s));
                return;
            }
            /*
             * The LLM request element can be consumed between two reads of
             * llm_elt + 4 (the peer confirmation runs as one host call), in
             * which case the "pending consumed" edge is never observed and
             * an unbounded hold wedges the arbiter.  Release after ~200 ms of
             * poll time; the start block still verifies the element and the
             * queued PDU before it models the event.
             */
            ESP32_BT_LOG(s,
                          "esp32_bt: EA gate release link=%08x target=%08x "
                          "waits=%u clock=%u\n",
                          gate_link, gate_target, s->bb_ble_evt_gate_waits,
                          esp32_bt_bt_clk(s));
            s->bb_ble_con_pending = true;
        }
        s->bb_ble_evt_gate_waits = 0;
        if (gate_active && ready &&
            s->bb_ble_evt_ea_env_addr != 0 && gate_link != 0 &&
            !s->bb_ble_evt_parked) {
            /*
             * Park the arbiter on no current element once, when the first
             * connection event is armed.  The fine-timer ISR uses the current
             * element's target for its due check, and the
             * pagescan/inquiry-scan elements left there by the earlier
             * activities have targets in the past.  The hardware would have
             * stopped them at their own expiry; without a baseband they never
             * were, so the model clears the stale current slot once for the
             * hand-off.  This is model state repair, not silicon timing.
             */
            uint32_t oldcurr = esp32_bt_guest_read(
                s, s->bb_ble_evt_ea_env_addr + s->bb_ble_evt_ea_curr_off, 4);

            s->bb_ble_evt_parked = true;
            if (oldcurr != 0) {
                ESP32_BT_LOG(s,
                              "esp32_bt: EA park curr=%08x -> 0 head=%08x "
                              "target=%08x clock=%u\n",
                              oldcurr,
                              esp32_bt_guest_read(
                                  s, s->bb_ble_evt_ea_env_addr, 4),
                              s->ea_target, esp32_bt_bt_clk(s));
            }
            esp32_bt_guest_write(s,
                                 s->bb_ble_evt_ea_env_addr +
                                 s->bb_ble_evt_ea_curr_off, 0, 4);
        }
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
 * Opt-in BLE connection-event model.
 *
 * The LLD queues an LE ACL PDU on the link object reached through
 * `llc_env[handle] + link_off`, but without a baseband the link id at
 * `link + lid_off` stays `0xffff` and no per-activity LL-PDU descriptor is
 * programmed.  The previous BLE slice assigned both from the gdb harness.
 * This model derives them from guest state instead:
 *
 *   1. poll the link's TX list (`link + txlist_off`) until it is non-empty;
 *   2. at the event-start tick, read the queued element's descriptor index,
 *      length and LLID, assign the link id and program the descriptor at
 *      `desc_base + 8*index` with payload offset `txbuf_off`.  It then models
 *      the LLD PDU programming step: the queued element moves from the TX
 *      queue (`txlist_off`) onto the in-flight list (`inflight_off`), so the
 *      controller's `r_lld_pdu_check` can consume it after the baseband
 *      acknowledgement.  Finally it models the LLD event-start transition:
 *      set the link event state (`link + state_off`), publish the link as the
 *      EA current element (`ea_env + ea_curr_off`) and push it onto the
 *      current-event list (`list_addr`);
 *   3. at the event-end tick, read the descriptor and payload back (the
 *      baseband read), set the descriptor TX-done bit and raise the RWBLE RX
 *      status bit, which the controller's `r_lld_evt_rx_isr`/`r_lld_evt_rx`
 *      turns into a deferred LLD element.  The deferred handler runs
 *      `r_lld_pdu_check`, frees the acknowledged PDU and emits the HCI
 *      completion.  Optionally it also raises the event-end status bit, which
 *      runs `r_lld_evt_end_isr`/`r_lld_evt_end` with the modelled state.
 *
 * The descriptor layout and field positions are the ones claimed for the
 * BLE EM region (spec/04 §3.10); the timing and every address are model
 * properties.  Nothing here is silicon or on-air evidence.
 */
static uint32_t esp32_bt_guest_read(Esp32BtState *s, uint32_t addr, size_t size)
{
    uint32_t v = 0;

    if (size == 0 || size > 4) {
        return 0;
    }
    address_space_read(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                       &v, size);
    return v;
}

static void esp32_bt_guest_write(Esp32BtState *s, uint32_t addr,
                                 uint32_t v, size_t size)
{
    if (size == 0 || size > 4) {
        return;
    }
    address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                        &v, size);
}

/* Resolve llc_env[handle] -> link object -> queued TX element. */
static bool esp32_bt_ble_evt_state(Esp32BtState *s, uint32_t *link_out,
                                   uint32_t *tx_out)
{
    uint32_t env, link, tx;

    if (s->bb_ble_evt_llc_env_addr == 0) {
        return false;
    }
    env = esp32_bt_guest_read(s,
                              s->bb_ble_evt_llc_env_addr +
                              4u * s->bb_ble_evt_handle, 4);
    if (env == 0) {
        return false;
    }
    link = esp32_bt_guest_read(s, env + s->bb_ble_evt_link_off, 4);
    if (link == 0) {
        return false;
    }
    tx = esp32_bt_guest_read(s, link + s->bb_ble_evt_txlist_off, 4);
    *link_out = link;
    *tx_out = tx;
    return true;
}

/*
 * Model the LLD PDU programming step.  r_lld_pdu_tx_prog packs the queued
 * element into the EM TX buffer and appends it to the PDU context's in-flight
 * list (pdu + 48), which r_lld_pdu_check walks after a baseband
 * acknowledgement.  Move the element from the TX queue to that list so the
 * controller can consume it on its own deferred-element path.
 */
static void esp32_bt_ble_evt_move_inflight(Esp32BtState *s, uint32_t link,
                                           uint32_t tx)
{
    uint32_t next, head, tail, qtail;

    if (!s->bb_ble_evt_inflight_move || tx == 0) {
        return;
    }
    next = esp32_bt_guest_read(s, tx, 4);
    head = esp32_bt_guest_read(s, link + s->bb_ble_evt_inflight_off, 4);
    tail = esp32_bt_guest_read(s, link + s->bb_ble_evt_inflight_tail_off, 4);
    if (head == 0) {
        head = tx;
        tail = tx;
    } else {
        if (tail == 0) {
            tail = head;
        }
        esp32_bt_guest_write(s, tail, tx, 4);
        tail = tx;
    }
    esp32_bt_guest_write(s, tx, 0, 4);
    esp32_bt_guest_write(s, link + s->bb_ble_evt_inflight_off, head, 4);
    esp32_bt_guest_write(s, link + s->bb_ble_evt_inflight_tail_off, tail, 4);

    /* Pop the element from the TX queue and repair its tail if needed. */
    esp32_bt_guest_write(s, link + s->bb_ble_evt_txlist_off, next, 4);
    qtail = esp32_bt_guest_read(s, link + s->bb_ble_evt_txlist_tail_off, 4);
    if (qtail == tx) {
        esp32_bt_guest_write(s, link + s->bb_ble_evt_txlist_tail_off, next, 4);
    }
    ESP32_BT_LOG(s,
                  "esp32_bt: BLE PDU in-flight link=%08x tx=%08x head=%08x "
                  "tail=%08x next=%08x clock=%u\n",
                  link, tx, head, tail, next, esp32_bt_bt_clk(s));
}

static void esp32_bt_ble_evt_poll(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t link = 0, tx = 0;

    if (!s->bb_ble_evt_inject || s->bb_ble_evt_fired) {
        s->bb_ble_evt_armed = false;
        return;
    }
    if (s->bb_ble_evt_ctrl_start) {
        /*
         * Controller-driven start: the model no longer synthesises the
         * event.  It waits for the controller's own event arbiter (the RWBT
         * 0x0b8 / RWBLE fine timer, driven by the bb-ea-timer model) to run
         * r_lld_evt_start, which programs the descriptor, assigns the link id
         * and sets the link event state.  The observable is that state byte;
         * once it appears the baseband end window is scheduled.
         */
        if (s->bb_ble_evt_started && !s->bb_ble_evt_end_armed &&
            esp32_bt_ble_evt_state(s, &link, &tx)) {
            uint32_t inflight = esp32_bt_guest_read(
                s, link + s->bb_ble_evt_inflight_off, 4);
            bool list_ready = true;

            /*
             * The controller's start callback (r_lld_evt_schedule) pushes
             * the link onto the current-event list at lld_evt_env; the event
             * end ISR pops that list.  Arming the end before the push
             * completes makes the end ISR find nothing and the LLD never
             * reschedules, so wait for the push (bounded, in case the
             * controller takes a path that never pushes).
             */
            if (s->bb_ble_evt_list_set && s->bb_ble_evt_list_addr != 0) {
                list_ready = esp32_bt_guest_read(
                                 s, s->bb_ble_evt_list_addr, 4) == link;
            }
            if (!list_ready && s->bb_ble_evt_wait < 150 &&
                s->bb_ble_evt_end_state != 0) {
                s->bb_ble_evt_wait++;
                esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_WATCH,
                               s->bb_ble_evt_poll_timer,
                               s->bb_ble_evt_poll_ns);
                return;
            }
            s->bb_ble_evt_wait = 0;
            s->bb_ble_evt_tx = inflight ? inflight : tx;
            s->bb_ble_evt_end_armed = true;
            ESP32_BT_LOG(s,
                          "esp32_bt: BLE controller event start "
                          "link=%08x lid=%04x tx=%08x inflight=%08x "
                          "state=%02x clock=%u\n",
                          link,
                          esp32_bt_guest_read(s,
                              link + s->bb_ble_evt_lid_off, 2),
                          tx, inflight,
                          esp32_bt_guest_read(s,
                              link + s->bb_ble_evt_state_off, 1),
                          esp32_bt_bt_clk(s));
            if (s->bb_ble_evt_end_cond) {
                /*
                 * Connection-event end condition.  The controller's RX-window
                 * end at `link + 0x78` (low half) and its event counter at
                 * `+0x7a` (high half) describe when the baseband closes the
                 * listen window.  The activity is idle when it has neither a
                 * queued nor an in-flight PDU and the pending-packet byte is
                 * zero; otherwise the end is the RX-window close after the
                 * exchange.  Both cases end at the controller's window, not at
                 * a duration constant.
                 */
                uint32_t target = esp32_bt_guest_read(s, link + 8, 4);
                uint32_t count = 0, pend = 0, end_slots;
                uint32_t win = esp32_bt_ble_evt_window(
                    s, link, target, &count, 0);
                bool idle = inflight == 0 && tx == 0;
                /* A response is posted at this event's end unless the peer
                 * budget is exhausted. */
                bool will_reply = s->bb_ble_evt_peer &&
                    !s->bb_ble_evt_peer_sent &&
                    (s->bb_ble_evt_peer_limit == 0 ||
                     s->bb_ble_evt_peer_posted < s->bb_ble_evt_peer_limit);

                if (s->bb_ble_evt_pend_off != 0) {
                    pend = esp32_bt_guest_read(
                        s, link + s->bb_ble_evt_pend_off, 1);
                    if (pend != 0) {
                        idle = false;
                    }
                }
                if (win == 0) {
                    /* No controller window describes this target yet. */
                    uint32_t win_us = esp32_bt_guest_read(
                        s, link + s->bb_ble_evt_duration_off, 2);

                    win = esp32_bt_ble_evt_slots(win_us);
                    if (win == 0) {
                        win = 1;
                    }
                    esp32_bt_guest_write(
                        s, link + s->bb_ble_evt_window_off,
                        (((target + win) & 0xffffu) | (count << 16)), 4);
                }
                s->bb_ble_evt_window_slots = win;
                s->bb_ble_evt_window_count = count;
                s->bb_ble_evt_idle = idle;
                /*
                 * Peer-side exchange.  The master's PDU is followed by the
                 * peer's response after T_IFS, so a real event ends at the
                 * response (or when neither side has more to send), not at
                 * the RX-window close.  Arm the end tick at the response and
                 * mark the cause "exchange"; the reply itself is posted at
                 * the end tick, before the RX status bit.
                 */
                end_slots = win;
                if (will_reply) {
                    uint32_t resp_slots =
                        (uint32_t)((s->bb_ble_evt_peer_delay_ns + 624999) /
                                   625000);

                    if (resp_slots == 0) {
                        resp_slots = 1;
                    }
                    if (resp_slots < end_slots) {
                        end_slots = resp_slots;
                    }
                }
                ESP32_BT_LOG(s,
                              "esp32_bt: BLE event end condition "
                              "window=%08x target=%08x win=%u count=%u "
                              "pend=%02x inflight=%08x cause=%s%s clock=%u\n",
                              esp32_bt_guest_read(
                                  s, link + s->bb_ble_evt_window_off, 4),
                              target, win, count, pend, inflight,
                              will_reply ? "exchange" :
                              (idle ? "idle" : "rx-window"),
                              will_reply ? " resp=1" : "",
                              esp32_bt_bt_clk(s));
                esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_END,
                               s->bb_ble_evt_end_timer,
                               (uint64_t)end_slots * 625000ull);
                return;
            }
            if (s->bb_ble_evt_ctrl_timing) {
                /*
                 * End the event after the duration the LLD wrote for the
                 * radio descriptor rather than the model's fixed tick.  The
                 * field is re-read here because the start block ran before
                 * r_lld_evt_schedule and the controller may have refreshed
                 * it while programming the event.
                 */
                uint32_t win_us = esp32_bt_guest_read(
                    s, link + s->bb_ble_evt_duration_off, 2);

                if (win_us != 0) {
                    esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_END,
                                   s->bb_ble_evt_end_timer,
                                   (uint64_t)win_us * 1000ull);
                    return;
                }
            }
            esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_END,
                           s->bb_ble_evt_end_timer,
                           s->bb_ble_evt_duration_ns);
            return;
        }
        if (s->bb_ea_model && esp32_bt_ble_evt_state(s, &link, &tx)) {
            /*
             * Diagnostic only: name the connection element the controller
             * inserted.  The fine timer itself is armed by the 0x0b8 writes
             * through esp32_bt_ea_rearm, so no scheduling happens here.
             */
            uint32_t etarget = esp32_bt_guest_read(s, link + 8, 4);

            if (etarget != 0 && !s->bb_ble_evt_end_armed) {
                ESP32_BT_LOG(s,
                              "esp32_bt: BLE EA element link=%08x "
                              "next=%08x target=%08x state=%02x clock=%u\n",
                              link, esp32_bt_guest_read(s, link, 4),
                              etarget,
                              esp32_bt_guest_read(s,
                                  link + s->bb_ble_evt_state_off, 1),
                              esp32_bt_bt_clk(s));
            }
        }
        if (s->bb_ea_model) {
            /*
             * Once the connection transaction has completed there may be no
             * further RWBT 0x0b8 write (the controller programmed its target
             * while the gate held).  Re-evaluate the gate here so the stored
             * target is armed as soon as the arbiter may run.
             */
            esp32_bt_ea_rearm(s);
        }
        esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_WATCH,
                       s->bb_ble_evt_poll_timer, s->bb_ble_evt_poll_ns);
        return;
    }
    if (esp32_bt_ble_evt_state(s, &link, &tx) && tx != 0) {
        ESP32_BT_LOG(s,
                      "esp32_bt: BLE event watch fired link=%08x tx=%08x "
                      "handle=%u delay=%" PRIu64 "ns clock=%u\n",
                      link, tx, s->bb_ble_evt_handle,
                      s->bb_ble_evt_start_delay_ns, esp32_bt_bt_clk(s));
        esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_START,
                       s->bb_ble_evt_start_timer,
                       s->bb_ble_evt_start_delay_ns);
        return;
    }
    esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_WATCH, s->bb_ble_evt_poll_timer,
                   s->bb_ble_evt_poll_ns);
}

/*
 * Program the per-activity LL-PDU descriptor from a queued TX element and
 * account the attached buffer.  This is the radio-side data path: the
 * descriptor header carries length in bits 15:8 and LLID in 7:0, +6 carries
 * the buffer index and the attach bit, and the link's pending-packet byte
 * mirrors r_lld_pdu_data_tx_push (spec/04 §3.11).  Returns false when there
 * is no queued element.
 */
static bool esp32_bt_ble_evt_program(Esp32BtState *s, uint32_t link,
                                     uint32_t tx, uint32_t *idx_out,
                                     uint32_t *hdr_out, uint32_t *bufidx_out,
                                     uint32_t *pend_out)
{
    uint32_t idx, len, llid, bufidx, desc, hdr, pend = 0;
    uint32_t lid = s->bb_ble_evt_handle & 0xffffu;

    if (tx == 0) {
        *idx_out = 0;
        *hdr_out = 0;
        *bufidx_out = 0;
        *pend_out = 0;
        return false;
    }
    idx = esp32_bt_guest_read(s, tx + s->bb_ble_evt_tx_idx_off, 1);
    len = esp32_bt_guest_read(s, tx + s->bb_ble_evt_tx_len_off, 2);
    llid = esp32_bt_guest_read(s, tx + s->bb_ble_evt_tx_llid_off, 1);
    bufidx = esp32_bt_guest_read(s, tx + s->bb_ble_evt_tx_buf_off, 1);
    desc = s->bb_ble_evt_desc_base + 8u * idx;
    hdr = ((len & 0xffu) << 8) | (llid & 0xffu);

    esp32_bt_em_write16(s, desc + 0x00, (uint16_t)lid);
    esp32_bt_em_write16(s, desc + 0x02, (uint16_t)hdr);
    esp32_bt_em_write16(s, desc + 0x04, (uint16_t)s->bb_ble_evt_txbuf_off);
    esp32_bt_em_write16(s, desc + 0x06,
                        (uint16_t)((bufidx & 0xffu) |
                                   (1u << (s->bb_ble_evt_attach_bit & 15u))));

    if (s->bb_ble_evt_pend_off != 0) {
        pend = esp32_bt_guest_read(s, link + s->bb_ble_evt_pend_off, 1);
        pend = (pend + 1u) & 0xffu;
        esp32_bt_guest_write(s, link + s->bb_ble_evt_pend_off, pend, 1);
    }
    *idx_out = idx;
    *hdr_out = hdr;
    *bufidx_out = bufidx;
    *pend_out = pend;
    return true;
}

static void esp32_bt_ble_evt_start(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t link = 0, tx = 0, idx = 0, hdr = 0, desc = 0;
    uint32_t bufidx = 0, pend = 0;
    uint32_t lid = s->bb_ble_evt_handle & 0xffffu;

    if (!s->bb_ble_evt_inject || s->bb_ble_evt_fired) {
        return;
    }
    if (!esp32_bt_ble_evt_state(s, &link, &tx)) {
        /* The link disappeared before the event; go back to watching. */
        esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_WATCH,
                       s->bb_ble_evt_poll_timer, s->bb_ble_evt_poll_ns);
        return;
    }

    esp32_bt_ble_evt_program(s, link, tx, &idx, &hdr, &bufidx, &pend);
    if (tx != 0) {
        desc = s->bb_ble_evt_desc_base + 8u * idx;
        /*
         * Model the LLD PDU programming step: the queued element leaves the TX
         * queue and joins the in-flight list that r_lld_pdu_check walks.
         */
        s->bb_ble_evt_tx = tx;
        esp32_bt_ble_evt_move_inflight(s, link, tx);
    }

    /* Assign the connection's link id. */
    esp32_bt_guest_write(s, link + s->bb_ble_evt_lid_off, lid, 2);

    /*
     * Model the LLD event-start state transition.  A real start sets the
     * link event state, publishes the link as the EA current element and
     * moves it to the current-event co_list at lld_evt_env, which
     * r_lld_evt_end_isr pops.  Without a baseband none of that happens, so
     * the controller never takes the connection-event path.
     */
    esp32_bt_guest_write(s, link + s->bb_ble_evt_state_off,
                         s->bb_ble_evt_state_value, 1);
    if (s->bb_ble_evt_ea_env_addr != 0) {
        esp32_bt_guest_write(s,
                             s->bb_ble_evt_ea_env_addr +
                             s->bb_ble_evt_ea_curr_off, link, 4);
    }
    if (s->bb_ble_evt_start_push && s->bb_ble_evt_list_set &&
        s->bb_ble_evt_list_addr != 0) {
        uint32_t old = esp32_bt_guest_read(s, s->bb_ble_evt_list_addr, 4);

        esp32_bt_guest_write(s, link, old, 4);
        esp32_bt_guest_write(s, s->bb_ble_evt_list_addr, link, 4);
    }

    s->bb_ble_evt_events++;
    ESP32_BT_LOG(s,
                  "esp32_bt: BLE event start link=%08x lid=%04x desc=%02x "
                  "hdr=%04x off=%04x buf=%02x pend=%02x d6=%04x state=%02x "
                  "ea=%08x list=%08x events=%u clock=%u\n",
                  link, lid, idx, hdr, s->bb_ble_evt_txbuf_off, bufidx, pend,
                  tx != 0 ? esp32_bt_em_read16(s, desc + 0x06) : 0,
                  esp32_bt_guest_read(s,
                                      link + s->bb_ble_evt_state_off, 1),
                  s->bb_ble_evt_ea_env_addr != 0 ?
                  esp32_bt_guest_read(s,
                                      s->bb_ble_evt_ea_env_addr +
                                      s->bb_ble_evt_ea_curr_off, 4) : 0,
                  s->bb_ble_evt_list_set && s->bb_ble_evt_list_addr != 0 ?
                  esp32_bt_guest_read(s, s->bb_ble_evt_list_addr, 4) : 0,
                  s->bb_ble_evt_events, esp32_bt_bt_clk(s));
    esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_END, s->bb_ble_evt_end_timer,
                   s->bb_ble_evt_duration_ns);
}

/*
 * Peer-side PDU model.
 *
 * A connection event is an exchange: the master sends its PDU, the slave
 * answers after T_IFS, and the event ends when neither side has more data.  A
 * model that only transmits leaves the RX half of the event empty, so the
 * controller never runs its own receive path and every event ends at the
 * RX-window close.
 *
 * This function posts the peer's response into the controller's own em_buf RX
 * ring.  r_em_buf_init built that ring at EM 0x0948 with a 0x0c stride and a
 * free-running index at em_buf_env + 0x5c8; r_lld_pdu_rx_handler walks it from
 * that index, so posting there is what a receive interrupt would deliver.
 * The descriptor fields are the ones the ROM/RAM handler reads:
 *
 *   +0x00  u16  RX status/control; any bit in 0x13f drops the packet
 *   +0x02  u16  bits 15:11 = link id (compared with link + 104)
 *   +0x04  u16  bits 15:8 = length, bits 1:0 = LLID
 *   +0x06  u16  status word (bit 15 + bits 13:8)
 *   +0x08  u16  EM offset of the RX payload buffer
 *
 * Returns true when a response was posted.  The caller reports it through the
 * per-activity RX count so r_lld_evt_rx() runs r_lld_pdu_rx_handler() with the
 * matching count.
 */
static bool esp32_bt_ble_evt_peer_reply(Esp32BtState *s, uint32_t link);

/*
 * PDUs received in this event: the configured per-activity count plus the
 * peer response modelled above.  Both r_lld_evt_rx() and the end environment
 * must see the same number.
 */
static uint32_t esp32_bt_ble_evt_rx_count(Esp32BtState *s)
{
    return s->bb_ble_evt_rx_pdus + (s->bb_ble_evt_peer_sent ? 1u : 0u);
}

static bool esp32_bt_ble_evt_peer_reply(Esp32BtState *s, uint32_t link)
{
    uint32_t idx, desc, buf_off, len, cat, i, act, word;
    uint8_t payload[ESP32_BT_RX_MAX_PAYLOAD];
    uint16_t lid = s->bb_ble_evt_handle & 0xffffu;
    char hex[3 * 48 + 1];
    int pos = 0;

    if (!s->bb_ble_evt_peer || s->bb_ble_evt_peer_sent ||
        (s->bb_ble_evt_peer_limit != 0 &&
         s->bb_ble_evt_peer_posted >= s->bb_ble_evt_peer_limit) ||
        s->bb_ble_evt_rx_idx_addr == 0 || s->bb_ble_evt_rx_desc_count == 0) {
        return false;
    }

    len = 0;
    memset(payload, 0, sizeof(payload));
    if (s->bb_ble_evt_peer_payload && s->bb_ble_evt_peer_payload[0]) {
        len = esp32_bt_parse_hex_payload(s->bb_ble_evt_peer_payload, payload,
                                         sizeof(payload));
        if (len == 0) {
            ESP32_BT_LOG(s, "esp32_bt: BLE peer PDU skipped: invalid "
                            "bb-ble-evt-peer-payload\n");
            return false;
        }
    } else {
        len = MIN(s->bb_ble_evt_peer_len, sizeof(payload));
    }
    /* The em_buf RX buffers are 0x104 bytes; keep the copy inside one. */
    len = MIN(len, 251u);

    idx = esp32_bt_guest_read(s, s->bb_ble_evt_rx_idx_addr, 1) %
          s->bb_ble_evt_rx_desc_count;
    desc = s->bb_ble_evt_rx_desc_base + s->bb_ble_evt_rx_desc_stride * idx;
    /* Keep the buffer r_em_buf_init bound to this ring entry. */
    buf_off = esp32_bt_em_read16(s, desc + s->bb_ble_evt_rx_buf_field);
    for (i = 0; i < len; i++) {
        esp32_bt_em_write8(s, buf_off + i, payload[i]);
    }

    /*
     * The descriptor's low two bits carry the LLID, not an independent PDU
     * category: 3 = LL control, 2 = start of an LL data (L2CAP) PDU, 1 =
     * continuation, 0 = empty.  r_lld_pdu_rx_handler branches on this field,
     * so derive it from the LLID unless the slice overrides it.
     */
    cat = s->bb_ble_evt_peer_cat;
    if (cat == 0) {
        cat = s->bb_ble_evt_peer_llid & 3u;
    }
    esp32_bt_em_write16(s, desc + 0x00, 0);
    esp32_bt_em_write16(s, desc + 0x02, (uint16_t)(lid << 11));
    esp32_bt_em_write16(s, desc + 0x04,
                        (uint16_t)(((len & 0xffu) << 8) | (cat & 3u)));
    esp32_bt_em_write16(s, desc + 0x06, 0x8000);

    /*
     * Per-activity RX count.  r_lld_evt_rx() reads the status word's high
     * nibble and passes it to the PDU RX handler, so the count and the number
     * of posted descriptors must agree.
     */
    act = s->bb_ble_evt_act_base + s->bb_ble_evt_act_stride * s->bb_ble_evt_handle;
    word = esp32_bt_guest_read(s, act, 2);
    word = (word & 0x0fffu) | (((s->bb_ble_evt_rx_pdus + 1u) & 0xfu) << 12);
    esp32_bt_guest_write(s, act, word, 2);

    s->bb_ble_evt_peer_sent = true;
    s->bb_ble_evt_peer_posted++;

    for (i = 0; i < len && i < 48; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x", payload[i]);
    }
    hex[pos] = 0;
    ESP32_BT_LOG(s,
                  "esp32_bt: BLE peer PDU link=%08x idx=%u desc=%04x "
                  "lid=%04x llid=%u cat=%u len=%u off=%04x payload=%s "
                  "rx=1 clock=%u\n",
                  link, idx, desc, lid, s->bb_ble_evt_peer_llid, cat, len,
                  buf_off, hex, esp32_bt_bt_clk(s));
    return true;
}

/*
 * Baseband event-end environment.
 *
 * At the end of an activity the radio publishes what it transferred in the
 * per-activity EM status word and in two completion counters.  The ROM reads
 * them back from the controller side:
 *
 *   - r_lld_evt_rx() takes the status word's high nibble (bits 15:12) as the
 *     number of PDUs received in the event and adds it to the link's
 *     accounted-packet byte (link + 150);
 *   - r_lld_evt_end() sums the high bytes of the two u16 counters at +0x50
 *     and +0x52 and asserts (lld_evt.c 2411) that the sum covers the
 *     accounted count before flushing the surplus as completed packets.
 *
 * r_lld_con_start clears those counters, so a model that leaves them at zero
 * only survives as long as nothing is accounted: an event with no queued PDU
 * still fails the end-path precondition because the control word written at
 * connection setup (`+0x00 = 0x2000`) has `2` in the high nibble and the RX
 * path adds it.  Write the real per-event counts here, before the RX status
 * interrupt, so both ROM readers see a consistent event result.
 */
static void esp32_bt_ble_evt_end_env(Esp32BtState *s, uint32_t link)
{
    uint32_t act, comp, nb, word;

    if (!s->bb_ble_evt_end_env) {
        return;
    }
    act = s->bb_ble_evt_act_base +
          s->bb_ble_evt_act_stride * s->bb_ble_evt_handle;

    /* PDUs received in this event, read by r_lld_evt_rx(). */
    word = esp32_bt_guest_read(s, act, 2);
    word = (word & 0x0fffu) |
           ((esp32_bt_ble_evt_rx_count(s) & 0xfu) << 12);
    esp32_bt_guest_write(s, act, word, 2);

    /*
     * Completion counters, read by r_lld_evt_end().  The accounted count is
     * the link byte the RX path is about to raise by rx_pdus; report it here
     * so the end-path precondition holds for both empty and data events.
     */
    nb = (esp32_bt_guest_read(s, link + 150, 1) +
          esp32_bt_ble_evt_rx_count(s)) & 0xffu;
    comp = s->bb_ble_evt_act_comp_off;
    word = esp32_bt_guest_read(s, act + comp, 2);
    esp32_bt_guest_write(s, act + comp,
                         (word & 0x00ffu) | ((nb & 0xffu) << 8), 2);
    word = esp32_bt_guest_read(s, act + comp + 2, 2);
    esp32_bt_guest_write(s, act + comp + 2, word & 0x00ffu, 2);

    /*
     * Event-state transition.  The baseband owns the activity state byte at
     * link + state_off: it raises it when the event starts and lowers it when
     * the event is over.  Leaving the active value in place makes the LLD's
     * end path extend the event one slot at a time instead of scheduling the
     * next interval, so a non-zero end value is written here when configured.
     */
    if (s->bb_ble_evt_end_state != 0) {
        esp32_bt_guest_write(s, link + s->bb_ble_evt_state_off,
                             s->bb_ble_evt_end_state & 0xffu, 1);
    }

    ESP32_BT_LOG(s,
                  "esp32_bt: BLE event end environment act=%08x rx=%u "
                  "nb=%02x word=%04x clock=%u\n",
                  act, esp32_bt_ble_evt_rx_count(s), nb,
                  esp32_bt_guest_read(s, act, 2), esp32_bt_bt_clk(s));
}

static void esp32_bt_ble_evt_end(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t link = 0, tx = 0, idx = 0, hdr, len, llid, off;
    uint32_t desc, ack = 0;
    uint8_t payload[64];
    uint32_t i, n;
    char hex[3 * sizeof(payload) + 1];
    int pos = 0;

    if (!s->bb_ble_evt_inject || s->bb_ble_evt_fired) {
        return;
    }

    if (!esp32_bt_ble_evt_state(s, &link, &tx)) {
        s->bb_ble_evt_started = false;
        s->bb_ble_evt_end_armed = false;
        ESP32_BT_LOG(s, "esp32_bt: BLE event end without a link\n");
        return;
    }
    /*
     * The queued element moved to the in-flight list at the start tick; use
     * the pointer recorded then (the TX queue may be empty by the event end).
     */
    if (s->bb_ble_evt_tx != 0) {
        tx = s->bb_ble_evt_tx;
    }
    if (tx != 0) {
        idx = esp32_bt_guest_read(s, tx + s->bb_ble_evt_tx_idx_off, 1);
        desc = s->bb_ble_evt_desc_base + 8u * idx;
        hdr = esp32_bt_em_read16(s, desc + 0x02);
        off = esp32_bt_em_read16(s, desc + 0x04);
        len = (hdr >> 8) & 0xffu;
        llid = hdr & 0xffu;
        n = MIN(len, sizeof(payload));
        memset(payload, 0, sizeof(payload));
        for (i = 0; i < n; i++) {
            payload[i] = (uint8_t)esp32_bt_guest_read(s,
                              esp32_bt_em_base(s) + off + i, 1);
            pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x", payload[i]);
        }
        hex[pos] = 0;

        /*
         * Baseband TX acknowledgement.  When the radio has transmitted the
         * PDU it sets the TX-done bit in the descriptor link word; the LLD's
         * r_lld_pdu_check consumes elements whose +0 has this bit set.
         */
        if (s->bb_ble_evt_tx_ack) {
            uint32_t bit = 1u << (s->bb_ble_evt_ack_bit & 15u);

            ack = esp32_bt_em_read16(s, desc + 0x00);
            ack = (ack & ~bit) | bit;
            esp32_bt_em_write16(s, desc + 0x00, (uint16_t)ack);
        }

        ESP32_BT_LOG(s,
                      "esp32_bt: BLE event end link=%08x desc=%02x hdr=%04x "
                      "off=%04x len=%u llid=%u payload=%s ack=%04x clock=%u\n",
                      link, idx, hdr, off, len, llid, hex, ack,
                      esp32_bt_bt_clk(s));
    }

    /*
     * Peer-side PDU.  Post it before the end environment so the per-activity
     * RX count and the completion counters describe the whole exchange, and
     * before the RX status bit so r_lld_evt_rx() finds the descriptor.
     */
    esp32_bt_ble_evt_peer_reply(s, link);
    esp32_bt_ble_evt_end_env(s, link);

    if (tx == 0) {
        if (s->bb_ble_evt_end_cond && s->bb_ble_evt_idle) {
            ESP32_BT_LOG(s,
                          "esp32_bt: BLE idle event end link=%08x "
                          "window=%08x win=%u count=%u state=%02x "
                          "clock=%u\n",
                          link,
                          esp32_bt_guest_read(
                              s, link + s->bb_ble_evt_window_off, 4),
                          s->bb_ble_evt_window_slots,
                          s->bb_ble_evt_window_count,
                          esp32_bt_guest_read(s,
                              link + s->bb_ble_evt_state_off, 1),
                          esp32_bt_bt_clk(s));
        }
        ESP32_BT_LOG(s,
                      "esp32_bt: BLE empty event end link=%08x state=%02x "
                      "clock=%u\n",
                      link,
                      esp32_bt_guest_read(s,
                          link + s->bb_ble_evt_state_off, 1),
                      esp32_bt_bt_clk(s));
    }

    if (s->bb_ble_evt_raise_rx) {
        /*
         * The RWBLE ISR takes its combined RX + event-end path only when both
         * status bits are set (r_rwble_isr masks 0x0a and branches on 0x0a).
         * The baseband therefore reports the event result through the RX bit
         * as well, even when the event carried no PDU: r_lld_evt_rx() reads
         * the per-activity RX count (zero here) and pushes the deferred
         * element, and r_lld_evt_end_isr() runs the event-end path.  With the
         * end environment reporting zero RX PDUs the accounted-packet byte
         * (link + 150) stays zero, so the end-path precondition holds.
         */
        s->rwble_irq_status |= 1u << (s->bb_ble_evt_rx_status_bit & 31u);
        ESP32_BT_LOG(s, "esp32_bt: BLE event rx status bit %u -> %08x\n",
                     s->bb_ble_evt_rx_status_bit, s->rwble_irq_status);
        esp32_bt_update_irqs(s);
    }

    if (s->bb_ble_evt_raise_end) {
        /*
         * With the start push enabled the current-event list and the EA
         * current element were published at the start tick, so the end tick
         * only has to deliver the event-end interrupt.  Keep the legacy
         * harness-owned push for setups that disable the start transition.
         */
        if (!s->bb_ble_evt_start_push) {
            if (s->bb_ble_evt_list_set && s->bb_ble_evt_list_addr != 0) {
                esp32_bt_guest_write(s, s->bb_ble_evt_list_addr, link, 4);
                ESP32_BT_LOG(s,
                              "esp32_bt: BLE event list addr=%08x <- %08x "
                              "readback=%08x link_next=%08x\n",
                              s->bb_ble_evt_list_addr, link,
                              esp32_bt_guest_read(s, s->bb_ble_evt_list_addr,
                                                  4),
                              esp32_bt_guest_read(s, link, 4));
            }
            if (s->bb_ble_evt_ea_env_addr != 0) {
                esp32_bt_guest_write(s, s->bb_ble_evt_ea_env_addr, link, 4);
            }
        } else if (s->bb_ble_evt_ea_env_addr != 0 &&
                   s->bb_ble_evt_end_state != 0) {
            /*
             * The active activity owns the arbiter's current slot while its
             * event is running.  Other activities may have become current in
             * between (the controller re-arms them from the end path), so
             * name the connection link again right before the event-end
             * interrupt; r_lld_evt_end_isr and r_lld_evt_rx_isr resolve their
             * target through this slot.  Opt-in with the end-state
             * environment so the shipped slices keep their timing.
             */
            esp32_bt_guest_write(s,
                                 s->bb_ble_evt_ea_env_addr +
                                 s->bb_ble_evt_ea_curr_off, link, 4);
            ESP32_BT_LOG(s,
                          "esp32_bt: BLE event end curr=%08x link=%08x "
                          "clock=%u\n",
                          esp32_bt_guest_read(s,
                              s->bb_ble_evt_ea_env_addr +
                              s->bb_ble_evt_ea_curr_off, 4),
                          link, esp32_bt_bt_clk(s));
            if (s->bb_ble_evt_list_set && s->bb_ble_evt_list_addr != 0) {
                /*
                 * r_lld_evt_rx_isr and r_lld_evt_end_isr take the link from
                 * the current-event list at lld_evt_env.  An activity the
                 * model could not start (its link was not resolvable at the
                 * fired target) can still sit at that list's head, because
                 * its own event-end interrupt never ran.  Make the running
                 * connection the current event so both ISRs resolve it; this
                 * is model state repair for the missing end, not silicon
                 * list behaviour.
                 */
                uint32_t old = esp32_bt_guest_read(
                    s, s->bb_ble_evt_list_addr, 4);

                if (old != link) {
                    esp32_bt_guest_write(s, link, 0, 4);
                    esp32_bt_guest_write(s, s->bb_ble_evt_list_addr, link, 4);
                    ESP32_BT_LOG(s,
                                  "esp32_bt: BLE event list repair "
                                  "head=%08x link=%08x clock=%u\n",
                                  old, link, esp32_bt_bt_clk(s));
                }
            }
        }
        s->rwble_irq_status |= 1u << (s->bb_ble_evt_end_status_bit & 31u);
        ESP32_BT_LOG(s,
                      "esp32_bt: BLE event end status bit %u -> %08x\n",
                      s->bb_ble_evt_end_status_bit, s->rwble_irq_status);
        esp32_bt_update_irqs(s);
    }

    /*
     * An empty connection event only burns the next interval: keep the model
     * watching so the following event, which may carry the queued ACL PDU,
     * runs through the controller as well.  Stop after a data event.
     */
    s->bb_ble_evt_started = false;
    s->bb_ble_evt_end_armed = false;
    s->bb_ble_evt_wait = 0;
    s->bb_ble_evt_idle = false;
    s->bb_ble_evt_peer_sent = false;
    s->bb_ble_evt_window_slots = 0;
    s->bb_ble_evt_window_count = 0;
    if (s->bb_ble_evt_tx != 0 || tx != 0) {
        s->bb_ble_evt_fired = true;
    }
    s->bb_ble_evt_tx = 0;
    if (!s->bb_ble_evt_fired && s->bb_ble_evt_ctrl_start) {
        /* An empty event returns to watching: the next interval may carry
         * the queued PDU and must run through the same controller path. */
        esp32_bt_sched(s, ESP32_BT_TMR_BLE_EVT_WATCH,
                       s->bb_ble_evt_poll_timer, s->bb_ble_evt_poll_ns);
    }
}

static void esp32_bt_ble_evt_arm_start(Esp32BtState *s)
{
    if (!s->bb_ble_evt_inject || s->bb_ble_evt_llc_env_addr == 0 ||
        s->bb_ble_evt_armed || s->bb_ble_evt_fired) {
        return;
    }
    s->bb_ble_evt_armed = true;
    ESP32_BT_LOG(s,
                  "esp32_bt: BLE event watch armed llc_env=%08x handle=%u "
                  "poll=%" PRIu64 "ns clock=%u\n",
                  s->bb_ble_evt_llc_env_addr, s->bb_ble_evt_handle,
                  s->bb_ble_evt_poll_ns, esp32_bt_bt_clk(s));
    esp32_bt_ble_evt_poll(s);
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
    case ESP32_BT_TMR_BLE_EVT_WATCH:
        esp32_bt_ble_evt_poll(s);
        break;
    case ESP32_BT_TMR_BLE_EVT_START:
        esp32_bt_ble_evt_start(s);
        break;
    case ESP32_BT_TMR_BLE_EVT_END:
        esp32_bt_ble_evt_end(s);
        break;
    case ESP32_BT_TMR_KE:
        esp32_bt_ke_fire(s);
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
    esp32_bt_ble_evt_arm_start(s);

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
        if (s->ea_diag_pending && s->bb_ble_evt_ea_env_addr != 0) {
            uint32_t head = esp32_bt_guest_read(
                s, s->bb_ble_evt_ea_env_addr, 4);
            uint32_t curr = esp32_bt_guest_read(
                s, s->bb_ble_evt_ea_env_addr +
                s->bb_ble_evt_ea_curr_off, 4);
            uint32_t target = head ? esp32_bt_guest_read(s, head + 8, 4) : 0;
            uint32_t dur = head ? esp32_bt_guest_read(s, head + 0x19, 1) : 0;

            s->ea_diag_pending = false;
            ESP32_BT_LOG(s,
                          "esp32_bt: EA isr clock read=%08x head=%08x "
                          "curr=%08x target=%08x dur=%02x start=%08x "
                          "now=%08x clock=%u\n",
                          r, head, curr, target, dur,
                          (target - dur) & (uint32_t)ESP32_BT_EA_WRAP_MASK,
                          esp32_bt_ea_now_slot(s), esp32_bt_bt_clk(s));
        }
        break;
    case RWBLE_WAKEUP_BOUND:
        r = s->rwbt[off / 4] & ~BT_WAKEUP_SELF_CLEAR;
        break;
    case RWBT_CLK_LO:
    case RWBLE_CLK_LO:
        r = esp32_bt_bt_clk(s);
        break;
    case RWBT_KE_TARGET:
        r = s->rwbt[off / 4];
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
    esp32_bt_ble_evt_arm_start(s);

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
        if (v & RWBT_KE_MASK) {
            s->ke_pending = false;
            esp32_bt_cancel(s, ESP32_BT_TMR_KE, s->ke_timer);
        }
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

        /*
         * r_rwble_isr() acknowledges the BLE fine-timer expiry through this
         * register before it dispatches r_ea_finetimer_isr.  Clear the
         * pending marker so the next programmed target can arm again.
         */
        if (s->bb_ea_rwble &&
            (v & (1u << (s->bb_ea_ble_status_bit & 31u)))) {
            s->ea_status_pending = false;
            esp32_bt_ea_rearm(s);
        }
        break;
    case RWBT_ISR_ENABLE:
        s->rwbt_irq_enable = v;
        break;
    case RWBT_INT_MASK:
        s->rwbt[off / 4] = v;
        s->ea_mask_enabled = (v >> RWBT_EA_STATUS_BIT) & 1u;
        esp32_bt_ea_rearm(s);
        if (s->bb_ke_timer && !(v & RWBT_KE_MASK)) {
            esp32_bt_cancel(s, ESP32_BT_TMR_KE, s->ke_timer);
        }
        break;
    case RWBT_KE_TARGET:
        s->rwbt[off / 4] = v;
        esp32_bt_ke_scan(s);
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
            timer_del(s->bb_ble_evt_poll_timer);
            timer_del(s->bb_ble_evt_start_timer);
            timer_del(s->bb_ble_evt_end_timer);
            for (int i = 0; i < ESP32_BT_TMR_COUNT; i++) {
                s->model_active[i] = false;
            }
            s->bb_tx_watch_armed = false;
            s->bb_tx_armed = false;
            if (s->bb_tx_inject && !s->bb_tx_fired) {
                esp32_bt_tx_watch_arm_start(s);
            }
            s->bb_ble_evt_armed = false;
            if (s->bb_ble_evt_inject && !s->bb_ble_evt_fired) {
                esp32_bt_ble_evt_arm_start(s);
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
    esp32_bt_ble_evt_arm_start(s);

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
    esp32_bt_ble_evt_arm_start(s);
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
    esp32_bt_cancel(s, ESP32_BT_TMR_BLE_EVT_WATCH, s->bb_ble_evt_poll_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_BLE_EVT_START, s->bb_ble_evt_start_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_BLE_EVT_END, s->bb_ble_evt_end_timer);
    esp32_bt_cancel(s, ESP32_BT_TMR_KE, s->ke_timer);
    s->ke_target = 0;
    s->ke_node = 0;
    s->ke_target_valid = false;
    s->ke_pending = false;
    s->bb_ble_evt_armed = false;
    s->bb_ble_evt_fired = false;
    s->bb_ble_evt_events = 0;
    s->bb_ble_evt_init_elt = 0;
    s->bb_ble_con_pending = false;
    s->bb_ble_evt_parked = false;
    s->bb_ble_evt_started = false;
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
    s->bb_ble_evt_poll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                            esp32_bt_ble_evt_poll, s);
    s->bb_ble_evt_start_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                             esp32_bt_ble_evt_start, s);
    s->bb_ble_evt_end_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           esp32_bt_ble_evt_end, s);
    s->ke_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                               esp32_bt_ke_fire, s);
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
    DEFINE_PROP_STRING("bb-rx-payload", Esp32BtState, bb_rx_payload),
    DEFINE_PROP_UINT32("bb-rx-len-flags", Esp32BtState,
                       bb_rx_len_flags, 0),
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
    /* Opt-in KE timer comparator (RWBT 0x0b4 / 0x00c bit 10 -> status bit 10). */
    DEFINE_PROP_BOOL("bb-ke-timer", Esp32BtState, bb_ke_timer, false),
    /* Optional task/id filter for the modelled KE timer. */
    DEFINE_PROP_UINT32("bb-ke-env-addr", Esp32BtState, bb_ke_env_addr, 0),
    DEFINE_PROP_UINT32("bb-ke-task", Esp32BtState, bb_ke_task, 0xffffffffu),
    DEFINE_PROP_UINT32("bb-ke-timer-id", Esp32BtState, bb_ke_timer_id,
                       0xffffffffu),
    DEFINE_PROP_BOOL("bb-ea-rwble", Esp32BtState, bb_ea_rwble, false),
    DEFINE_PROP_UINT32("bb-ea-ble-status-bit", Esp32BtState,
                       bb_ea_ble_status_bit, 7),

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

    /*
     * Opt-in BLE connection-event model.  Disabled by default.  It watches the
     * LLD link reached through llc_env[handle] + link-off and its TX list, then
     * derives the link id and per-activity LL-PDU descriptor from the queued
     * element and performs the baseband descriptor read (spec/04 §3.10).
     */
    DEFINE_PROP_BOOL("bb-ble-evt-inject", Esp32BtState,
                     bb_ble_evt_inject, false),
    DEFINE_PROP_UINT32("bb-ble-evt-llc-env-addr", Esp32BtState,
                       bb_ble_evt_llc_env_addr, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-handle", Esp32BtState,
                       bb_ble_evt_handle, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-link-off", Esp32BtState,
                       bb_ble_evt_link_off, 16),
    DEFINE_PROP_UINT32("bb-ble-evt-txlist-off", Esp32BtState,
                       bb_ble_evt_txlist_off, 48),
    DEFINE_PROP_UINT32("bb-ble-evt-txlist-tail-off", Esp32BtState,
                       bb_ble_evt_txlist_tail_off, 52),
    DEFINE_PROP_UINT32("bb-ble-evt-inflight-off", Esp32BtState,
                       bb_ble_evt_inflight_off, 88),
    DEFINE_PROP_UINT32("bb-ble-evt-inflight-tail-off", Esp32BtState,
                       bb_ble_evt_inflight_tail_off, 92),
    DEFINE_PROP_BOOL("bb-ble-evt-inflight-move", Esp32BtState,
                     bb_ble_evt_inflight_move, true),
    DEFINE_PROP_UINT32("bb-ble-evt-lid-off", Esp32BtState,
                       bb_ble_evt_lid_off, 104),
    DEFINE_PROP_UINT32("bb-ble-evt-tx-idx-off", Esp32BtState,
                       bb_ble_evt_tx_idx_off, 4),
    DEFINE_PROP_UINT32("bb-ble-evt-tx-len-off", Esp32BtState,
                       bb_ble_evt_tx_len_off, 8),
    DEFINE_PROP_UINT32("bb-ble-evt-tx-llid-off", Esp32BtState,
                       bb_ble_evt_tx_llid_off, 10),
    DEFINE_PROP_UINT32("bb-ble-evt-tx-buf-off", Esp32BtState,
                       bb_ble_evt_tx_buf_off, 6),
    DEFINE_PROP_UINT32("bb-ble-evt-desc-base", Esp32BtState,
                       bb_ble_evt_desc_base, 0x05c0),
    DEFINE_PROP_UINT32("bb-ble-evt-txbuf-off", Esp32BtState,
                       bb_ble_evt_txbuf_off, 0x0b96),
    DEFINE_PROP_UINT32("bb-ble-evt-pend-off", Esp32BtState,
                       bb_ble_evt_pend_off, 0x8c),
    DEFINE_PROP_UINT32("bb-ble-evt-ack-bit", Esp32BtState,
                       bb_ble_evt_ack_bit, 15),
    DEFINE_PROP_UINT32("bb-ble-evt-attach-bit", Esp32BtState,
                       bb_ble_evt_attach_bit, 15),
    DEFINE_PROP_BOOL("bb-ble-evt-tx-ack", Esp32BtState,
                     bb_ble_evt_tx_ack, true),
    DEFINE_PROP_UINT32("bb-ble-evt-list-addr", Esp32BtState,
                       bb_ble_evt_list_addr, 0),
    DEFINE_PROP_BOOL("bb-ble-evt-list-set", Esp32BtState,
                     bb_ble_evt_list_set, false),
    DEFINE_PROP_UINT32("bb-ble-evt-ea-env-addr", Esp32BtState,
                       bb_ble_evt_ea_env_addr, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-ea-curr-off", Esp32BtState,
                       bb_ble_evt_ea_curr_off, 0x14),
    DEFINE_PROP_UINT32("bb-ble-evt-state-off", Esp32BtState,
                       bb_ble_evt_state_off, 0x97),
    DEFINE_PROP_UINT32("bb-ble-evt-state-value", Esp32BtState,
                       bb_ble_evt_state_value, 1),
    DEFINE_PROP_BOOL("bb-ble-evt-start-push", Esp32BtState,
                     bb_ble_evt_start_push, true),
    DEFINE_PROP_BOOL("bb-ble-evt-ctrl-start", Esp32BtState,
                     bb_ble_evt_ctrl_start, false),
    DEFINE_PROP_UINT32("bb-ble-evt-llm-elt-addr", Esp32BtState,
                       bb_ble_evt_llm_elt_addr, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-rxwinsz", Esp32BtState,
                       bb_ble_evt_rxwinsz, 1),
    DEFINE_PROP_BOOL("bb-ble-evt-ctrl-timing", Esp32BtState,
                     bb_ble_evt_ctrl_timing, false),
    DEFINE_PROP_BOOL("bb-ble-evt-end-cond", Esp32BtState,
                     bb_ble_evt_end_cond, false),
    DEFINE_PROP_UINT32("bb-ble-evt-duration-off", Esp32BtState,
                       bb_ble_evt_duration_off, 0x12),
    DEFINE_PROP_UINT32("bb-ble-evt-interval-off", Esp32BtState,
                       bb_ble_evt_interval_off, 0x94),
    DEFINE_PROP_UINT32("bb-ble-evt-window-off", Esp32BtState,
                       bb_ble_evt_window_off, 0x78),
    DEFINE_PROP_BOOL("bb-ble-evt-empty-start", Esp32BtState,
                     bb_ble_evt_empty_start, false),
    DEFINE_PROP_BOOL("bb-ble-evt-end-env", Esp32BtState,
                     bb_ble_evt_end_env, false),
    DEFINE_PROP_UINT32("bb-ble-evt-act-base", Esp32BtState,
                       bb_ble_evt_act_base, 0x3ffb00ba),
    DEFINE_PROP_UINT32("bb-ble-evt-act-stride", Esp32BtState,
                       bb_ble_evt_act_stride, 90),
    DEFINE_PROP_UINT32("bb-ble-evt-act-comp-off", Esp32BtState,
                       bb_ble_evt_act_comp_off, 0x50),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-pdus", Esp32BtState,
                       bb_ble_evt_rx_pdus, 0),
    DEFINE_PROP_BOOL("bb-ble-evt-peer", Esp32BtState,
                     bb_ble_evt_peer, false),
    DEFINE_PROP_UINT32("bb-ble-evt-peer-llid", Esp32BtState,
                       bb_ble_evt_peer_llid, 2),
    DEFINE_PROP_UINT32("bb-ble-evt-peer-cat", Esp32BtState,
                       bb_ble_evt_peer_cat, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-peer-len", Esp32BtState,
                       bb_ble_evt_peer_len, 0),
    DEFINE_PROP_STRING("bb-ble-evt-peer-payload", Esp32BtState,
                       bb_ble_evt_peer_payload),
    DEFINE_PROP_UINT64("bb-ble-evt-peer-delay-ns", Esp32BtState,
                       bb_ble_evt_peer_delay_ns, 400000),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-desc-base", Esp32BtState,
                       bb_ble_evt_rx_desc_base, 0x948),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-desc-stride", Esp32BtState,
                       bb_ble_evt_rx_desc_stride, 0xc),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-desc-count", Esp32BtState,
                       bb_ble_evt_rx_desc_count, 8),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-idx-addr", Esp32BtState,
                       bb_ble_evt_rx_idx_addr, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-buf-field", Esp32BtState,
                       bb_ble_evt_rx_buf_field, 0x08),
    DEFINE_PROP_UINT32("bb-ble-evt-peer-limit", Esp32BtState,
                       bb_ble_evt_peer_limit, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-end-state", Esp32BtState,
                       bb_ble_evt_end_state, 0),
    DEFINE_PROP_UINT32("bb-ble-evt-end-status-bit", Esp32BtState,
                       bb_ble_evt_end_status_bit, 3),
    DEFINE_PROP_BOOL("bb-ble-evt-raise-end", Esp32BtState,
                     bb_ble_evt_raise_end, false),
    DEFINE_PROP_UINT32("bb-ble-evt-rx-status-bit", Esp32BtState,
                       bb_ble_evt_rx_status_bit, 1),
    DEFINE_PROP_BOOL("bb-ble-evt-raise-rx", Esp32BtState,
                     bb_ble_evt_raise_rx, false),
    DEFINE_PROP_UINT64("bb-ble-evt-poll-ns", Esp32BtState,
                       bb_ble_evt_poll_ns, 200000),
    DEFINE_PROP_UINT64("bb-ble-evt-start-delay-ns", Esp32BtState,
                       bb_ble_evt_start_delay_ns, 1000000),
    DEFINE_PROP_UINT64("bb-ble-evt-duration-ns", Esp32BtState,
                       bb_ble_evt_duration_ns, 2000000),
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
