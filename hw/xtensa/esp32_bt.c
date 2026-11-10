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
#define RWBT_WAKEUP_BOUND  0x01c
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

static uint32_t esp32_bt_bt_clk(void)
{
    /* BR/EDR and BLE native clock: one tick is 312.5 us. */
    return (uint32_t)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 312500);
}

static const char *esp32_bt_block(uint32_t off)
{
    return off >= RWBLE_BASE ? "RWBLE" : "RWBT ";
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
 * Opt-in RWBLE status-bit probe (docs/11 Q4e).
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
    qemu_log_mask(LOG_UNIMP,
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
    timer_mod(s->rwble_probe_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns);
    qemu_log_mask(LOG_UNIMP,
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
    timer_del(s->wakeup_timer);
    timer_del(s->wakeup_end_timer);
    timer_mod(s->wakeup_start_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->wakeup_start_ns);
    qemu_log_mask(LOG_UNIMP, "esp32_bt: wakeup requested\n");
}

static void esp32_bt_sleep_ack(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    *esp32_bt_sleep_ctrl(s) |= RWBT_SLEEP_STATE;
    qemu_log_mask(LOG_UNIMP, "esp32_bt: sleep ack, 0x030 -> %08x\n",
                  *esp32_bt_sleep_ctrl(s));

    if (s->wakeup_interval_ns) {
        timer_mod(s->wakeup_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  s->wakeup_interval_ns);
    }
}

static void esp32_bt_wakeup_timer(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    if (!(*esp32_bt_sleep_ctrl(s) & RWBT_SLEEP_STATE)) {
        /* Not asleep: try again later rather than spinning. */
        if (s->wakeup_interval_ns) {
            timer_mod(s->wakeup_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      s->wakeup_interval_ns);
        }
        return;
    }

    qemu_log_mask(LOG_UNIMP, "esp32_bt: sleep timer expiry\n");
    esp32_bt_begin_wakeup(s);
}

static void esp32_bt_wakeup_start(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    s->wakeup_end_armed = false;
    s->rwbt_irq_status |= RWBT_IRQ_WAKEUP;
    qemu_log_mask(LOG_UNIMP,
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
    qemu_log_mask(LOG_UNIMP,
                  "esp32_bt: RWBT wakeup end, status=%08x 0x030=%08x\n",
                  s->rwbt_irq_status, *ctrl);
    esp32_bt_update_irqs(s);
}

static uint64_t esp32_bt_rwbt_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t r;
    uint32_t off = addr & ~3u;

    esp32_bt_rwble_probe_arm_start(s);

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
    case RWBLE_IRQ_STATUS:
        r = s->rwble_irq_status;
        break;
    case RWBT_WAKEUP_BOUND:
    case RWBLE_WAKEUP_BOUND:
        r = s->rwbt[off / 4] & ~BT_WAKEUP_SELF_CLEAR;
        break;
    case RWBT_CLK_LO:
    case RWBLE_CLK_LO:
        r = esp32_bt_bt_clk();
        break;
    case RWBLE_CLK_HI:
        r = 0;
        break;
    default:
        r = s->rwbt[off / 4];
        break;
    }

    qemu_log_mask(LOG_UNIMP, "esp32_bt: %s read  %04x -> %08x\n",
                  esp32_bt_block(off), (uint32_t)off, r);
    log_mmio_access(ESP32_BT_RWBT_BASE + off, r, false);
    return r;
}

static void esp32_bt_rwbt_write(void *opaque, hwaddr addr,
                                uint64_t value, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t v = (uint32_t)value;

    esp32_bt_rwble_probe_arm_start(s);

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
                timer_mod(s->wakeup_end_timer,
                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          20000000);
            }
        }
        if (v == 0xffffffffu && s->wake_in_progress &&
            s->wakeup_ack_seen) {
            s->wakeup_end_armed = true;
            timer_mod(s->wakeup_end_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      s->wakeup_end_ns);
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
            timer_del(s->wakeup_timer);
            timer_mod(s->sleep_ack_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      s->sleep_ack_ns);
            qemu_log_mask(LOG_UNIMP, "esp32_bt: sleep request\n");
        }

        s->rwbt[off / 4] = v;

        if (!(old & RWBT_WAKEUP_REQ) && (v & RWBT_WAKEUP_REQ)) {
            esp32_bt_begin_wakeup(s);
        }
        break;
    }
    case RWBT_WAKEUP_BOUND:
    case RWBLE_WAKEUP_BOUND:
        s->rwbt[off / 4] = v & ~BT_WAKEUP_SELF_CLEAR;
        break;
    default:
        s->rwbt[off / 4] = v;
        break;
    }

    qemu_log_mask(LOG_UNIMP, "esp32_bt: %s write %04x <- %08x\n",
                  esp32_bt_block(off), (uint32_t)off, v);
    log_mmio_access(ESP32_BT_RWBT_BASE + off, v, true);

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
}

static uint64_t esp32_bt_bb_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t r = s->bb[off / 4];

    qemu_log_mask(LOG_UNIMP, "esp32_bt: BB    read  %04x -> %08x\n",
                  (uint32_t)off, r);
    log_mmio_access(ESP32_BT_BB_BASE + off, r, false);
    return r;
}

static void esp32_bt_bb_write(void *opaque, hwaddr addr,
                              uint64_t value, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t off = addr & ~3u;
    uint32_t v = (uint32_t)value;

    s->bb[off / 4] = v;
    qemu_log_mask(LOG_UNIMP, "esp32_bt: BB    write %04x <- %08x\n",
                  (uint32_t)off, v);
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
    timer_del(s->sleep_ack_timer);
    timer_del(s->wakeup_timer);
    timer_del(s->wakeup_start_timer);
    timer_del(s->wakeup_end_timer);
    timer_del(s->rwble_probe_timer);
    s->rwble_probe_armed = false;
    s->rwble_probe_fired = false;
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
}

static void esp32_bt_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->reset = esp32_bt_reset;
    device_class_set_props(dc, esp32_bt_properties);
}

static Property esp32_bt_properties[] = {
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
     * Opt-in RWBLE status-bit probe (docs/11 Q4e).  Disabled by default
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
