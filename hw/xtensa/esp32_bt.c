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
 * Synthetic wakeup: the controller programs a sleep timer through 0x034 and
 * sets 0x030 bit 31.  The real hardware raises an IRQ when the timer expires;
 * this model raises the RWBT "wakeup end" status bit (bit 0) after a fixed
 * virtual delay so the controller leaves its idle loop and services HCI.
 */
static void esp32_bt_wakeup_timer(void *opaque)
{
    Esp32BtState *s = ESP32_BT(opaque);

    /* The baseband clears the sleep request when the wakeup completes. */
    s->rwbt[RWBT_SLEEP_CTRL / 4] &= ~RWBT_SLEEP_REQUEST;
    s->rwbt_irq_status |= 0x1;
    qemu_log_mask(LOG_UNIMP,
                  "esp32_bt: synthetic RWBT wakeup, status=%08x\n",
                  s->rwbt_irq_status);
    esp32_bt_update_irqs(s);
}

static uint64_t esp32_bt_rwbt_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32BtState *s = ESP32_BT(opaque);
    uint32_t r;
    uint32_t off = addr & ~3u;

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

        s->rwbt[off / 4] = v;
        if (!(old & RWBT_SLEEP_REQUEST) && (v & RWBT_SLEEP_REQUEST)) {
            timer_mod(s->wakeup_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      s->wakeup_interval_ns);
        } else if ((old & RWBT_SLEEP_REQUEST) &&
                   !(v & RWBT_SLEEP_REQUEST)) {
            timer_del(s->wakeup_timer);
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
    timer_del(s->wakeup_timer);
    esp32_bt_update_irqs(s);

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
    s->wakeup_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                   esp32_bt_wakeup_timer, s);
}

static void esp32_bt_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->reset = esp32_bt_reset;
    device_class_set_props(dc, esp32_bt_properties);
}

static Property esp32_bt_properties[] = {
    DEFINE_PROP_UINT64("wakeup-interval-ns", Esp32BtState,
                       wakeup_interval_ns, 1000000),
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
