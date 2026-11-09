#pragma once

#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qemu/timer.h"
#include "hw/xtensa/esp32_reg.h"

/*
 * ESP32 Bluetooth (BR/EDR + BLE) register model.
 *
 * This is intentionally a *tracing/permissive* model, not a functional
 * controller.  The ESP32 Bluetooth hardware is a RivieraWaves (CEVA)
 * dual-mode baseband.  The control/status registers live in two blocks:
 *
 *   0x3ff71000-0x3ff71fff : RWBT (0x000..0x1ff) and RWBLE (0x200..0x3ff)
 *   0x3ff51000-0x3ff511ff : Bluetooth baseband / RF control registers
 *
 * RWBLE is therefore a sub-window of the RWBT block, not a separate address
 * range.  Both are driven by the same ROM.
 *
 * The controller blob also uses the "exchange memory" (EM) region at
 * 0x3ffb0000-0x3ffb7cd8.  EM is ordinary SRAM from the CPU's point of view,
 * so it is not intercepted here (yet).
 */

#define TYPE_ESP32_BT "misc.esp32.bt"
#define ESP32_BT(obj) OBJECT_CHECK(Esp32BtState, (obj), TYPE_ESP32_BT)

#define ESP32_BT_RWBT_BASE DR_REG_PHY_BASE   /* 0x3ff71000 */
#define ESP32_BT_RWBT_SIZE 0x1000
#define ESP32_BT_BB_BASE   DR_REG_BT_BASE    /* 0x3ff51000 */
#define ESP32_BT_BB_SIZE   0x1000

/* IRQ output names: RWBT -> ETS_RWBT_INTR_SOURCE (6),
 * RWBLE -> ETS_RWBLE_INTR_SOURCE (7). */
#define ESP32_BT_RWBT_IRQ  "rwbt-irq"
#define ESP32_BT_RWBLE_IRQ "rwble-irq"

typedef struct Esp32BtState {
    SysBusDevice parent_obj;

    MemoryRegion iomem_rwbt;
    MemoryRegion iomem_bb;

    uint32_t rwbt[ESP32_BT_RWBT_SIZE / 4];
    uint32_t bb[ESP32_BT_BB_SIZE / 4];

    /* Pending interrupt status for the RWBT and RWBLE blocks. */
    uint32_t rwbt_irq_status;
    uint32_t rwble_irq_status;

    /* Interrupt enable/ack latches (0x064 and 0x22c). */
    uint32_t rwbt_irq_enable;
    uint32_t rwble_irq_enable;

    qemu_irq irq_rwbt;
    qemu_irq irq_rwble;

    /*
     * Sleep/wakeup state machine for 0x030.
     *
     * The RWBT block raises two distinct interrupt status events during a
     * sleep exit:
     *   - status bit 2 -> r_rwip_wakeup()      (RWIP "wakeup": clock/RF on)
     *   - status bit 0 -> r_rwip_wakeup_end()  (RWIP "wakeup end")
     * r_rwip_wakeup() sets the RWIP prevent-sleep bit 0 that
     * r_rwip_wakeup_end() requires, so the order matters: bit 2 must be
     * delivered before bit 0.  The real block also reports the sleep state
     * back in 0x030 bit 15, which btdm_wakeup_request() polls before it asks
     * the baseband to wake up (0x030 bit 4).
     *
     * This model synthesizes those events from the sleep request (bit 31) and
     * a programmable periodic sleep-timer expiry.  It is not silicon
     * behaviour; see docs/09 and notes/q4g.md.
     */
    QEMUTimer *sleep_ack_timer;     /* sets 0x030 bit 15 (asleep) */
    QEMUTimer *wakeup_timer;        /* sleep-timer expiry / periodic wake */
    QEMUTimer *wakeup_start_timer;  /* raises RWBT status bit 2 */
    QEMUTimer *wakeup_end_timer;    /* raises RWBT status bit 0 */
    uint64_t wakeup_interval_ns;
    uint64_t sleep_ack_ns;
    uint64_t wakeup_start_ns;
    uint64_t wakeup_end_ns;
    bool wake_in_progress;
    bool wakeup_ack_seen;
    bool wakeup_end_armed;
} Esp32BtState;
