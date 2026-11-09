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
     * Synthetic baseband wakeup.  The real RWBT block raises an interrupt
     * when the sleep timer programmed in 0x034 expires.  This model does not
     * implement the timer unit, so it fires a configurable periodic wakeup
     * after a sleep request in 0x030 bit 31.  See docs/09 for the caveat.
     */
    QEMUTimer *wakeup_timer;
    uint64_t wakeup_interval_ns;
} Esp32BtState;
