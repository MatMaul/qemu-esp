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

    /* Opt-in device-only trace; see ESP32_BT_LOG() in esp32_bt.c. */
    bool bt_trace;

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

    /*
     * Opt-in RWBLE status-bit probe (docs/11 Q4e).  Disabled by default: the
     * default property value selects no bit, so the model behaves exactly as
     * before.  When enabled it raises ONE bit in RWBLE_IRQ_STATUS (0x210)
     * either after a chosen RWBLE register write (default 0x2a0, the
     * advertising-config write in r_lld_adv_start) or after a virtual delay
     * from the first RWBT/RWBLE access (approximately boot).  The guest's
     * RWBLE handler then dispatches it; the point is to observe which ROM
     * handler runs, not to emulate a real event.
     */
    uint32_t rwble_probe_bit;         /* bit index; 0xffffffff disables */
    uint32_t rwble_probe_trigger_off; /* RWBLE offset whose write arms it */
    uint64_t rwble_probe_delay_ns;    /* delay from the trigger write */
    uint64_t rwble_probe_start_ns;    /* >0: arm from reset instead */
    bool rwble_probe_armed;
    bool rwble_probe_fired;
    QEMUTimer *rwble_probe_timer;

    /*
     * Opt-in baseband RX descriptor model (iteration 4).  Disabled by default.
     *
     * When enabled, a guest write that raises the selected bit (default bit
     * 10 of RWBT 0x00c, the inquiry-activity bit set by r_ld_fm_prog_push)
     * arms a one-shot timer.  On expiry the model fills the
     * descriptor currently named by RWBT 0x02c (bt_et_currentrxdescptr),
     * advances 0x02c to the next ring entry and raises the selected RWBT
     * status bit.  This models the owner/complete half of the RX ring that
     * the CPU-only EM tracer cannot see.  The payload contents are synthetic
     * and no on-air behaviour is implied.
     */
    bool bb_rx_inject;
    uint32_t bb_rx_trigger_off;
    uint32_t bb_rx_trigger_bit;
    uint64_t bb_rx_delay_ns;
    uint32_t bb_rx_activity;
    uint32_t bb_rx_packet_type;
    uint32_t bb_rx_payload_len;
    uint32_t bb_rx_status_low;
    uint32_t bb_rx_status_bit;
    bool bb_rx_armed;
    bool bb_rx_fired;
    QEMUTimer *bb_rx_timer;

    /*
     * Optional synthetic EA fine-timer ticks (RWBT status bit 9).  The real
     * baseband raises bit 9 when the event/fine timer expires; that is what
     * lets the controller's scheduler run the inquiry event-start callback
     * and push the frame-manager program.  Disabled by default and bounded to
     * a small number of ticks so it remains an opt-in probe.
     */
    bool bb_ea_inject;
    uint64_t bb_ea_interval_ns;
    uint32_t bb_ea_ticks;
    QEMUTimer *bb_ea_timer;

    /*
     * Opt-in hardware fine-timer model (iteration 5).  Disabled by default.
     *
     * The controller's event arbiter (ROM ea_prog_timer / r_ea_finetimer_isr)
     * programs an absolute target in RWBT 0x0b8 and enables the fine-target
     * interrupt mask (0x00c bit 9).  The real block raises RWBT status bit 9
     * when the native clock reaches that target.  This model tracks the two
     * software writes, schedules a QEMU timer in the same 625 us slot unit the
     * ROM uses, and raises status bit 9 on expiry.  The guest acknowledges it
     * with a 0x018 = 0x200 write.  This is model evidence, not silicon.
     */
    bool bb_ea_model;
    uint32_t ea_target;         /* last value written to RWBT 0x0b8 */
    bool ea_target_valid;       /* a target has been programmed */
    bool ea_mask_enabled;       /* 0x00c bit 9, as seen by the ROM */
    bool ea_status_pending;     /* bit 9 raised, not yet acknowledged */
    bool ea_armed;
    uint32_t ea_fires;
    QEMUTimer *bb_fine_timer;

    /*
     * Opt-in state-based RX injection trigger (iteration 5).  When
     * bb-rx-watch-addr is non-zero the model polls that guest address and arms
     * the one-shot frame injection only after it becomes non-zero.  The
     * rx-model generator points this at ld_fm_env+0x14 (0x3ffb8298), the frame
     * manager program queue that r_ld_fm_prog_push fills from the inquiry
     * event-start callback.  This replaces the fixed post-boot delay.
     */
    uint32_t bb_rx_watch_addr;
    uint32_t bb_rx_watch_mask;
    uint32_t bb_rx_watch_offset;
    uint32_t bb_rx_watch_value;
    uint64_t bb_rx_watch_poll_ns;
    bool bb_rx_watch_after_ea;
    bool bb_rx_watch_armed;
    bool bb_rx_watch_gated;
    bool bb_rx_watch_done;
    uint32_t bb_rx_watch_fires;
    QEMUTimer *bb_rx_watch_timer;
} Esp32BtState;
