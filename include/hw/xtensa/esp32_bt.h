#pragma once

#include <stdio.h>

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

    /*
     * Opt-in NDJSON sidecar (`bt-events=PATH`).  It is an additional canonical
     * view of the same events; the historical text log is unchanged.
     */
    char *bt_events;
    FILE *bt_events_fp;
    uint64_t bt_events_seq;

    /*
     * Opt-in VHCI capture.  `vhci-env` is the guest address of
     * the `vhci_env_p` pointer.  The model samples the host-to-controller and
     * controller-to-host buffers on BT register activity and logs one line per
     * distinct packet, so a session can capture HCI bytes without a gdb
     * breakpoint on every VHCI access.
     */
    uint32_t vhci_env_addr;
    uint32_t vhci_rx_key;
    uint32_t vhci_tx_key;

    /*
     * Opt-in deterministic model clock.
     *
     * `bt-clock=model` advances a model timebase from guest-visible BT
     * activity instead of QEMU_CLOCK_VIRTUAL, which tracks host wall time.
     * Each RWBT/RWBLE/BB register access adds `bt-clock-step-ns` and processes
     * every modelled event whose deadline is now due.  The model timers below
     * then use that timebase, so tracing or gdb no longer changes the event
     * ordering.  This is model-defined timing, not silicon validation; the
     * default remains `host` for compatibility with the stock baselines.
     */
    char *bt_clock;
    char *bt_clock_start;
    char *bt_clock_anchor;
    uint64_t bt_clock_step_ns;
    uint64_t bt_clock_idle_step_ns;
    bool model_started;
    bool model_anchored;
    /*
     * HCI_Inquiry hold: freeze the model clock from the anchor until the
     * controller programs the inquiry fine-timer target (0x0b8 write) or the
     * host-virtual deadline expires.  The host-timed scheduler otherwise runs
     * a variable number of instructions between the VHCI staging and that
     * programming, which can let the pre-armed periodic slot fire first and
     * move the inquiry event out of its window.
     */
    bool model_anchor_hold;
    uint64_t model_anchor_hold_deadline_ns;
    uint64_t model_ns;
    uint64_t model_base_ns;
    uint64_t model_base_count;
    uint64_t model_deadline[16];
    bool model_active[16];
    QEMUTimer *model_idle_timer;
    bool model_idle_armed;
    uint64_t model_accesses;

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
     * Opt-in KE (kernel event) timer comparator model.
     *
     * The controller arms its software timers through ke_timer_hw_set(), which
     * writes the absolute 10 ms target to RWBT 0x0b4 and enables the interrupt
     * mask at RWBT 0x00c bit 10.  The real block raises RWBT status bit 10 when
     * that target is reached; r_rwbt_isr() then calls r_ke_event_set() and the
     * controller runs its own timer list.  Without it the KE timers never
     * expire (the supervision-timeout path never runs).  Disabled by default.
     */
    bool bb_ke_timer;
    uint32_t bb_ke_env_addr;
    uint32_t bb_ke_task;
    uint32_t bb_ke_timer_id;
    bool ke_target_valid;
    bool ke_pending;
    uint32_t ke_target;
    uint32_t ke_node;
    QEMUTimer *ke_timer;

    /*
     * Opt-in RWBLE status-bit probe (parent project Q4e).  Disabled by default: the
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
     * Opt-in baseband RX descriptor model.  Disabled by default.
     *
     * When enabled, a guest write that raises the selected bit (the inquiry
     * generator uses bit 12 of RWBT 0x024, written by ld_inq_evt_start_cbk)
     * arms a one-shot timer.  On expiry the model fills the descriptor
     * currently named by RWBT 0x02c (bt_et_currentrxdescptr), advances 0x02c
     * to the next ring entry and raises the selected RWBT status bit.  This
     * models the owner/complete half of the RX ring that the CPU-only EM
     * tracer cannot see.  bb_rx_payload_len is 18 by default (FHS = 144 bits)
     * and bb_rx_rssi is written to descriptor +0x08, which ld_inq_frm_cbk
     * emits as the HCI RSSI byte.  The payload contents are synthetic and no
     * on-air behaviour is implied (see docs/09 §3.8).
     */
    bool bb_rx_inject;
    uint32_t bb_rx_trigger_off;
    uint32_t bb_rx_trigger_bit;
    uint64_t bb_rx_delay_ns;
    uint32_t bb_rx_activity;
    uint32_t bb_rx_packet_type;
    uint32_t bb_rx_payload_len;
    /*
     * Optional explicit payload and descriptor length flags.  When
     * bb_rx_payload is a non-empty hex string it replaces the built-in FHS
     * pattern and its byte count overrides bb_rx_payload_len.  bb_rx_len_flags
     * is ORed into the low two bits of descriptor +0x06; the ACL DM1/DV path in
     * ld_acl_rx requires those bits to be 3 (spec/04 §3.3).
     */
    char *bb_rx_payload;
    uint32_t bb_rx_len_flags;
    uint32_t bb_rx_rssi;
    uint32_t bb_rx_status_low;
    uint32_t bb_rx_status_bit;
    bool bb_rx_armed;
    bool bb_rx_fired;
    bool bb_rx_window;
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
     * Optional periodic RWBT status bit 16 tick.  r_rwbt_isr
     * dispatches bit 16 to r_ea_sw_isr, which walks the software EA list; in
     * the inquiry model that is the reliable path that advances the
     * frame-manager program and runs ld_inq_evt_start_cbk.  The cadence is a
     * model ordering aid, not a claim about the real software-interrupt rate.
     */
    bool bb_sw_inject;
    bool bb_sw_armed;
    uint32_t bb_sw_ticks;
    uint64_t bb_sw_interval_ns;
    QEMUTimer *bb_sw_timer;

    /*
     * Opt-in hardware fine-timer model.  Disabled by default.
     *
     * The controller's event arbiter (ROM ea_prog_timer / r_ea_finetimer_isr)
     * programs an absolute target in RWBT 0x0b8 and enables the fine-target
     * interrupt mask (0x00c bit 9).  The real block raises RWBT status bit 9
     * when the native clock reaches that target.  This model tracks the two
     * software writes, schedules a QEMU timer in the same 625 us slot unit the
     * ROM uses, and raises status bit 9 on expiry.  The guest acknowledges it
     * with a 0x018 = 0x200 write.  Because r_ea_finetimer_isr only runs the
     * element whose target equals the clock it reads, the model pins the
     * reported clock to the fired target for a short window
     * (clock_floor/clock_hold_until).  This is model evidence, not silicon.
     */
    bool bb_ea_model;
    uint32_t clock_floor;       /* native-clock ticks already consumed by fires */
    uint64_t clock_hold_until;  /* pin the clock to clock_floor until this ns */
    uint32_t ea_target;         /* last value written to RWBT 0x0b8 */
    bool ea_target_valid;       /* a target has been programmed */
    bool ea_mask_enabled;       /* 0x00c bit 9, as seen by the ROM */
    bool ea_status_pending;     /* bit 9 raised, not yet acknowledged */
    bool ea_armed;
    uint32_t ea_fires;
    bool ea_diag_pending;       /* log the arbiter state on the next clock read */
    QEMUTimer *bb_fine_timer;

    /*
     * Opt-in bank selection for the modelled fine-timer expiry.  The real
     * hardware raises the expiry in the bank that owns the programmed
     * activity: RWBT status bit 9 for BR/EDR and RWBLE status bit 7 for BLE.
     * Both dispatch to r_ea_finetimer_isr, but the guest acknowledges them
     * through different registers (0x018 vs 0x218).
     */
    bool bb_ea_rwble;
    uint32_t bb_ea_ble_status_bit;

    /*
     * Opt-in state-based RX injection trigger.  When
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

    /*
     * Opt-in baseband TX completion model.  Disabled by default.
     *
     * The BR/EDR hardware TX control block is an array of 10-byte records at
     * EM 0x23ba, indexed by 10*(2*link_id + queue) (spec/04 §3.2b).  Software
     * marks a record pending by setting bit 15 of its +0x00 link word; the
     * ROM's ld_acl_tx() sends only records whose bit 15 is set and the
     * baseband clears it when the packet is transmitted (spec/04 §3.2b).
     * This model polls one guest link word, performs that write-back on the
     * configured owner bit and raises the selected RWBT/RWBLE status bit, so
     * the CPU-visible half of the owner/complete handshake is observable.
     * The address, bits, delays and target block are all properties: the
     * model is a harness aid, not a statement about silicon polarity.
     */
    bool bb_tx_inject;
    uint32_t bb_tx_watch_addr;
    uint32_t bb_tx_watch_mask;
    uint32_t bb_tx_watch_value;
    uint32_t bb_tx_owner_bit;
    uint32_t bb_tx_status_bit;
    bool bb_tx_rwble;
    uint64_t bb_tx_poll_ns;
    uint64_t bb_tx_delay_ns;
    bool bb_tx_watch_armed;
    bool bb_tx_armed;
    bool bb_tx_fired;
    uint32_t bb_tx_completions;
    QEMUTimer *bb_tx_watch_timer;
    QEMUTimer *bb_tx_timer;

    /*
     * Opt-in BLE connection-event model.  Disabled by default.
     *
     * The stock LLD queues an LE ACL PDU on the link object reached through
     * `llc_env[handle] + link-off`, but with no baseband it never assigns the
     * link id (`link + lid-off`, `0xffff` before an event), programs the
     * per-activity LL-PDU descriptor, or reads that descriptor on air.  This
     * model polls the link's TX list, and on a non-empty list derives the
     * link id and descriptor from guest state at a modelled event-start tick,
     * link id and descriptor from guest state at a modelled event-start tick,
     * sets the LLD event state, publishes the link as the EA current element
     * and pushes it onto the current-event list, then performs the baseband
     * descriptor read at the event-end tick.  It can also raise the RWBLE
     * event-end status bit so the guest's own r_lld_evt_end_isr runs.  Every
     * offset, the descriptor base and the EM payload offset is a property; the
     * timing is model-defined and is not a silicon or RF claim.
     */
    bool bb_ble_evt_inject;
    uint32_t bb_ble_evt_llc_env_addr;
    uint32_t bb_ble_evt_handle;
    uint32_t bb_ble_evt_link_off;
    uint32_t bb_ble_evt_txlist_off;
    uint32_t bb_ble_evt_txlist_tail_off;
    uint32_t bb_ble_evt_inflight_off;
    uint32_t bb_ble_evt_inflight_tail_off;
    bool bb_ble_evt_inflight_move;
    uint32_t bb_ble_evt_lid_off;
    uint32_t bb_ble_evt_tx_idx_off;
    uint32_t bb_ble_evt_tx_len_off;
    uint32_t bb_ble_evt_tx_llid_off;
    uint32_t bb_ble_evt_tx_buf_off;
    uint32_t bb_ble_evt_desc_base;
    uint32_t bb_ble_evt_txbuf_off;
    uint32_t bb_ble_evt_pend_off;
    uint32_t bb_ble_evt_ack_bit;
    uint32_t bb_ble_evt_attach_bit;
    bool bb_ble_evt_tx_ack;
    uint32_t bb_ble_evt_list_addr;
    bool bb_ble_evt_list_set;
    uint32_t bb_ble_evt_ea_env_addr;
    uint32_t bb_ble_evt_ea_curr_off;
    uint32_t bb_ble_evt_state_off;
    uint32_t bb_ble_evt_state_value;
    bool bb_ble_evt_start_push;
    bool bb_ble_evt_ctrl_start;
    uint32_t bb_ble_evt_llm_elt_addr;
    uint32_t bb_ble_evt_rxwinsz;
    bool bb_ble_evt_ctrl_timing;
    bool bb_ble_evt_end_cond;
    uint32_t bb_ble_evt_duration_off;
    uint32_t bb_ble_evt_interval_off;
    uint32_t bb_ble_evt_window_off;
    uint32_t bb_ble_evt_window_slots;
    uint32_t bb_ble_evt_window_count;
    bool bb_ble_evt_idle;
    bool bb_ble_evt_empty_start;
    bool bb_ble_evt_end_env;
    uint32_t bb_ble_evt_act_base;
    uint32_t bb_ble_evt_act_stride;
    uint32_t bb_ble_evt_act_comp_off;
    uint32_t bb_ble_evt_rx_pdus;
    /*
     * Peer-side PDU model (opt-in bb-ble-evt-peer).  At the event end the
     * model posts what the peer's response to the master's PDU would have
     * carried into the controller's em_buf RX ring, reports it through the
     * per-activity RX count and ends the event at the response time instead
     * of the RX-window close, so the controller's own r_lld_evt_rx /
     * r_lld_pdu_rx_handler path consumes the received PDU.
     */
    bool bb_ble_evt_peer;
    uint32_t bb_ble_evt_peer_llid;
    uint32_t bb_ble_evt_peer_cat;
    uint32_t bb_ble_evt_peer_len;
    char *bb_ble_evt_peer_payload;
    /*
     * Ordered peer payloads (opt-in bb-ble-evt-peer-payloads).  A
     * semicolon-separated list; the n-th posted peer PDU uses the n-th
     * segment, and the last one repeats once the list is exhausted.  It lets
     * a slice answer a multi-PDU procedure (LL_ENC_RSP then
     * LL_START_ENC_RSP) without changing the single-payload property.
     */
    char *bb_ble_evt_peer_payloads;
    uint64_t bb_ble_evt_peer_delay_ns;
    uint32_t bb_ble_evt_rx_desc_base;
    uint32_t bb_ble_evt_rx_desc_stride;
    uint32_t bb_ble_evt_rx_desc_count;
    uint32_t bb_ble_evt_rx_idx_addr;
    uint32_t bb_ble_evt_rx_buf_field;
    bool bb_ble_evt_peer_sent;
    /*
     * Peer PDU budget (opt-in bb-ble-evt-peer-limit).  Zero keeps the old
     * one-response-per-event behaviour; a non-zero value caps the total posted
     * over the session, so a later event can carry the controller's own LLCP
     * reply instead of another peer request.
     */
    uint32_t bb_ble_evt_peer_limit;
    uint32_t bb_ble_evt_peer_posted;
    /*
     * Data-event continuation (opt-in bb-ble-evt-continue).  The default
     * stops watching after the event that carried a PDU, so a procedure that
     * spans two connection events (LL_ENC_REQ in one, LL_START_ENC_REQ in the
     * next) is only observed up to its first transmission.  With this count
     * non-zero the model keeps watching until that many data-carrying events
     * have run through the controller.
     */
    uint32_t bb_ble_evt_continue;
    uint32_t bb_ble_evt_data_events;
    /*
     * Reply only after the controller transmitted a PDU in this event
     * (opt-in bb-ble-evt-peer-after-tx).  The encrypted-link procedure needs
     * it: the peer's LL_ENC_RSP must follow the controller's LL_ENC_REQ, not
     * arrive unsolicited in an empty event.
     */
    bool bb_ble_evt_peer_after_tx;
    /*
     * Opt-in BLE AES block model (bb-ble-aes).  r_llm_encryption_start writes
     * the 128-bit key to RWBLE 0x2c4..0x2d0 and the EM input offset to 0x2d4,
     * then starts the block with bit 0 of 0x2c0.  The model encrypts the 16
     * bytes at em_base + offset, writes the result 16 bytes later and raises
     * the crypto-completion IRQ status bit 4 (r_lld_crypt_isr).
     */
    bool bb_ble_aes;
    uint32_t bb_ble_aes_em_base;
    uint32_t bb_ble_evt_end_state;
    uint32_t bb_ble_evt_init_elt;
    bool bb_ble_con_pending;
    bool bb_ble_evt_parked;
    bool bb_ble_evt_started;
    uint32_t bb_ble_evt_wait;
    uint32_t bb_ble_evt_gate_waits;
    uint32_t bb_ble_evt_end_status_bit;
    bool bb_ble_evt_raise_end;
    uint32_t bb_ble_evt_rx_status_bit;
    bool bb_ble_evt_raise_rx;
    uint64_t bb_ble_evt_poll_ns;
    uint64_t bb_ble_evt_start_delay_ns;
    uint64_t bb_ble_evt_duration_ns;
    bool bb_ble_evt_armed;
    bool bb_ble_evt_fired;
    bool bb_ble_evt_end_armed;
    uint32_t bb_ble_evt_tx;
    uint32_t bb_ble_evt_events;
    QEMUTimer *bb_ble_evt_poll_timer;
    QEMUTimer *bb_ble_evt_start_timer;
    QEMUTimer *bb_ble_evt_end_timer;
} Esp32BtState;
