# vhci-trace: in-process VHCI H2C/C2H capture for the ESP32 BT model

`vhci_trace.c` is an ordinary QEMU TCG plugin. It captures the controller's
host-to-controller (H2C) and controller-to-host (C2H) HCI packets without a gdb
breakpoint, and optionally dumps the first `r_ld_fm_frame_isr` state. It is
active **only** when loaded with `-plugin`, so normal runs are unaffected.

Three hooks:

- `stage=ADDR,stage-end=ADDR` — sample guest stores inside the host VHCI
  staging function. The controller's staging window (`env+0x28`,
  `env+0x4d8`, `env+0x4dc`) is short; a TB sampler misses it, a store callback
  does not.
- `send=ADDR` — hook the controller-to-host entry (`vhci_send`) at instruction
  granularity and read `$a2` (buffer) and `$a3` (length).
- `isr=ADDR` — hook the first `r_ld_fm_frame_isr` execution and emit the RXFM
  status/current/queue and descriptor words.

Each packet is written in three shapes (the historical claim families use all
three):

```
H2C len=4 01 03 0c 00
H2C len=4 hdr=01 03 0c
H2C dump 0x01 0x03 0x0c 0x00
```

## Build (out of tree, no QEMU rebuild)

The QEMU build tree is used only for `config-host.mak`; nothing is written
under `build/`.

```sh
cd references/qemu-esp/contrib/plugins/vhci-trace
make
# -> build/libvhci_trace.so
```

`make clean` removes the object and shared library.

## Run

The argument list must be one comma-separated string with no spaces. The
harness normally launches this through `harness/generate.py run
session-rx-model`; a direct run looks like:

```sh
cd references/qemu-esp
timeout 120 build/qemu-system-xtensa -nographic -machine esp32 \
  -drive file=flash_image.bin,if=mtd,format=raw -no-reboot \
  -global driver=misc.esp32.bt,property=bt-clock,value=model \
  -global driver=misc.esp32.bt,property=bt-clock-step-ns,value=1000 \
  -plugin $PWD/contrib/plugins/vhci-trace/build/libvhci_trace.so,\
env=0x3ffc8630,out=/tmp/vhci.log,stage=0x4014bd6c,stage-end=0x4014be88,\
send=0x4014bbc4,isr=0x4008ac5c,isr-status=0x3ff71010,\
isr-current=0x3ff7102c,isr-queue=0x3ffb8298,isr-desc=0x3ffb2382
```

`env` is the guest address of `vhci_env_p`; resolve it from the app ELF rather
than hard-coding it. The other addresses are the resolved symbols and the
documented RWBT/EM addresses.

## Options

| Option | Meaning |
|---|---|
| `env=ADDR` | guest address of the `vhci_env_p` pointer (required) |
| `out=PATH` | output file (default stderr) |
| `stage=ADDR`, `stage-end=ADDR` | host VHCI staging function range (H2C store hook) |
| `send=ADDR` | `vhci_send` entry (C2H register hook) |
| `arg-buf-index=N`, `arg-len-index=N` | Xtensa register indices (default 2 and 3) |
| `env-ptr-offset=N` | `CPUState.env_ptr` offset (default 544) |
| `regs-offset=N` | `CPUArchState.regs` offset (default 8) |
| `isr=ADDR` | `r_ld_fm_frame_isr` entry (RXFM dump) |
| `isr-status=ADDR` | RWBT `0x010` status word |
| `isr-current=ADDR` | RWBT `0x02c` current RX descriptor |
| `isr-queue=ADDR` | `ld_fm_env+0x14` program queue |
| `isr-desc=ADDR` | EM RX descriptor 0 base |
| `verbose` | setup/exit diagnostics on stderr |

## Non-public register access

QEMU 8.0's public plugin API has no register read and no guest-memory read.
The plugin therefore resolves `address_space_read_full`, `address_space_memory`
and `qemu_get_cpu` from the running binary's `.symtab` (`/proc/self/exe`). For
C2H it reads the Xtensa register window from the CPU state:

```c
CPUState *cpu = qemu_get_cpu(cpu_index);
env = *(void **)((char *)cpu + env_ptr_offset);
aN  = *(uint32_t *)((char *)env + regs_offset + 4 * N);
```

The offsets 544 and 8 come from the QEMU build's DWARF for `CPUState.env_ptr`
and `CPUArchState.regs`; override them when the QEMU build changes. This is a
harness aid and a non-public ABI dependency, not a hardware claim.

## Why not gdb

A gdb breakpoint on every VHCI access slows the guest by an order of magnitude.
With the deterministic model clock (`bt-clock=model`) the model timebase
advances from executed instructions while the guest's own timers still use host
virtual time; a breakpoint desynchronises the two and can move the inquiry
result outside the sampled window. The plugin observes the same events without
stopping the CPU.

## License

GNU GPL, version 2 or later.
