# em-trace: QEMU TCG plugin for ESP32 Exchange Memory tracing

`em_trace.c` is an ordinary QEMU TCG plugin. It logs CPU loads/stores that
land in the ESP32 Bluetooth Exchange Memory window and is active **only** when
loaded with `-plugin`, so normal runs are unaffected.

Each record is:

```
<seq> pc=0x.. addr=0x.. off=0x.. sz=N R|W val=0x..|?
```

`addr` is the guest virtual address (the EM window is identity-mapped on this
ESP32 machine), `off = addr - lo`, and `val` is the value after the access.

## Build (out of tree, no QEMU rebuild)

The QEMU build tree is used only for `config-host.mak`; nothing is written
under `build/`.

```sh
cd references/qemu-esp/contrib/plugins/em-trace
make
# -> build/libem_trace.so
```

`make clean` removes the object and shared library.

## Run

Copy the firmware image to `/tmp` inside the same command (another capture pass may replace
the harness image) and always bound the run:

```sh
cd references/qemu-esp
cp /path/to/flash_image.bin /tmp/emflash.bin
timeout 20 build/qemu-system-xtensa -nographic -machine esp32 \
  -drive file=/tmp/emflash.bin,if=mtd,format=raw -no-reboot \
  -plugin $PWD/contrib/plugins/em-trace/build/libem_trace.so,\
out=/tmp/em_trace.log,hist=on,value=on
```

Note: the argument list must be one comma-separated string with no spaces.

## Options

| Option | Meaning |
|---|---|
| `lo=ADDR` | EM base (default `0x3ffb0000`) |
| `hi=ADDR` | EM end, exclusive (default `0x3ffb7cd8`) |
| `range=LO-HI` | log only this EM-offset range (repeatable) |
| `offset=OFF` | log only accesses at this EM offset (repeatable) |
| `value=on\|off` | best-effort value recovery (default on) |
| `hist=on\|off` | per-offset histogram at exit (default off) |
| `out=PATH` | trace file (default stderr) |
| `vaddr=on\|off` | filter on vaddr (default on) or QEMU "phys" |
| `verbose` | setup diagnostics on stderr |
| `sample=N`, `near=on` | debug-only first-N access sampler |

## Value recovery and the vaddr/phys caveat

QEMU 8.0's public plugin API does **not** expose the value of a memory
transaction and has no guest-memory read helper. The plugin therefore resolves
QEMU's internal `address_space_read_full` and `address_space_memory` from the
running binary's own `.symtab` (`/proc/self/exe`) and calls them after the
access has executed. This is a non-public ABI dependency; `value=off` disables
it. If resolution fails, `val=?`.

`qemu_plugin_hwaddr_phys_addr()` returns a RAM-address-space address in this
tree, not the bus physical address: for the ESP32 DRAM block it is biased by
the RAMBlock's `offset` (e.g. `0x3ffb63ac` is reported as `0x418b63ac`). The
plugin therefore filters and reads through the **virtual** address by default;
the EM window is identity-mapped, so `vaddr` is the correct EM offset.

## Analysis

`analyze.py TRACE [--lo OFF] [--hi OFF] [--nonzero]` prints the summary, per
region access counts, and the histogram (optionally filtered).
