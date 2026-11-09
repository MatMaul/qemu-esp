#!/usr/bin/env python3
"""Summarize an em-trace log.

The log is the file produced by libem_trace.so via out=PATH.  It contains one
line per EM access followed by an optional histogram section and a summary:

    <seq> pc=0x.. addr=0x.. off=0x.. sz=N R|W val=0x..|?
    # histogram: off size reads writes first last
    0x0948 2 0 2 0x954 0x954
    # em-trace summary: seen=.. logged=.. reads=.. writes=.. lo=.. hi=.. value=..

Usage:
    ./analyze.py TRACE [--lo OFF] [--hi OFF] [--nonzero]

--lo/--hi restrict the histogram listing to EM offsets in [lo, hi).
--nonzero shows only entries that were written at least once with a non-zero
          first or last value.
"""
import argparse
import re
import sys

REGIONS = [
    ("BTDM0", 0x0000, 0x09A8),
    ("BLE",   0x09A8, 0x1DDC),
    ("BTDM1", 0x1DDC, 0x2730),
    ("BR/EDR", 0x2730, 0x6388),
]

HIST_RE = re.compile(r"^0x([0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)")


def parse(path):
    hist = []
    summary = None
    order = []
    in_hist = False
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("# em-trace summary:"):
                summary = line.rstrip("\n")
                continue
            if line.startswith("# histogram:"):
                in_hist = True
                continue
            if line.startswith("#"):
                continue
            if in_hist:
                m = HIST_RE.match(line)
                if m:
                    hist.append({
                        "off": int(m.group(1), 16),
                        "size": int(m.group(2)),
                        "r": int(m.group(3)),
                        "w": int(m.group(4)),
                        "first": m.group(5),
                        "last": m.group(6),
                    })
            elif line and line[0].isdigit():
                order.append(line.rstrip("\n"))
    return summary, order, hist


def region_counts(order):
    counts = {name: 0 for name, _, _ in REGIONS}
    other = 0
    for line in order:
        m = re.search(r" off=0x([0-9a-fA-F]+)", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        for name, lo, hi in REGIONS:
            if lo <= off < hi:
                counts[name] += 1
                break
        else:
            other += 1
    return counts, other


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--lo", default=None)
    ap.add_argument("--hi", default=None)
    ap.add_argument("--nonzero", action="store_true")
    args = ap.parse_args()

    summary, order, hist = parse(args.trace)
    if summary:
        print(summary)
    print("access lines: %d, histogram entries: %d" % (len(order), len(hist)))

    counts, other = region_counts(order)
    for name, lo, hi in REGIONS:
        print("  %-6s 0x%04x-0x%04x: %d" % (name, lo, hi, counts[name]))
    if other:
        print("  other                    : %d" % other)

    lo = int(args.lo, 0) if args.lo else 0
    hi = int(args.hi, 0) if args.hi else 0x100000000
    print("\noff    size  reads  writes  first       last")
    for e in hist:
        if not (lo <= e["off"] < hi):
            continue
        if args.nonzero and e["w"] > 0 and \
           e["first"] in ("0x0", "-") and e["last"] in ("0x0", "-"):
            continue
        print("0x%04x %4d %6d %7d  %-10s %-10s" %
              (e["off"], e["size"], e["r"], e["w"], e["first"], e["last"]))


if __name__ == "__main__":
    main()
