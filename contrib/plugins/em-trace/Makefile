# -*- Mode: makefile -*-
#
# Out-of-tree build for the em-trace QEMU TCG plugin.
#
# Run from this directory:
#     make
#
# It borrows CC / GLIB_* / SRC_PATH from the already-configured QEMU build
# tree (../../../build/config-host.mak) but writes only into ./build.

THIS_DIR := $(CURDIR)
QEMU_BUILD ?= $(THIS_DIR)/../../../build

include $(QEMU_BUILD)/config-host.mak

PLUGIN_BUILD := $(THIS_DIR)/build
SRC := $(THIS_DIR)/em_trace.c
OBJ := $(PLUGIN_BUILD)/em_trace.o
TARGET := $(PLUGIN_BUILD)/libem_trace.so

CFLAGS = -D_GNU_SOURCE -fPIC -Wall -Wextra -O2
CFLAGS += $(GLIB_CFLAGS)
CFLAGS += -I$(SRC_PATH)/include/qemu
LDLIBS = $(GLIB_LIBS)

all: $(TARGET)

$(PLUGIN_BUILD):
	mkdir -p $@

$(OBJ): $(SRC) | $(PLUGIN_BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJ)
	$(CC) -shared -Wl,-soname,libem_trace.so -o $@ $< $(LDLIBS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
