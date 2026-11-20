# A314shd: build with the bebbo m68k-amigaos-gcc toolchain.
#   make            -> ../../tfmcp/amiga/A314shd (the copy the Pi installs)
#   make PREFIX=/opt/amiga
PREFIX ?= $(HOME)/amiga-gcc16
CC = $(PREFIX)/bin/m68k-amigaos-gcc

CFLAGS = -noixemul -O2 -m68000 -fomit-frame-pointer -Wall -Wno-pointer-sign -Wno-parentheses
LDFLAGS = -noixemul -s

OUT = ../../tfmcp/amiga/A314shd

all: $(OUT)

$(OUT): a314sh/a314shd.c a314device/a314.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ a314sh/a314shd.c -lamiga
