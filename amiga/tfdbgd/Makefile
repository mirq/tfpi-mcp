# tfdbgd: build with the bebbo m68k-amigaos-gcc toolchain.
#   make            -> ../../tfmcp/amiga/tfdbgd (the copy the Pi installs)
#   make PREFIX=/opt/amiga
PREFIX ?= $(HOME)/amiga-gcc16
CC = $(PREFIX)/bin/m68k-amigaos-gcc
VASM = $(PREFIX)/bin/vasmm68k_mot

# 68000 code for the C parts (the agent checks for a 68020+ itself);
# no small data: the trap handler and workers run outside the agent's context.
CFLAGS = -noixemul -O2 -m68000 -fomit-frame-pointer -Wall -Wextra -Wno-unused-parameter \
         -Wno-pointer-sign -std=gnu11
LDFLAGS = -noixemul -s

OBJS = main.o jobs.o inspect.o screen.o input.o trap.o
OUT = ../../tfmcp/amiga/tfdbgd

all: $(OUT)

$(OUT): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c tfdbgd.h a314.h
	$(CC) $(CFLAGS) -c -o $@ $<

trap.o: trap.s
	$(VASM) -Fhunk -m68060 -no-opt -quiet -o $@ $<

clean:
	rm -f $(OBJS)

.PHONY: all clean
