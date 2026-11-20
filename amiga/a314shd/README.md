# A314shd

The Amiga side of a314's `a314sh` service. It runs AmigaDOS commands sent from
the Pi; tfpi-mcp uses it to start the agent `tfdbgd` and, while the agent is
not connected, for `amiga_run`.

`a314sh/a314shd.c` and `a314device/a314.h` are unmodified copies from
[erique/a314](https://github.com/erique/a314) (commit 6d8d100, CC0 1.0).
TF Pi installs only the Pi side, so tfpi-mcp ships the Amiga binary.

Build with `make -C amiga/a314shd` (bebbo toolchain, `PREFIX=~/amiga-gcc16`).
It writes `tfmcp/amiga/A314shd`; commit it with the sources.
