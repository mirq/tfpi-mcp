# AGENTS.md

tfpi-mcp: an MCP server (Python, standard library only) that runs on a TF Pi
(Raspberry Pi on a TerribleFire TF4060 Amiga accelerator, with
[tfpi](https://github.com/terriblefire/tfpi) and erique/a314 branch `tf4060`
installed). Next to it is a small Amiga agent, `tfdbgd`, written in C and 68k
assembly.

## Layout

- `tfmcp/`: the Python package. It is installed to `/opt/tfpi-mcp/lib/tfmcp` and
  run with `python3 -m tfmcp`.
  - `mcp.py`: JSON-RPC/MCP server, stdio and HTTP transports.
  - `tools.py`: every tool, its JSON schema and `INSTRUCTIONS`.
  - `bridge.py`: daemon (`tfpi-mcp serve`, systemd `tfpi-mcp.service`). It
    registers the a314 service `tfdbg` with a314d (localhost:7110), holds the
    single stream to the Amiga agent and serves MCP processes over
    `/run/tfpi-mcp/bridge.sock` (newline-delimited JSON).
  - `agent.py`: client for that socket. `proto.py`: the wire protocol.
  - `a314sh.py`: client for A314shd (localhost:23891).
  - `share.py`: the PI0: directory. `serial.py`: a314d's `serial.log` and pty.
  - `hunk.py`, `elf.py`, `symbols.py`, `backtrace.py`, `disasm.py` (objdump),
    `screen.py` (planar/HAM/EHB/RTG to PNG), `keys.py`, `crash.py`.
  - `amiga/tfdbgd`: the prebuilt agent binary (committed).
- `amiga/tfdbgd/`: agent sources. `tfdbgd.h` documents the protocol, and
  `tfmcp/proto.py` mirrors it. Change both together and bump `PROTO_VERSION`.
- `install.sh`: two-stage, idempotent installer (curl | sudo bash).
  `systemd/`, `bin/`.

## Tests

- `python3 -m unittest discover -s tests` takes about 6 s and needs only the
  standard library.
- `tests/fakes.py` has fakes for a314d's client socket, the agent and
  A314shd. `tests/helpers.Rig` wires the bridge to them through `TFMCP_*`
  environment variables (see `tfmcp/config.py`). Add new paths or ports there.
- Some tests are skipped when these are missing:
  - the m68k-amigaos-gcc toolchain at `~/amiga-gcc16` (`AMIGA_GCC`)
  - a sample ELF plus Bartman's `addr2line` (`TFMCP_TEST_ELF`)
  - an m68k objdump

## Amiga agent

- Build with `make -C amiga/tfdbgd`. It needs the bebbo toolchain
  (`PREFIX=~/amiga-gcc16`), and writes `tfmcp/amiga/tfdbgd`.
- Commit the rebuilt binary with the sources.
  `test_committed_binary_matches_source` fails when they differ. The build is
  deterministic.
- C is compiled for 68000 with no small data. The trap handler (`trap.s`,
  `tfdbg_trap_c`) runs in supervisor mode inside any task: no OS calls, no
  a4-relative data.
- It has not been run on hardware yet. Check changes to the trap and stop path
  with care.

## Rules

- Never touch the TF4060 flash, the CPLD or tfdiag. `test_formats.Safety`
  greps for the tool names.
- Respect tfpi's `/var/lib/tfpi/flash.lock`: tools refuse while it is held.
- Persistent state is written with fsync and an atomic rename
  (`config.write_json`). The Pi loses power with the Amiga.
- `README.md` is the user manual: short, plain sentences. Update it when tools
  or settings change.
