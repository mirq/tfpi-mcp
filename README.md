# tfpi-mcp

An MCP server that lets AI agents (Claude Code, OpenCode, Cursor and other MCP
clients) run, watch and debug programs on an Amiga with a TerribleFire TF4060
and [TF Pi](https://github.com/terriblefire/tfpi).

The agent can:

- copy programs to the Amiga and run them, with output and return codes
- read the Amiga's serial output (kprintf, Enforcer and MuForce hits)
- take screenshots and type keys or move the mouse
- look at memory, tasks, libraries and screens
- debug a program: breakpoints, stepping, registers, call stacks,
  disassembly, and symbols from hunk or ELF/DWARF files
- catch crashes instead of a Guru, and explain Enforcer hits and alerts

## Install

Install TF Pi first. Then, on the Pi:

```sh
curl -fsSL https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash
```

or with wget:

```sh
wget -qO- https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash
```

Run the same command again to update. To remove it:

```sh
curl -fsSL https://raw.githubusercontent.com/mirq/tfpi-mcp/main/install.sh | sudo bash -s -- --uninstall
```

The installer:

- puts the server in `/opt/tfpi-mcp`, with the `tfpi-mcp` command in `/usr/local/bin`
- starts the `tfpi-mcp` service, which runs as the Pi user
- copies the Amiga agent to `PI0:.tfmcp/tfdbgd`
- installs `binutils-m68k-linux-gnu` for the disassembler

## Connect your AI client

The simplest way is SSH. Set up a key login to the Pi first.

Claude Code:

```sh
claude mcp add amiga -- ssh pi@tfpi.local tfpi-mcp
```

Any client with a JSON config:

```json
{"mcpServers": {"amiga": {"command": "ssh", "args": ["pi@tfpi.local", "tfpi-mcp"]}}}
```

Replace `pi@tfpi.local` with your Pi's user and name.

### HTTP instead of SSH

```sh
sudo tfpi-mcp config set http.enabled true
sudo systemctl restart tfpi-mcp
tfpi-mcp config token
```

The URL is `http://tfpi.local:8765/mcp`. Send the token as
`Authorization: Bearer <token>`. It is plain HTTP, so only use it on your home
network.

## On the Amiga

Most tools need the small agent `tfdbgd` running on the Amiga. The
`agent_start` tool starts it through A314shd. You can also start it yourself:

```
run >NIL: PI0:.tfmcp/tfdbgd
```

To have it start at boot, add that line to `S:User-Startup`, after PI0: is
mounted. Options:

- `READONLY` refuses memory writes, input and kills.
- `NOREBOOT` refuses resets.

The agent needs a 68020 or better and Kickstart 3.0 or newer. Without it,
`amiga_run` still works through A314shd, and so do files and serial.

## Tools

| Group | Tools |
| --- | --- |
| Status | `amiga_status`, `agent_start`, `agent_stop`, `amiga_events` |
| Programs | `amiga_run`, `amiga_start`, `amiga_job`, `amiga_jobs`, `amiga_break` |
| Files (PI0:) | `files_list`, `files_read`, `files_write`, `files_delete`, `files_mkdir`, `amiga_read_file` |
| Serial | `serial_read`, `serial_write` |
| System | `mem_read`, `mem_write`, `disassemble`, `list_tasks`, `list_libraries`, `memory_stats` |
| Screen, input | `list_screens`, `screenshot`, `send_keys`, `send_mouse`, `amiga_reboot` |
| Debugger | `debug_launch`, `debug_breakpoint`, `debug_continue`, `debug_run_to`, `debug_wait`, `debug_registers`, `debug_backtrace`, `debug_symbols` |
| After a crash | `crash_report`, `alert_decode` |

To try a tool from the Pi's shell:

```sh
tfpi-mcp call amiga_status
tfpi-mcp call amiga_run '{"command": "version"}'
```

`tfpi-mcp tools` lists them all.

## Debugging

`debug_launch` loads a program and stops at its first instruction. Breakpoints
can be:

- a symbol: `main`
- a source line: `game.c:120`
- a hunk offset: `h0:0x40`
- an address: `0x07812A44`

Symbols come from the executable itself if it has a symbol table (gcc and
vbcc keep one unless you strip it). Source lines need one of these:

- LINE debug hunks (vbcc or SAS/C with `-g`)
- the ELF file of an elf2hunk build (Bartman's toolchain, ACE). Pass it as
  `symbols_path`.

When a program started by the agent crashes, it stops instead of showing a
Guru. Look at it with `debug_backtrace`, `debug_registers`, `disassemble` and
`mem_read`, then end it with `debug_continue mode=kill`.

## Settings

`tfpi-mcp config show` shows the settings. Change one with
`sudo tfpi-mcp config set KEY VALUE`.

| Setting | Default | What it allows |
| --- | --- | --- |
| `allow_input` | true | `send_keys`, `send_mouse` |
| `allow_kill` | true | killing a debugged program |
| `allow_mem_write` | false | `mem_write` and changing registers |
| `allow_reboot` | false | `amiga_reboot` |
| `max_output` | 65536 | bytes of program output returned per call |
| `http.enabled`, `http.port`, `http.bind` | off, 8765, 0.0.0.0 | MCP over HTTP |

## Limits

- `send_keys` and `send_mouse` go through input.device. Games that read the
  keyboard or mouse hardware directly won't see them.
- Breakpoints only work in the program's own code, not in ROM or libraries.
  Subtasks the program starts don't have the agent's crash handler.
- A program can only be killed while it is stopped at a breakpoint, a step
  or a crash. Killing it frees its code and stack, but not the windows,
  files or libraries it opened. To end a running program, use `amiga_break`
  (Ctrl-C).
- After a pause (`debug_continue mode=pause`) the program can only continue,
  because it may be in the middle of an OS call.
- A314shd runs one command at a time and can't be interrupted. `amiga_run`
  uses the agent when it is connected, so a hung command can be stopped
  with Ctrl-C.
- While TF Pi flashes firmware, updates or runs diagnostics, a314 is
  stopped. The tools say so, and work again once it is finished.
