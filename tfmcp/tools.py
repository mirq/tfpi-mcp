"""The MCP tools: control, files, serial, inspection, debugging, post-mortem."""

import base64
import fcntl
import os
import re
import secrets
import shlex
import struct
import time

from . import a314sh, agent, backtrace, config, crash, disasm, keys, proto, screen, serial, share, symbols
from .agent import AgentError
from .mcp import Tool, ToolError

INSTRUCTIONS = """\
Controls an Amiga 4000 (TF4060 accelerator, 68060) through the TF Pi mounted on it.

Start with amiga_status. Most tools need the Amiga agent tfdbgd; if it isn't
connected call agent_start (it is launched through A314shd). If A314shd isn't
running either, ask the user to run once on the Amiga: Execute PI0:.tfmcp/Install
(it starts A314shd at every boot, and the agent now).

Typical loop: upload a program with files_write (it lands on PI0:, the Pi share
the Amiga mounts), run it with amiga_run (output + return code; Ctrl-C after the
timeout) or amiga_start for long-running programs. Watch kprintf/Enforcer output
with serial_read. Look at the screen with screenshot, drive it with send_keys /
send_mouse.

Debugging: debug_launch stops a program at its first instruction with
breakpoints set (symbols, file:line with LINE/DWARF debug info, hunk:offset or
addresses), then debug_continue / debug_run_to / debug_backtrace /
debug_registers / disassemble / mem_read. Crashes in programs started by the
agent stop the program instead of a Guru; inspect it, then kill it with
debug_continue mode=kill. crash_report parses Enforcer/MuForce hits and alerts
from the serial log.

Paths: share paths are relative to PI0: ("game/main" = PI0:game/main). Amiga
command lines use AmigaDOS syntax.
"""


class Tools:
    def __init__(self, bridge=None):
        self.bridge = bridge or agent.Bridge()
        self._symcache = {}

    # ---- plumbing ----------------------------------------------------------------------

    @staticmethod
    def conf():
        return config.load()

    @staticmethod
    def tfpi_busy():
        path = config.TFPI_LOCK
        try:
            handle = open(path)
        except OSError:
            return False
        with handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle, fcntl.LOCK_UN)
        return False

    def guard(self):
        if self.tfpi_busy():
            raise ToolError("TF Pi is flashing firmware, updating or running diagnostics (a314 is stopped). "
                            "Wait until it finishes.")

    def status(self):
        try:
            return self.bridge.status()
        except AgentError as error:
            raise ToolError(str(error)) from None

    def need_agent(self):
        self.guard()
        st = self.status()
        if not st["a314d"]:
            raise ToolError("a314d is not running on the Pi (the bridge can't register its service). "
                            "Check: systemctl status a314d")
        if not st["agent"]:
            raise ToolError("the Amiga agent tfdbgd is not connected. Call agent_start, or on the Amiga: "
                            f"run >NIL: PI0:{config.SHARE_DIR_NAME}/tfdbgd")
        return st

    def call(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AgentError as error:
            raise ToolError(str(error)) from None

    def need(self, flag, what):
        if not self.conf().get(flag):
            raise ToolError(f"{what} is disabled on this Pi. Enable it with: sudo tfpi-mcp config set {flag} true")

    def seq(self):
        return self.status()["seq"]

    def wait_job(self, job, since, timeout, types=("job_stop", "job_exit")):
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            events, seq = self.call(self.bridge.events, since, max(0.0, min(left, 30)))
            for ev in events:
                if ev.get("job") == job and ev["type"] in types:
                    return ev, ev["seq"]
                if ev["type"] == "agent_disconnected":
                    raise ToolError(f"lost the Amiga agent while waiting: {ev.get('reason')}")
            since = seq
            if time.time() >= deadline:
                return None, since

    def job_entry(self, job):
        for entry in self.call(self.bridge.jobs):
            if entry["job"] == job:
                return entry
        raise ToolError(f"no job {job} (the bridge keeps the last {50} finished ones)")

    def new_output(self, tag):
        name = time.strftime("%Y%m%d-%H%M%S") + f"-{tag}-{secrets.token_hex(3)}.out"
        try:
            local = share.work_dir("jobs") / name
            return str(local), share.amiga_path(local)
        except share.ShareError:
            return None, "T:" + name

    def read_output(self, meta, offset=0, limit=None):
        limit = limit or self.conf()["max_output"]
        local = meta.get("output")
        if local and os.path.exists(local):
            size = os.path.getsize(local)
            with open(local, "rb") as handle:
                handle.seek(offset)
                data = handle.read(limit)
        elif meta.get("amiga_output"):
            try:
                size, data = self.bridge.file_read(meta["amiga_output"], offset, min(limit, proto.MAX_CHUNK))
            except AgentError:
                return {"output": "", "output_size": 0}
        else:
            return {"output": "", "output_size": 0}
        out = {"output": data.decode("latin-1"), "output_size": size}
        if offset + len(data) < size:
            out["output_truncated"] = True
            out["output_next_offset"] = offset + len(data)
        return out

    def serial_cursor(self):
        try:
            return serial.size() if serial.directory() else None
        except OSError:
            return None

    def serial_since(self, cursor, limit=8192):
        if cursor is None:
            return None
        try:
            text, _ = serial.read(cursor, limit)
            return text
        except (serial.SerialError, OSError):
            return None

    # ---- symbols -----------------------------------------------------------------------

    def load_symbols(self, path):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None
        cached = self._symcache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            syms = symbols.Symbols.from_file(path)
        except (OSError, ValueError):
            return None
        self._symcache[path] = (mtime, syms)
        return syms

    def job_symbols(self, entry):
        path = (entry.get("meta") or {}).get("symbols")
        return self.load_symbols(path) if path else None

    def program_local(self, command, cwd):
        try:
            word = shlex.split(command)[0]
        except (ValueError, IndexError):
            return None
        local = share.to_local(word)
        if local is None and ":" not in word and cwd:
            base = share.to_local(cwd)
            if base is not None:
                local = base / word
        return str(local) if local is not None and os.path.isfile(local) else None

    def describe(self, addr, entry=None):
        if entry is None:
            return ""
        syms = self.job_symbols(entry)
        segs = entry.get("segments") or []
        if syms:
            return symbols.describe(syms.lookup(addr, segs))
        where = symbols.Symbols.where(addr, segs)
        return f"hunk {where[0]}+{where[1]:#x}" if where else ""

    def resolve(self, location, job=None):
        if location is None:
            raise ToolError("an address or location is needed")
        entry = self.job_entry(job) if job else None
        if isinstance(location, int):
            return location, "address", entry
        loc = str(location).strip()
        reg = loc.lower()
        if reg == "pc" or reg in REG_NAMES_LOWER:
            if not entry:
                raise ToolError(f"{loc!r} needs job= (a stopped job)")
            regs = self.call(self.bridge.regs, job)
            value = regs["pc"] if reg == "pc" else regs["regs"]["a7" if reg == "sp" else reg]
            return value, reg, entry
        syms = self.job_symbols(entry) if entry else None
        segs = (entry or {}).get("segments") or []
        try:
            addr, note = symbols.resolve(loc, syms, segs)
        except symbols.SymbolError as error:
            raise ToolError(f"{error}. Locations: {symbols.LOCATION_HELP}") from None
        return addr, note, entry

    # ---- status / agent --------------------------------------------------------------------

    def amiga_status(self, check_shell=True):
        out = {"tfpi_busy": self.tfpi_busy()}
        try:
            st = self.bridge.status()
            out["bridge"] = "running"
            out["a314d"] = st["a314d"]
            out["agent"] = {"connected": st["agent"], "info": st["hello"]}
        except AgentError as error:
            out["bridge"] = str(error)
            st = None
        sh = share.find()
        out["share"] = {"device": sh.device + ":", "volume": sh.volume + ":", "path": str(sh.root)} if sh else None
        d = serial.directory()
        out["serial"] = {"present": d is not None, "log_size": serial.size() if d else 0}
        if check_shell and not out["tfpi_busy"]:
            try:
                rc, text = a314sh.run("echo tfpi-mcp", timeout=4)
                out["a314sh"] = "ok" if "tfpi-mcp" in text else f"rc {rc}: {text.strip()[:200]}"
            except a314sh.ShellError as error:
                out["a314sh"] = str(error)
        if st and st["agent"]:
            out["jobs"] = [{k: j.get(k) for k in ("job", "state", "mode")} | {"command": (j.get("meta") or {}).get("command")}
                           for j in self.call(self.bridge.jobs) if j.get("state") != "exited"]
        conf = self.conf()
        out["permissions"] = {k: conf[k] for k in ("allow_mem_write", "allow_input", "allow_reboot", "allow_kill")}
        out["disassembler"] = disasm.objdump() or "missing (apt install binutils-m68k-linux-gnu)"
        hints = []
        if out["tfpi_busy"]:
            hints.append("TF Pi is busy (flash/update/diagnostics); a314 is stopped until it finishes")
        if st and not st["a314d"]:
            hints.append("a314d isn't running: sudo systemctl start a314d")
        if st and st["a314d"] and not st["agent"]:
            if out.get("a314sh", "ok") == "ok":
                hints.append("call agent_start to launch tfdbgd on the Amiga")
            else:
                hints.append("A314shd isn't running on the Amiga, so agent_start can't launch the agent. "
                             "Once, on the Amiga: " + config.INSTALL_COMMAND + " (starts A314shd at every "
                             "boot and the agent now)")
        if not sh:
            hints.append("the a314fs share (PI0:) isn't configured")
        out["hints"] = hints
        return out

    def copy_amiga_files(self):
        """Puts the agent, A314shd and the Install script in PI0:.tfmcp
        (rewritten only when they differ). Returns the agent's local path."""
        folder = share.work_dir()
        for name in config.AMIGA_FILES:
            source = config.AGENT_BINARY if name == "tfdbgd" else config.AGENT_BINARY.with_name(name)
            data = source.read_bytes()
            target = folder / name
            if not target.exists() or target.read_bytes() != data:
                share.write(share.amiga_path(target), data, executable=name != "Install")
        return folder / "tfdbgd"

    def agent_start(self, readonly=False, wait=20):
        self.guard()
        st = self.status()
        if st["agent"]:
            return {"started": False, "connected": True, "info": st["hello"]}
        if not st["a314d"]:
            raise ToolError("a314d is not running on the Pi")
        try:
            target = self.copy_amiga_files()
        except share.ShareError as error:
            raise ToolError(str(error)) from None
        command = f"run >NIL: {share.amiga_path(target)}" + (" READONLY" if readonly else "")
        try:
            rc, text = a314sh.run(command, timeout=15)
        except a314sh.ShellError as error:
            raise ToolError(f"couldn't launch the agent through A314shd: {error}. Or start just the "
                            f"agent on the Amiga: {command}") from None
        deadline = time.time() + wait
        while time.time() < deadline:
            st = self.status()
            if st["agent"] and st["hello"]:
                return {"started": True, "connected": True, "info": st["hello"]}
            time.sleep(0.5)
        raise ToolError(f"launched ({command}, rc {rc}{': ' + text.strip() if text.strip() else ''}) but the "
                        "agent did not connect. It needs a 68020+, Kickstart 3.0+ and a314.device.")

    def agent_stop(self):
        self.need_agent()
        self.call(self.bridge.quit)
        return {"stopped": True}

    # ---- running programs -------------------------------------------------------------------

    def amiga_run(self, command, timeout=30, cwd="", via="auto", stack=0):
        self.guard()
        st = self.status()
        cursor = self.serial_cursor()
        if via == "a314sh" or (via == "auto" and not st["agent"]):
            full = command if not cwd else f'cd "{cwd}"\n{command}'
            try:
                rc, text = a314sh.run(full, timeout=timeout)
            except a314sh.ShellError as error:
                raise ToolError(str(error)) from None
            limit = self.conf()["max_output"]
            out = {"via": "a314sh", "rc": rc, "output": text[:limit]}
            if len(text) > limit:
                out["output_truncated"] = True
            serial_text = self.serial_since(cursor)
            if serial_text:
                out["serial"] = serial_text
            return out
        self.need_agent()
        local, amiga = self.new_output("run")
        since = st["seq"]
        job = self.call(self.bridge.run, command, proto.MODE_SHELL, 0, cwd, amiga, "", stack)
        meta = {"command": command, "output": local, "amiga_output": amiga, "kind": "run", "cwd": cwd}
        self.call(self.bridge.job_meta, job, **meta)
        ev, since = self.wait_job(job, since, timeout, ("job_exit",))
        out = {"via": "agent", "job": job}
        if ev is None:
            out["timed_out"] = True
            try:
                out["break_sent_to"] = self.bridge.job_break(job)
            except AgentError:
                pass
            ev, since = self.wait_job(job, since, 5, ("job_exit",))
            if ev is None:
                out["note"] = (f"still running after Ctrl-C; see amiga_job job={job}, or amiga_break "
                               f"job={job} signal=D/E/F")
        if ev:
            out.update(rc=ev["rc"], how=ev["how"])
            if ev["how"] == "load_failed":
                out["error"] = proto.dos_error(ev["result2"])
        out.update(self.read_output(meta))
        serial_text = self.serial_since(cursor)
        if serial_text:
            out["serial"] = serial_text
        return out

    def amiga_start(self, command, mode="shell", cwd="", stack=0, priority=0, catch_crashes=True):
        self.need_agent()
        local, amiga = self.new_output("job")
        since = self.seq()
        flags = proto.RF_CATCH if catch_crashes and mode == "exec" else 0
        m = proto.MODE_EXEC if mode == "exec" else proto.MODE_SHELL
        job = self.call(self.bridge.run, command, m, flags, cwd, amiga, "", stack, priority)
        meta = {"command": command, "output": local, "amiga_output": amiga, "kind": "start", "cwd": cwd}
        sym = self.program_local(command, cwd) if mode == "exec" else None
        if sym:
            meta["symbols"] = sym
        self.call(self.bridge.job_meta, job, **meta)
        ev, _ = self.wait_job(job, since, 5, ("job_started", "job_exit"))
        out = {"job": job, "mode": mode, "output_file": amiga,
               "next": f"amiga_job job={job} (wait= to block), amiga_break job={job}"}
        if ev is None:
            out["state"] = "starting"
        elif ev["type"] == "job_exit":
            out.update(state="exited", rc=ev["rc"], how=ev["how"])
            if ev["how"] == "load_failed":
                out["error"] = proto.dos_error(ev["result2"])
        else:
            out["state"] = "running"
        return out

    def amiga_job(self, job, wait=0, output_offset=0):
        if wait:
            entry = self.job_entry(job)
            if entry.get("state") not in ("exited", "stopped"):
                self.wait_job(job, self.seq(), float(wait))
        entry = self.job_entry(job)
        meta = entry.get("meta") or {}
        out = {"job": job, "state": entry.get("state", "unknown"), "command": meta.get("command"),
               "mode": entry.get("mode")}
        for k in ("rc", "how"):
            if k in entry:
                out[k] = entry[k]
        if entry.get("how") == "load_failed":
            out["error"] = proto.dos_error(entry.get("result2", 0))
        if entry.get("stop"):
            out["stop"] = self.describe_stop(entry, entry["stop"])
        out.update(self.read_output(meta, output_offset))
        return out

    def amiga_jobs(self):
        out = []
        for entry in self.call(self.bridge.jobs):
            meta = entry.get("meta") or {}
            out.append({"job": entry["job"], "state": entry.get("state"), "mode": entry.get("mode"),
                        "command": meta.get("command") or entry.get("command"), "rc": entry.get("rc"),
                        "how": entry.get("how")})
        return {"jobs": out}

    def amiga_break(self, job=None, task=None, signal="C"):
        self.need_agent()
        masks = {"C": 1 << 12, "D": 1 << 13, "E": 1 << 14, "F": 1 << 15}
        mask = 0
        for ch in str(signal).upper().replace("CTRL-", "").replace(",", ""):
            if ch not in masks:
                raise ToolError("signal must be C, D, E or F (Ctrl-C...)")
            mask |= masks[ch]
        if job is not None:
            return {"job": job, "signalled": self.call(self.bridge.job_break, int(job), mask)}
        if task is None:
            raise ToolError("give job= or task= (an address from list_tasks)")
        self.call(self.bridge.signal, symbols.parse_int(task), mask)
        return {"task": task, "signalled": 1}

    # ---- files -----------------------------------------------------------------------------

    @staticmethod
    def _share(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (share.ShareError, OSError) as error:
            raise ToolError(str(error)) from None

    def files_list(self, path=""):
        return {"path": self._share(lambda: share.amiga_path(share.resolve(path, True))),
                "entries": self._share(share.listing, path)}

    def files_read(self, path, offset=0, length=65536, encoding="auto"):
        return self._share(share.read, path, int(offset), min(int(length), 4 * 1024 * 1024), encoding)

    def files_write(self, path, text=None, base64_data=None, offset=0, executable=False):
        if (text is None) == (base64_data is None):
            raise ToolError("give exactly one of text or base64_data")
        try:
            data = text.encode("latin-1") if text is not None else base64.b64decode(base64_data, validate=True)
        except (UnicodeEncodeError, ValueError) as error:
            raise ToolError(f"bad data: {error}") from None
        return self._share(share.write, path, data, int(offset), executable)

    def files_delete(self, path):
        return self._share(share.delete, path)

    def files_mkdir(self, path):
        return self._share(share.mkdir, path)

    def amiga_read_file(self, path, offset=0, length=32768):
        self.need_agent()
        size, data = self.call(self.bridge.file_read, path, int(offset), min(int(length), proto.MAX_CHUNK))
        out = {"path": path, "size": size, "offset": offset, "length": len(data),
               "more": offset + len(data) < size}
        if share._looks_text(data):
            out["text"] = data.decode("latin-1")
        else:
            out["base64"] = base64.b64encode(data).decode()
        return out

    # ---- serial ------------------------------------------------------------------------------

    def serial_read(self, cursor=None, tail=4096, wait_for=None, timeout=0, max_bytes=65536):
        try:
            if wait_for or timeout:
                start = serial.size() if cursor is None else int(cursor)
                matched, text, nxt = serial.wait_for(wait_for, start, float(timeout or 10), int(max_bytes))
                return {"text": text, "cursor": nxt, "matched": matched}
            text, nxt = serial.read(None if cursor is None else int(cursor), int(max_bytes), int(tail))
            return {"text": text, "cursor": nxt}
        except serial.SerialError as error:
            raise ToolError(str(error)) from None
        except re.error as error:
            raise ToolError(f"bad wait_for regex: {error}") from None

    def serial_write(self, text, newline=False):
        try:
            n = serial.write(text + ("\r" if newline else ""))
        except (serial.SerialError, OSError) as error:
            raise ToolError(str(error)) from None
        return {"written": n}

    # ---- memory / system ------------------------------------------------------------------------

    def mem_read(self, address, length=256, width=1, format="hex", force=False, job=None):
        self.need_agent()
        addr, note, entry = self.resolve(address, job)
        length = max(1, min(int(length), 64 * 1024))
        if width not in (1, 2, 4):
            raise ToolError("width must be 1, 2 or 4")
        length -= length % width or 0
        data = self.call(self.bridge.mem_read, addr, length or width, width, force)
        out = {"address": f"{addr:08X}", "length": len(data)}
        if note not in ("address",):
            out["location"] = note
        where = self.describe(addr, entry) if entry else ""
        if where:
            out["symbol"] = where
        if format == "base64":
            out["base64"] = base64.b64encode(data).decode()
        else:
            out["dump"] = hexdump(data, addr, width)
        return out

    def mem_write(self, address, hex_data=None, base64_data=None, value=None, width=1, force=False, job=None):
        self.need("allow_mem_write", "Writing Amiga memory")
        self.need_agent()
        addr, _, _ = self.resolve(address, job)
        given = [x is not None for x in (hex_data, base64_data, value)]
        if sum(given) != 1:
            raise ToolError("give exactly one of hex_data, base64_data or value")
        if value is not None:
            v = symbols.parse_int(value)
            data = (v & ((1 << (8 * width)) - 1)).to_bytes(width, "big")
        elif hex_data is not None:
            data = bytes.fromhex(re.sub(r"[\s:]", "", hex_data))
        else:
            data = base64.b64decode(base64_data)
        if width not in (1, 2, 4) or len(data) % width:
            raise ToolError("data length must be a multiple of width (1, 2 or 4)")
        self.call(self.bridge.mem_write, addr, data, width, force)
        return {"address": f"{addr:08X}", "written": len(data)}

    def disassemble(self, address="pc", count=16, job=None):
        self.need_agent()
        addr, note, entry = self.resolve(address, job)
        count = max(1, min(int(count), 200))
        size = count * 10 + 16
        data = b""
        while size >= 2 and not data:
            try:
                data = self.bridge.mem_read(addr, size)
            except AgentError as error:
                if error.status not in (proto.ST_BUS_ERROR, proto.ST_BAD_ADDRESS) or size <= 16:
                    raise ToolError(str(error)) from None
                size //= 2
        try:
            lines = disasm.disassemble(data, addr)
        except (RuntimeError, OSError) as error:
            raise ToolError(str(error)) from None
        pc = None
        if entry and entry.get("state") == "stopped":
            pc = (entry.get("stop") or {}).get("pc")
        out = []
        for a, raw, text in lines[:count]:
            line = f"{'=>' if a == pc else '  '} {a:08X}  {raw:<20} {text}"
            where = self.describe(a, entry) if entry else ""
            if where and ("+" not in where.split(" ")[0] or where.split(" ")[0].endswith("+0x0")):
                line += f"    <{where}>"
            out.append(line)
        return {"address": f"{addr:08X}", "location": note, "code": "\n".join(out)}

    def list_tasks(self, filter=None):
        self.need_agent()
        tasks = self.call(self.bridge.tasks)
        if filter:
            rx = re.compile(filter, re.I)
            tasks = [t for t in tasks if rx.search(t["name"]) or rx.search(t["command"])]
        for t in tasks:
            for k in ("address", "sigwait", "sigrecvd", "sp", "stack_lower", "stack_upper"):
                t[k] = f"{t[k]:08X}"
        return {"tasks": tasks}

    def list_libraries(self, kind="libraries", filter=None):
        self.need_agent()
        if kind not in proto.LIB_KINDS:
            raise ToolError(f"kind must be one of {', '.join(proto.LIB_KINDS)}")
        items = self.call(self.bridge.libs, proto.LIB_KINDS[kind])
        if filter:
            rx = re.compile(filter, re.I)
            items = [i for i in items if rx.search(i["name"])]
        for i in items:
            i["address"] = f"{i['address']:08X}"
        return {kind: items}

    def memory_stats(self):
        self.need_agent()
        stats = self.call(self.bridge.memstats)
        for r in stats["regions"]:
            r["lower"], r["upper"] = f"{r['lower']:08X}", f"{r['upper']:08X}"
        return stats

    # ---- screen and input ---------------------------------------------------------------------

    def list_screens(self):
        self.need_agent()
        out = []
        for i, s in enumerate(self.call(self.bridge.screens)):
            out.append({"index": i, "address": f"{s['address']:08X}", "title": s["title"],
                        "width": s["width"], "height": s["height"], "depth": s["depth"],
                        "rtg": s["rtg"], "front": s["front"], "mode_id": f"{s['mode_id']:08X}",
                        "ham": bool(s["mode_id"] & screen.HAM_KEY) and not s["rtg"],
                        "ehb": bool(s["mode_id"] & screen.EHB_KEY) and not s["rtg"]})
        return {"screens": out}

    def screenshot(self, screen_index=0, address=None, region=None, aspect=True, max_width=1024, save=True):
        self.need_agent()
        screens = self.call(self.bridge.screens)
        if not screens:
            raise ToolError("no screens open")
        if address is not None:
            want = symbols.parse_int(address)
            match = [s for s in screens if s["address"] == want]
            if not match:
                raise ToolError(f"no screen at {want:08X} (see list_screens)")
            s = match[0]
        else:
            if not 0 <= int(screen_index) < len(screens):
                raise ToolError(f"screen_index must be 0..{len(screens) - 1}")
            s = screens[int(screen_index)]
        width = min(s["width"], s["bitmap_width"] or s["width"])
        height = min(s["height"], s["rows"] or s["height"])
        x, y, w, h = 0, 0, width, height
        if region:
            x, y, w, h = (int(v) for v in region)
            if x < 0 or y < 0 or w <= 0 or h <= 0 or x + w > width or y + h > height:
                raise ToolError(f"region must lie inside {width}x{height}")
        if s["rtg"]:
            per = max(1, proto.MAX_CHUNK // (w * 3))
            rows = []
            for top in range(y, y + h, per):
                n = min(per, y + h - top)
                data = self.call(self.bridge.grab, s["address"], x, top, w, n, 1)
                rows += [data[i * w * 3:(i + 1) * w * 3] for i in range(n)]
        else:
            ax = x - x % 16
            aw = w + (x - ax)
            rowbytes = (aw + 15) // 16 * 2
            depth = s["depth"]
            per = max(1, proto.MAX_CHUNK // (rowbytes * depth))
            planar = bytearray()
            for top in range(y, y + h, per):
                n = min(per, y + h - top)
                planar += self.call(self.bridge.grab, s["address"], ax, top, aw, n, 0)
            idx = screen.planar_rows(bytes(planar), aw, h, depth, rowbytes)
            if ax != x:
                idx = [row[x - ax:] for row in idx]
            rows = screen.indices_to_rgb(idx, s["palette"], s["mode_id"], depth)
        sx, sy = screen.mode_aspect(s["mode_id"], width, height) if aspect and not s["rtg"] else (1, 1)
        out_w = w * sx
        if max_width and out_w > max_width:
            f = max_width / out_w
            sx, sy = sx * f, sy * f
        rows, out_w = screen.scale_rgb(rows, w, sx, sy)
        png = screen.png(rows, out_w)
        info = {"screen": f"{s['address']:08X}", "title": s["title"], "size": f"{width}x{height}",
                "depth": s["depth"], "rtg": s["rtg"], "image": f"{out_w}x{len(rows)}"}
        if region:
            info["region"] = [x, y, w, h]
        if save:
            try:
                path = share.work_dir("screens") / (time.strftime("%Y%m%d-%H%M%S") + ".png")
                path.write_bytes(png)
                info["saved"] = share.amiga_path(path)
            except (share.ShareError, OSError):
                pass
        info["_content"] = [{"type": "image", "data": base64.b64encode(png).decode(), "mimeType": "image/png"}]
        return info

    def send_keys(self, text=None, keys=None, delay_ms=30):
        self.need("allow_input", "Sending input to the Amiga")
        self.need_agent()
        groups = []
        try:
            if text:
                for ch in text:
                    groups.append(keys_mod.text_events(ch))
            for spec in keys or []:
                groups.append(keys_mod.combo_events(spec))
        except keys_mod.KeyError_ as error:
            raise ToolError(str(error)) from None
        if not groups:
            raise ToolError("give text and/or keys")
        for group in groups:
            self.call(self.bridge.input, group)
            if delay_ms:
                time.sleep(delay_ms / 1000)
        return {"sent": len(groups), "note": "input.device events: programs that read the keyboard hardware "
                "directly (most games) won't see them"}

    def send_mouse(self, dx=0, dy=0, button=None, action="click"):
        self.need("allow_input", "Sending input to the Amiga")
        self.need_agent()
        try:
            events = keys_mod.mouse_events(int(dx), int(dy), button, action)
        except keys_mod.KeyError_ as error:
            raise ToolError(str(error)) from None
        if not events:
            raise ToolError("nothing to do: give dx/dy and/or button")
        self.call(self.bridge.input, events)
        return {"events": len(events)}

    def amiga_reboot(self, confirm=False):
        self.need("allow_reboot", "Rebooting the Amiga")
        if not confirm:
            raise ToolError("this resets the Amiga (unsaved work is lost): call again with confirm=true")
        self.need_agent()
        try:
            self.bridge.reboot()
        except AgentError:
            pass            # the reply never comes: the machine is resetting
        return {"rebooting": True, "note": "tfdbgd won't be back until it is started again (agent_start, "
                "which needs A314shd: " + config.INSTALL_COMMAND + " sets that up once)"}

    # ---- debugging -------------------------------------------------------------------------------

    def describe_stop(self, entry, stop):
        out = {"reason": stop["reason"], "pc": f"{stop['pc']:08X}"}
        where = self.describe(stop["pc"], entry) if stop["pc"] else ""
        if where:
            out["location"] = where
        if stop["reason"] == "exception":
            out["exception"] = stop.get("vector_name")
            if stop.get("fault_address"):
                out["fault_address"] = f"{stop['fault_address']:08X}"
            out["hint"] = ("the program crashed; inspect it (debug_backtrace, mem_read, disassemble), then "
                           "debug_continue mode=kill (or set pc with debug_registers to skip the fault)")
        if stop["reason"] == "pause":
            out["note"] = "paused from outside: registers are those of the interrupt, pc unknown"
        regs = stop.get("regs") or {}
        out["registers"] = " ".join(f"{k.upper()}={v:08X}" for k, v in regs.items()) + f" SR={stop['sr']:04X}"
        return out

    def _stopped(self, job):
        entry = self.job_entry(job)
        if entry.get("state") != "stopped":
            raise ToolError(f"job {job} is {entry.get('state')}, not stopped")
        return entry

    def _report(self, job, ev):
        entry = self.job_entry(job)
        if ev is None:
            return {"job": job, "state": entry.get("state", "running"),
                    "note": "still running; debug_wait or debug_continue mode=pause"}
        if ev["type"] == "job_exit":
            out = {"job": job, "state": "exited", "rc": ev["rc"], "how": ev["how"]}
            out.update(self.read_output(entry.get("meta") or {}))
            return out
        out = {"job": job, "state": "stopped"}
        out.update(self.describe_stop(entry, ev))
        if disasm.objdump() and ev["pc"]:
            try:
                out["code"] = self.disassemble(ev["pc"], 6, job)["code"]
            except ToolError:
                pass
        return out

    def debug_launch(self, command, cwd="", symbols_path=None, breakpoints=None, stop_at_entry=True,
                     stack=0, timeout=20):
        self.need_agent()
        since = self.seq()
        local, amiga = self.new_output("debug")
        meta = {"command": command, "output": local, "amiga_output": amiga, "kind": "debug", "cwd": cwd}
        sym = None
        if symbols_path:
            sym = share.to_local(symbols_path) if ":" in symbols_path else None
            if sym is None:
                try:
                    sym = share.resolve(symbols_path, True)
                except share.ShareError as error:
                    raise ToolError(f"symbols: {error}") from None
            sym = str(sym)
        else:
            sym = self.program_local(command, cwd)
        if sym:
            meta["symbols"] = sym
        job = self.call(self.bridge.run, command, proto.MODE_EXEC, proto.RF_CATCH | proto.RF_STOP_ENTRY,
                        cwd, amiga, "", stack)
        self.call(self.bridge.job_meta, job, **meta)
        ev, since2 = self.wait_job(job, since, timeout, ("job_started", "job_exit"))
        if ev is None:
            raise ToolError(f"job {job} did not start within {timeout} s")
        if ev["type"] == "job_exit":
            return {"job": job, "state": "exited", "rc": ev["rc"], "how": ev["how"],
                    "error": proto.dos_error(ev["result2"]) if ev["how"] == "load_failed" else None}
        started = ev
        stop, _ = self.wait_job(job, since2, timeout)
        if stop is None or stop["type"] != "job_stop":
            return self._report(job, stop)
        entry = self.job_entry(job)
        syms = self.job_symbols(entry)
        out = {"job": job, "entry": f"{started['entry']:08X}",
               "segments": [{"start": f"{s['start']:08X}", "size": s["size"]} for s in started["segments"]]}
        if syms:
            out["symbols"] = syms.summary()
            warn = syms.check_segments(started["segments"])
            if warn:
                out["warning"] = warn
        else:
            out["symbols"] = None
            out["note"] = ("no symbols: give symbols_path (the executable with symbols, or an ELF), or put "
                           "the program on PI0:")
        bps = []
        entry_wanted = False
        for loc in breakpoints or []:
            try:
                addr, note, _ = self.resolve(loc, job)
                self.call(self.bridge.bp, job, 1, addr)
                bps.append({"location": loc, "address": f"{addr:08X}", "at": self.describe(addr, entry) or note})
                entry_wanted |= addr == started["entry"]
            except ToolError as error:
                bps.append({"location": loc, "error": str(error)})
        out["breakpoints"] = bps
        if stop["pc"] == started["entry"] and not entry_wanted:
            self.call(self.bridge.bp, job, 0, started["entry"])
        if stop_at_entry:
            out.update(self._report(job, stop))
            out["stopped_at"] = "entry"
            return out
        since3 = self.seq()
        self.call(self.bridge.cont, job, proto.RM_CONTINUE)
        ev, _ = self.wait_job(job, since3, 2)
        out.update(self._report(job, ev))
        return out

    def debug_breakpoint(self, job, action="set", location=None):
        self.need_agent()
        entry = self.job_entry(job)
        ops = {"set": 1, "clear": 0, "list": 2, "clear_all": 3}
        if action not in ops:
            raise ToolError("action must be set, clear, list or clear_all")
        addr = 0
        if action in ("set", "clear"):
            addr, _, entry = self.resolve(location, job)
        addrs = self.call(self.bridge.bp, job, ops[action], addr)
        return {"job": job, "breakpoints": [{"address": f"{a:08X}", "at": self.describe(a, entry)} for a in addrs]}

    def debug_continue(self, job, mode="continue", count=1, wait=10):
        self.need_agent()
        modes = {"continue": proto.RM_CONTINUE, "step": proto.RM_STEP, "kill": proto.RM_KILL,
                 "pause": proto.RM_PAUSE}
        if mode not in modes:
            raise ToolError("mode must be continue, step, kill or pause")
        if mode == "kill":
            self.need("allow_kill", "Killing programs")
        entry = self.job_entry(job)
        state, stop = entry.get("state"), entry.get("stop") or {}
        if mode in ("kill", "step") and state == "running":
            raise ToolError(f"job {job} is running. Stop it at a breakpoint first, or end it with "
                            f"amiga_break job={job} (Ctrl-C)" if mode == "kill" else
                            f"job {job} is running: pause it or wait for a breakpoint first")
        if mode in ("kill", "step") and stop.get("reason") == "pause":
            raise ToolError("a paused job may be inside the OS: it can only continue. Set a breakpoint "
                            f"and continue, or use amiga_break job={job} (Ctrl-C)")
        steps = max(1, min(int(count), 500)) if mode == "step" else 1
        trail = []
        ev = None
        for _ in range(steps):
            since = self.seq()
            self.call(self.bridge.cont, job, modes[mode], 20)
            types = ("job_exit",) if mode == "kill" else ("job_stop", "job_exit")
            ev, _ = self.wait_job(job, since, float(wait), types)
            if ev is None or ev["type"] != "job_stop":
                break
            if steps > 1:
                trail.append(f"{ev['pc']:08X} {self.describe(ev['pc'], self.job_entry(job))}".strip())
        out = self._report(job, ev)
        if len(trail) > 1:
            out["stepped_through"] = trail
        return out

    def debug_run_to(self, job, location, wait=10):
        self.need_agent()
        self._stopped(job)
        addr, _, entry = self.resolve(location, job)
        existing = self.call(self.bridge.bp, job, 2)
        if addr not in existing:
            self.call(self.bridge.bp, job, 1, addr)
        since = self.seq()
        self.call(self.bridge.cont, job, proto.RM_CONTINUE)
        ev, _ = self.wait_job(job, since, float(wait))
        if addr not in existing and (ev is None or ev["type"] == "job_stop"):
            try:
                self.bridge.bp(job, 0, addr)
            except AgentError:
                pass
        out = self._report(job, ev)
        if ev and ev["type"] == "job_stop" and ev["pc"] != addr:
            out["note"] = f"stopped elsewhere before reaching {location}"
        return out

    def debug_wait(self, job, timeout=30):
        entry = self.job_entry(job)
        if entry.get("state") == "stopped":
            return self._report(job, dict(entry["stop"], type="job_stop", job=job))
        if entry.get("state") == "exited":
            return self._report(job, {"type": "job_exit", "rc": entry.get("rc"), "how": entry.get("how")})
        ev, _ = self.wait_job(job, self.seq(), float(timeout))
        return self._report(job, ev)

    def debug_registers(self, job, set=None):
        self.need_agent()
        self._stopped(job)
        if set:
            self.need("allow_mem_write", "Changing registers")
            index = {n: i for i, n in enumerate(proto.REG_NAMES)}
            index.update(pc=16, sr=17, ccr=17, sp=15)
            for name, value in set.items():
                key = name.lower()
                if key not in index:
                    raise ToolError(f"unknown register {name!r}")
                self.call(self.bridge.setreg, job, index[key], symbols.parse_int(value))
        regs = self.call(self.bridge.regs, job)
        entry = self.job_entry(job)
        out = {"job": job, "pc": f"{regs['pc']:08X}", "sr": f"{regs['sr']:04X}",
               "flags": "".join(f if regs["sr"] & bit else "-" for f, bit in
                                (("X", 16), ("N", 8), ("Z", 4), ("V", 2), ("C", 1))),
               "registers": {k: f"{v:08X}" for k, v in regs["regs"].items()},
               "exact": regs["registers_exact"]}
        where = self.describe(regs["pc"], entry)
        if where:
            out["location"] = where
        pointing = {}
        for k, v in regs["regs"].items():
            w = self.describe(v, entry)
            if w:
                pointing[k] = w
        if pointing:
            out["registers_pointing_into_program"] = pointing
        return out

    def debug_backtrace(self, job, depth=16, stack_bytes=2048):
        self.need_agent()
        entry = self._stopped(job)
        regs = self.call(self.bridge.regs, job)
        sp = regs["regs"]["a7"]
        size = max(64, min(int(stack_bytes), 16384))
        stack = b""
        while size >= 64 and not stack:
            try:
                stack = self.bridge.mem_read(sp, size)
            except AgentError:
                size //= 2
        segs = entry.get("segments") or []
        syms = self.job_symbols(entry)
        data = None
        if syms:
            try:
                with open(entry["meta"]["symbols"], "rb") as handle:
                    data = handle.read()
            except (OSError, KeyError):
                data = None
        cache = {}

        def code(addr, n):
            if data is not None and syms and syms.hunks and "data_offset" in syms.hunks[0]:
                where = symbols.Symbols.where(addr, segs)
                if where:
                    h, off = where
                    hk = syms.hunks[h] if h < len(syms.hunks) else None
                    if hk and hk.get("data_offset") is not None and off + n <= hk.get("data_size", 0):
                        base = hk["data_offset"] + off
                        return data[base:base + n]
            key = addr & ~15
            if key not in cache:
                try:
                    cache[key] = self.bridge.mem_read(key, 32)
                except AgentError:
                    cache[key] = b""
            chunk = cache[key]
            off = addr - key
            return chunk[off:off + n] if off + n <= len(chunk) else None

        frames = backtrace.walk(regs["regs"], regs["pc"], stack, sp, segs, code, int(depth))
        out = []
        for f in frames:
            item = {"address": f"{f['address']:08X}", "kind": f["kind"]}
            where = self.describe(f["address"], entry)
            if where:
                item["at"] = where
            if "stack_offset" in f:
                item["sp_offset"] = f["stack_offset"]
            out.append(item)
        result = {"job": job, "frames": out, "sp": f"{sp:08X}", "stack_read": len(stack)}
        if any(f["kind"] == "scan" for f in frames):
            result["note"] = "frames marked scan were found by scanning the stack for return addresses"
        if not regs["registers_exact"]:
            result["note"] = "paused from outside: the stack scan starts in the interrupt handler"
        return result

    def debug_symbols(self, job=None, path=None, filter=None, address=None, limit=100):
        if job is None and path is None:
            raise ToolError("give job= or path= (an executable or ELF on the share)")
        if job is not None:
            entry = self.job_entry(job)
            syms = self.job_symbols(entry)
            segs = entry.get("segments") or []
            if syms is None:
                raise ToolError(f"job {job} has no symbols")
        else:
            try:
                local = str(share.resolve(path, True))
            except share.ShareError as error:
                raise ToolError(str(error)) from None
            syms = self.load_symbols(local)
            if syms is None:
                raise ToolError(f"{path} has no readable symbols")
            entry, segs = None, []
        out = {"summary": syms.summary()}
        if address is not None:
            addr = symbols.parse_int(address)
            out["lookup"] = syms.lookup(addr, segs) if segs else None
        else:
            found = syms.search(filter, int(limit))
            for f in found:
                if segs and f["hunk"] < len(segs):
                    f["address"] = f"{segs[f['hunk']]['start'] + f['offset']:08X}"
            out["symbols"] = found
        return out

    # ---- post-mortem ------------------------------------------------------------------------------

    def crash_report(self, cursor=None, tail=65536, symbols_path=None):
        try:
            text, nxt = serial.read(None if cursor is None else int(cursor), 1024 * 1024, int(tail))
        except serial.SerialError as error:
            text, nxt = "", None
            serial_error = str(error)
        else:
            serial_error = None
        parsed = crash.parse(text)
        syms = None
        if symbols_path:
            try:
                syms = self.load_symbols(str(share.resolve(symbols_path, True)))
            except share.ShareError as error:
                raise ToolError(str(error)) from None
        jobs = []
        try:
            jobs = self.bridge.jobs()
        except AgentError:
            pass
        for hit in parsed["hits"]:
            hit["address"] = f"{hit['address']:08X}"
            hit["pc"] = f"{hit['pc']:08X}"
            for seg in hit.get("segments", []):
                s = syms or self._symbols_for_program(seg["program"], jobs)
                if s:
                    seg["at"] = symbols.describe(s.lookup_hunk(seg["hunk"], seg["offset"]))
                seg["address"] = f"{seg['address']:08X}"
            for k in ("usp", "task"):
                if k in hit:
                    hit[k] = f"{hit[k]:08X}"
            for k in ("data_regs", "addr_regs", "stack"):
                if k in hit:
                    hit[k] = " ".join(f"{v:08X}" for v in hit[k])
        for a in parsed["alerts"]:
            if "task" in a:
                a["task"] = f"{a['task']:08X}"
        events = []
        try:
            evs, _ = self.bridge.events(0, 0)
            for ev in evs:
                if ev["type"] == "job_stop" and ev["reason"] == "exception":
                    entry = next((j for j in jobs if j["job"] == ev["job"]), {"meta": {}})
                    item = {"job": ev["job"], "command": (entry.get("meta") or {}).get("command")}
                    item.update(self.describe_stop(entry, ev))
                    events.append(item)
        except AgentError:
            pass
        out = {"enforcer_hits": parsed["hits"][-50:], "alerts": parsed["alerts"][-50:],
               "mungwall": parsed["mungwall"][-50:], "agent_caught_crashes": events[-20:],
               "serial_cursor": nxt}
        if serial_error:
            out["serial_error"] = serial_error
        if not (parsed["hits"] or parsed["alerts"] or parsed["mungwall"] or events):
            out["summary"] = "nothing found"
        return out

    def _symbols_for_program(self, program, jobs):
        name = os.path.basename(program.split(":")[-1]).lower()
        for entry in reversed(jobs):
            meta = entry.get("meta") or {}
            path = meta.get("symbols")
            if path and os.path.basename(path).lower() == name:
                return self.load_symbols(path)
        return None

    def alert_decode(self, code):
        try:
            text = str(code).strip().lstrip("#").split(".")[0]
            return crash.decode_alert(int(text[2:] if text.lower().startswith("0x") else text.lstrip("$"), 16))
        except ValueError:
            raise ToolError("code must be a hex alert number like 80000004 or #81000005") from None

    def amiga_events(self, since=0, timeout=0):
        events, seq = self.call(self.bridge.events, int(since), float(timeout))
        return {"events": events[-200:], "next_since": seq}


keys_mod = keys
REG_NAMES_LOWER = set(proto.REG_NAMES) | {"sp"}


def hexdump(data, addr, width=1):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        if width == 1:
            hexpart = " ".join(f"{b:02X}" for b in chunk)
        else:
            hexpart = " ".join(chunk[i:i + width].hex().upper() for i in range(0, len(chunk), width))
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr + off:08X}: {hexpart:<48} {text}")
    return "\n".join(lines)


# ---- registry ----------------------------------------------------------------------------

def _s(props=None, required=()):
    return {"type": "object", "properties": props or {}, "required": list(required), "additionalProperties": False}


S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
N = {"type": "number"}
LOC = {"type": ["string", "integer"], "description": symbols.LOCATION_HELP + "; or pc/d0..a7 of a stopped job"}
JOB = {"type": "integer", "description": "job id"}


def build(tools=None):
    t = tools or Tools()
    R, W, D = dict(read_only=True), dict(), dict(destructive=True)
    specs = [
        ("amiga_status", "Health of the whole chain: TF Pi lock, a314d, the agent (CPU, Kickstart, free memory), "
         "A314shd, the PI0: share, the serial log, running jobs, permissions.",
         _s({"check_shell": {**B, "description": "also test A314shd (default true)"}}), t.amiga_status, R),
        ("agent_start", "Copy tfdbgd to PI0:.tfmcp and start it on the Amiga through A314shd; waits until it "
         "connects. Needed by most tools.",
         _s({"readonly": {**B, "description": "refuse memory writes, input and kills on the Amiga side"},
             "wait": I}), t.agent_start, W),
        ("agent_stop", "Stop tfdbgd on the Amiga (refused while jobs run).", _s(), t.agent_stop, W),
        ("amiga_run", "Run an AmigaDOS command line and return its output and return code. Through tfdbgd (Ctrl-C "
         "after timeout) or, when the agent is missing or via=a314sh, through A314shd. Serial output produced "
         "meanwhile is included.",
         _s({"command": S, "timeout": {**N, "description": "seconds (default 30)"},
             "cwd": {**S, "description": "Amiga directory to run in"},
             "via": {"type": "string", "enum": ["auto", "agent", "a314sh"]},
             "stack": {**I, "description": "stack bytes for the command"}}, ["command"]), t.amiga_run, W),
        ("amiga_start", "Start a program without waiting (games, servers). mode=exec runs it directly "
         "(crashes stop it instead of a Guru); mode=shell uses the shell (redirection, scripts).",
         _s({"command": S, "mode": {"type": "string", "enum": ["shell", "exec"]}, "cwd": S, "stack": I,
             "priority": I, "catch_crashes": B}, ["command"]), t.amiga_start, W),
        ("amiga_job", "State, return code and output of a job; wait= seconds to block until it exits or stops.",
         _s({"job": JOB, "wait": N, "output_offset": I}, ["job"]), t.amiga_job, R),
        ("amiga_jobs", "Jobs started through the agent (running and recently finished).", _s(), t.amiga_jobs, R),
        ("amiga_break", "Send Ctrl-C (or D/E/F) to a job (shell jobs: the processes it started) or to any task.",
         _s({"job": JOB, "task": {**S, "description": "task address from list_tasks"},
             "signal": {**S, "description": "C, D, E, F or combinations like CD"}}), t.amiga_break, W),
        ("files_list", "List a directory on the PI0: share.", _s({"path": S}), t.files_list, R),
        ("files_read", "Read a file from the PI0: share (text or base64; offset/length for big files).",
         _s({"path": S, "offset": I, "length": I,
             "encoding": {"type": "string", "enum": ["auto", "text", "base64"]}}, ["path"]), t.files_read, R),
        ("files_write", "Write a file to the PI0: share (the Amiga sees it at once). offset>0 appends a chunk "
         "(uploads in pieces). executable=true for programs.",
         _s({"path": S, "text": S, "base64_data": S, "offset": I, "executable": B}, ["path"]), t.files_write, W),
        ("files_delete", "Delete a file or empty directory on the PI0: share.", _s({"path": S}, ["path"]),
         t.files_delete, D),
        ("files_mkdir", "Create a directory on the PI0: share.", _s({"path": S}, ["path"]), t.files_mkdir, W),
        ("amiga_read_file", "Read a file from any Amiga volume (DH0:, RAM:, T:, S:...) through the agent.",
         _s({"path": S, "offset": I, "length": I}, ["path"]), t.amiga_read_file, R),
        ("serial_read", "Read the Amiga's serial output (kprintf, RawPutChar, Enforcer/MuForce). Without cursor: the "
         "tail. With wait_for (regex) or timeout: wait for new output. Returns a cursor for the next call.",
         _s({"cursor": I, "tail": I, "wait_for": S, "timeout": N, "max_bytes": I}), t.serial_read, R),
        ("serial_write", "Type into the Amiga's serial input (RawMayGetChar: ROM debuggers, SAD, programs "
         "polling the serial port).", _s({"text": S, "newline": B}, ["text"]), t.serial_write, W),
        ("mem_read", "Read Amiga memory (hex dump or base64). RAM, ROM and memory boards are allowed; I/O space "
         "needs force=true. Bus errors are caught.",
         _s({"address": LOC, "length": I, "width": {"type": "integer", "enum": [1, 2, 4]},
             "format": {"type": "string", "enum": ["hex", "base64"]}, "force": B, "job": JOB}, ["address"]),
         t.mem_read, R),
        ("mem_write", "Write Amiga memory (disabled unless allow_mem_write). hex_data, base64_data or value "
         "(with width).",
         _s({"address": LOC, "hex_data": S, "base64_data": S, "value": {"type": ["string", "integer"]},
             "width": {"type": "integer", "enum": [1, 2, 4]}, "force": B, "job": JOB}, ["address"]),
         t.mem_write, D),
        ("disassemble", "Disassemble 68k code at an address, symbol, file:line or a stopped job's pc.",
         _s({"address": LOC, "count": I, "job": JOB}), t.disassemble, R),
        ("list_tasks", "Tasks and processes (state, priority, signals, stack, CLI command).",
         _s({"filter": {**S, "description": "regex on name/command"}}), t.list_tasks, R),
        ("list_libraries", "Open libraries, devices, resources, public ports or semaphores with versions.",
         _s({"kind": {"type": "string", "enum": list(proto.LIB_KINDS)}, "filter": S}), t.list_libraries, R),
        ("memory_stats", "Free/largest/total chip and fast memory and the memory regions.", _s(),
         t.memory_stats, R),
        ("list_screens", "Open Intuition screens (front first): size, depth, mode, RTG or native.", _s(),
         t.list_screens, R),
        ("screenshot", "Capture a screen as PNG (native OCS/ECS/AGA incl. HAM/EHB, or RTG). Default: the front "
         "screen, pixel aspect corrected, max 1024 wide; saved under PI0:.tfmcp/screens.",
         _s({"screen_index": I, "address": S,
             "region": {"type": "array", "items": I, "minItems": 4, "maxItems": 4,
                        "description": "[x, y, width, height]"},
             "aspect": B, "max_width": I, "save": B}), t.screenshot, R),
        ("send_keys", "Type text and/or key combos (e.g. 'return', 'ramiga+m', 'ctrl+c', 'f1', 'shift+tab') into "
         "input.device (US keymap).",
         _s({"text": S, "keys": {"type": "array", "items": S}, "delay_ms": I}), t.send_keys, W),
        ("send_mouse", "Move the mouse (relative dx/dy) and/or click: button left/right/middle, action "
         "click/double/down/up.",
         _s({"dx": I, "dy": I, "button": {"type": "string", "enum": ["left", "right", "middle"]},
             "action": {"type": "string", "enum": ["click", "double", "down", "up"]}}), t.send_mouse, W),
        ("amiga_reboot", "Reset the Amiga (ColdReboot; disabled unless allow_reboot). confirm=true required.",
         _s({"confirm": B}), t.amiga_reboot, D),
        ("debug_launch", "Start a program under the debugger, stopped at its first instruction (or running with "
         "stop_at_entry=false), with breakpoints set. Symbols come from the executable on PI0: or symbols_path "
         "(hunk with symbols/LINE debug info, or the ELF for elf2hunk builds).",
         _s({"command": S, "cwd": S, "symbols_path": S, "breakpoints": {"type": "array", "items": LOC},
             "stop_at_entry": B, "stack": I, "timeout": N}, ["command"]), t.debug_launch, W),
        ("debug_breakpoint", "Set, clear or list breakpoints of a debugged job (only inside the program's own code).",
         _s({"job": JOB, "action": {"type": "string", "enum": ["set", "clear", "list", "clear_all"]},
             "location": LOC}, ["job"]), t.debug_breakpoint, W),
        ("debug_continue", "Resume a stopped job and wait for the next stop/exit: continue, step (count "
         "instructions), kill, or pause a running one.",
         _s({"job": JOB, "mode": {"type": "string", "enum": ["continue", "step", "kill", "pause"]},
             "count": I, "wait": N}, ["job"]), t.debug_continue, W),
        ("debug_run_to", "Run a stopped job until a location (temporary breakpoint): step over calls, run to "
         "a line.", _s({"job": JOB, "location": LOC, "wait": N}, ["job", "location"]), t.debug_run_to, W),
        ("debug_wait", "Wait for a job to stop or exit.", _s({"job": JOB, "timeout": N}, ["job"]), t.debug_wait, R),
        ("debug_registers", "Registers of a stopped job (with symbols for pointers into the program); set= "
         "{\"d0\": \"0x10\", \"pc\": \"main\"} changes them (needs allow_mem_write).",
         _s({"job": JOB, "set": {"type": "object", "additionalProperties": {"type": ["string", "integer"]}}},
            ["job"]), t.debug_registers, R),
        ("debug_backtrace", "Call stack of a stopped job (frame chains, else a stack scan for return addresses).",
         _s({"job": JOB, "depth": I, "stack_bytes": I}, ["job"]), t.debug_backtrace, R),
        ("debug_symbols", "Search symbols of a job or an executable on the share, or look up an address.",
         _s({"job": JOB, "path": S, "filter": S, "address": S, "limit": I}), t.debug_symbols, R),
        ("crash_report", "Post-mortem: Enforcer/MuForce hits (symbolicated when the program is known), "
         "alerts/gurus decoded, Mungwall reports from the serial log, and crashes the agent caught.",
         _s({"cursor": I, "tail": I, "symbols_path": S}), t.crash_report, R),
        ("alert_decode", "Explain an Amiga alert / Guru Meditation number.", _s({"code": S}, ["code"]),
         t.alert_decode, R),
        ("amiga_events", "Raw agent event stream (job started/stopped/exited, agent connect/disconnect).",
         _s({"since": I, "timeout": N}), t.amiga_events, R),
    ]
    return [Tool(name, desc, schema, func, read_only=flags.get("read_only", False),
                 destructive=flags.get("destructive", False)) for name, desc, schema, func, flags in specs]
