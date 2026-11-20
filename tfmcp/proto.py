"""The tfdbg wire protocol (see amiga/tfdbgd/tfdbgd.h; keep both in step).

Frame: u32 length (bytes after it), u8 type, u8 status, u16 reserved, u32 id,
payload. Big-endian. Requests and replies share the type; events are 0x40+
with id 0.
"""

import struct

PROTO_VERSION = 1
SERVICE_NAME = "tfdbg"
HEADER = struct.Struct(">IBBHI")        # length, type, status, reserved, id
MAX_FRAME = 64 * 1024 * 1024
MAX_CHUNK = 32 * 1024

RQ_HELLO, RQ_MEM_READ, RQ_MEM_WRITE, RQ_TASKS, RQ_LIBS, RQ_MEMSTATS, RQ_SIGNAL = range(1, 8)
RQ_RUN, RQ_JOBS, RQ_BP, RQ_CONT, RQ_REGS, RQ_SETREG, RQ_SCREENS, RQ_GRAB = range(8, 16)
RQ_INPUT, RQ_REBOOT, RQ_SEGS, RQ_JOB_BREAK, RQ_QUIT, RQ_FILE_READ = range(16, 22)

EV_JOB_STARTED, EV_JOB_EXIT, EV_JOB_STOP, EV_LOG = 0x41, 0x42, 0x43, 0x44

ST_OK, ST_BAD_REQUEST, ST_BAD_ADDRESS, ST_BUS_ERROR, ST_NO_JOB, ST_NOT_STOPPED = range(6)
ST_DENIED, ST_NO_MEMORY, ST_DOS_ERROR, ST_UNSUPPORTED, ST_BUSY = range(6, 11)

STATUS_TEXT = {
    ST_BAD_REQUEST: "bad request",
    ST_BAD_ADDRESS: "address not allowed (not RAM/ROM/a memory board; use force for I/O space)",
    ST_BUS_ERROR: "bus error while accessing that address",
    ST_NO_JOB: "no such job (it may have exited)",
    ST_NOT_STOPPED: "the job is not in the state needed (stopped/running)",
    ST_DENIED: "refused by the agent (started READONLY/NOREBOOT)",
    ST_NO_MEMORY: "the Amiga is out of memory",
    ST_DOS_ERROR: "AmigaDOS error",
    ST_UNSUPPORTED: "not supported for this job/screen",
    ST_BUSY: "busy (jobs are still running)",
}

MODE_EXEC, MODE_SHELL = 0, 1
RF_CATCH, RF_STOP_ENTRY = 1, 2
JS_NAMES = {0: "starting", 1: "running", 2: "stopped", 3: "exited"}
STOP_REASONS = {1: "breakpoint", 2: "step", 3: "exception", 4: "pause"}
RM_CONTINUE, RM_STEP, RM_KILL, RM_PAUSE = range(4)
EXIT_KINDS = {0: "exited", 1: "killed", 2: "load_failed"}

VECTORS = {
    2: "bus error / access fault", 3: "address error", 4: "illegal instruction",
    5: "division by zero", 6: "CHK", 7: "TRAPV", 8: "privilege violation", 9: "trace",
    10: "line A emulator", 11: "line F emulator / FPU", 14: "format error",
    48: "FPU branch on unordered", 49: "FPU inexact", 50: "FPU divide by zero",
    51: "FPU underflow", 52: "FPU operand error", 53: "FPU overflow", 54: "FPU signalling NaN",
}
for _n in range(16):
    VECTORS[32 + _n] = f"TRAP #{_n}"

# AmigaDOS error codes worth naming
DOS_ERRORS = {
    103: "insufficient free store", 121: "file is not an executable", 202: "object in use",
    203: "object already exists", 204: "directory not found", 205: "object not found",
    209: "action not known", 210: "invalid component name", 212: "object wrong type",
    213: "disk not validated", 214: "disk write-protected", 216: "directory not empty",
    218: "device (or volume) not mounted", 221: "disk full", 222: "file is protected from deletion",
    223: "file is write protected", 224: "file is read protected", 225: "not a valid DOS disk",
    226: "no disk in drive", 232: "no more entries in directory", 233: "object is soft linked",
}

TASK_STATES = {0: "invalid", 1: "added", 2: "running", 3: "ready", 4: "waiting", 5: "exception", 6: "removed"}
LIB_KINDS = {"libraries": 0, "devices": 1, "resources": 2, "ports": 3, "semaphores": 4}


def dos_error(code):
    return f"{code} ({DOS_ERRORS.get(code, 'AmigaDOS error')})"


def pack_frame(ftype, req_id, payload=b"", status=0):
    return HEADER.pack(8 + len(payload), ftype, status, 0, req_id) + payload


class FrameReader:
    """Reassembles frames from a byte stream."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data):
        self.buf += data
        frames = []
        while len(self.buf) >= 4:
            (length,) = struct.unpack_from(">I", self.buf)
            if length < 8 or length > MAX_FRAME:
                raise ValueError(f"bad frame length {length}")
            if len(self.buf) < 4 + length:
                break
            _, ftype, status, _, req_id = HEADER.unpack_from(self.buf)
            payload = bytes(self.buf[HEADER.size:4 + length])
            del self.buf[:4 + length]
            frames.append((ftype, status, req_id, payload))
        return frames


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated payload")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self):
        return self.take(1)[0]

    def i8(self):
        return struct.unpack(">b", self.take(1))[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def i16(self):
        return struct.unpack(">h", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]

    def str(self):
        return self.take(self.u16()).decode("latin-1")

    def rest(self):
        chunk = self.data[self.pos:]
        self.pos = len(self.data)
        return chunk


def pstr(text):
    data = (text or "").encode("latin-1", "replace")[:65535]
    return struct.pack(">H", len(data)) + data


# ---- request payloads -------------------------------------------------------

def rq_mem_read(addr, length, width=1, force=False):
    return struct.pack(">IIBB", addr, length, width, 1 if force else 0)


def rq_mem_write(addr, data, width=1, force=False):
    return struct.pack(">IBBH", addr, width, 1 if force else 0, 0) + data


def rq_run(cmdline, mode=MODE_SHELL, flags=RF_CATCH, pri=0, stack=0, cwd="", out="", inp=""):
    return (struct.pack(">BBbBI", mode, flags, pri, 0, stack) + pstr(cmdline) + pstr(cwd)
            + pstr(out) + pstr(inp))


def rq_bp(job, op, addr=0):
    return struct.pack(">IBI", job, op, addr)


def rq_cont(job, mode, rc=20):
    return struct.pack(">IBi", job, mode, rc)


def rq_setreg(job, index, value):
    return struct.pack(">IBI", job, index, value & 0xFFFFFFFF)


GRAB_PLANAR, GRAB_RGB, GRAB_LUT8 = range(3)   # LUT8: pen bytes of 8-bit RTG screens
PIXFMT_LUT8 = 0                                 # cybergraphics pixel format


def rq_grab(screen, x, y, w, h, fmt):
    return struct.pack(">IHHHHB", screen, x, y, w, h, fmt)


def rq_input(events):
    """events: (cls, code, qualifier, x, y); cls 1 rawkey, 2 rawmouse"""
    out = bytes([len(events)])
    for cls, code, qual, x, y in events:
        out += struct.pack(">BBHHhh", cls, 0, code, qual, x, y)
    return out


def rq_file_read(path, offset, length):
    return pstr(path) + struct.pack(">II", offset, length)


# ---- reply / event decoders -------------------------------------------------

REG_NAMES = [f"d{i}" for i in range(8)] + [f"a{i}" for i in range(8)]


def decode_hello(data):
    r = Reader(data)
    hello = {"proto": r.u16(), "agent_version": r.u16(), "attn_flags": r.u16(),
             "exec_version": r.u16(), "exec_revision": r.u16(), "kickstart": r.u16(),
             "chip_free": r.u32(), "fast_free": r.u32(), "agent_task": r.u32(), "flags": r.u32()}
    try:
        hello["vblank_hz"] = r.u8()
        hello["power_hz"] = r.u8()
    except ValueError:
        pass
    attn = hello["attn_flags"]
    cpu = "68060" if attn & 0x80 else "68040" if attn & 0x08 else "68030" if attn & 0x04 else \
        "68020" if attn & 0x02 else "68010" if attn & 0x01 else "68000"
    hello["cpu"] = cpu
    hello["fpu"] = bool(attn & 0x70) or (cpu in ("68040", "68060") and bool(attn & 0x40))
    hello["readonly"] = bool(hello["flags"] & 1)
    hello["noreboot"] = bool(hello["flags"] & 2)
    return hello


def decode_segs(r):
    return [{"start": r.u32(), "size": r.u32()} for _ in range(r.u16())]


def decode_regs(r):
    out = {"reason": STOP_REASONS.get(r.u8(), "unknown")}
    vector = r.u8()
    out["vector"] = vector
    out["vector_name"] = VECTORS.get(vector, f"vector {vector}") if vector else None
    out["frame_format"] = r.u16()
    out["fault_address"] = r.u32()
    out["fault_status"] = r.u32()
    out["registers_exact"] = bool(r.u8())
    r.u8()
    out["sr"] = r.u16()
    out["pc"] = r.u32()
    out["regs"] = {name: r.u32() for name in REG_NAMES}
    return out


def decode_event(ftype, data):
    r = Reader(data)
    if ftype == EV_JOB_STARTED:
        ev = {"type": "job_started", "job": r.u32(), "task": r.u32(), "mode": r.u8(), "flags": r.u8()}
        r.u16()
        ev["entry"] = r.u32()
        ev["segments"] = decode_segs(r)
        ev["mode"] = "exec" if ev["mode"] == MODE_EXEC else "shell"
        return ev
    if ftype == EV_JOB_EXIT:
        return {"type": "job_exit", "job": r.u32(), "rc": r.i32(), "result2": r.i32(),
                "how": EXIT_KINDS.get(r.u8(), "exited")}
    if ftype == EV_JOB_STOP:
        ev = {"type": "job_stop", "job": r.u32()}
        ev.update(decode_regs(r))
        return ev
    if ftype == EV_LOG:
        return {"type": "log", "text": data.decode("latin-1", "replace")}
    return {"type": f"unknown_{ftype:#x}", "data": data.hex()}


def decode_tasks(data):
    r = Reader(data)
    tasks = []
    for _ in range(r.u16()):
        t = {"address": r.u32(), "pri": r.i8(), "state": TASK_STATES.get(r.u8(), "?")}
        t["type"] = "process" if r.u8() == 13 else "task"
        r.u8()
        t.update({"sigwait": r.u32(), "sigrecvd": r.u32(), "sp": r.u32(), "stack_lower": r.u32(),
                  "stack_upper": r.u32(), "cli": r.u16(), "name": r.str(), "command": r.str()})
        tasks.append(t)
    return tasks


def decode_libs(data, kind):
    r = Reader(data)
    out = []
    for _ in range(r.u16()):
        e = {"address": r.u32(), "version": r.u16(), "revision": r.u16(), "open_count": r.u16(),
             "node_type": r.u8(), "pri": r.i8(), "name": r.str()}
        extra = r.str()
        if kind <= 1:
            e["id_string"] = extra
        elif kind == 3:
            e["task"] = extra
        if kind >= 3:
            for key in ("version", "revision", "open_count"):
                e.pop(key)
        out.append(e)
    return out


def decode_memstats(data):
    r = Reader(data)
    keys = ("chip_free", "fast_free", "total_free", "chip_largest", "fast_largest", "chip_total", "fast_total")
    out = {k: r.u32() for k in keys}
    regions = []
    for _ in range(r.u16()):
        reg = {"lower": r.u32(), "upper": r.u32(), "free": r.u32(), "attributes": r.u16(), "pri": r.i8()}
        r.u8()
        reg["name"] = r.str()
        attrs = reg["attributes"]
        reg["kind"] = "chip" if attrs & 2 else "fast" if attrs & 4 else "other"
        regions.append(reg)
    out["regions"] = regions
    return out


def decode_jobs(data):
    r = Reader(data)
    jobs = []
    for _ in range(r.u16()):
        j = {"job": r.u32(), "mode": "exec" if r.u8() == MODE_EXEC else "shell",
             "state": JS_NAMES.get(r.u8(), "?"), "flags": r.u8()}
        r.u8()
        j["task"] = r.u32()
        j["command"] = r.str()
        jobs.append(j)
    return jobs


def decode_screens(data):
    r = Reader(data)
    screens = []
    for _ in range(r.u16()):
        s = {"address": r.u32(), "bitmap": r.u32(), "width": r.u16(), "height": r.u16(),
             "left": r.i16(), "top": r.i16(), "depth": r.u16()}
        flags = r.u16()
        s["rtg"] = bool(flags & 1)
        s["front"] = bool(flags & 2)
        s.update({"mode_id": r.u32(), "bytes_per_row": r.u16(), "rows": r.u16(), "bitmap_width": r.u16(),
                  "bits_per_pixel": r.u16(), "pixel_format": r.u32()})
        s["planes"] = [r.u32() for _ in range(8)]
        ncol = r.u16()
        raw = r.take(ncol * 3)
        s["palette"] = [tuple(raw[i:i + 3]) for i in range(0, len(raw), 3)]
        s["title"] = r.str()
        screens.append(s)
    return screens
