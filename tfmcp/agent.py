"""Talk to the Amiga agent (tfdbgd) through the bridge's Unix socket."""

import base64
import json
import socket
import struct

from . import config, proto


class AgentError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Bridge:
    def __init__(self, path=None):
        self.path = str(path or config.BRIDGE_SOCKET)

    def call(self, msg, timeout=60):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout + 5)
        try:
            sock.connect(self.path)
        except OSError as error:
            sock.close()
            raise AgentError(f"the tfpi-mcp bridge is not running ({error}); "
                             "start it with: sudo systemctl start tfpi-mcp") from None
        try:
            f = sock.makefile("rwb")
            f.write(json.dumps(msg).encode() + b"\n")
            f.flush()
            line = f.readline()
        except OSError as error:
            raise AgentError(f"bridge connection failed: {error}") from None
        finally:
            sock.close()
        if not line:
            raise AgentError("the bridge closed the connection")
        return json.loads(line)

    # ---- generic ------------------------------------------------------------------

    def status(self):
        return self.call({"op": "status"}, 5)

    def events(self, since=0, timeout=0):
        reply = self.call({"op": "events", "since": since, "timeout": timeout}, timeout)
        return reply["events"], reply["seq"]

    def jobs(self):
        return self.call({"op": "jobs"})["jobs"]

    def job_meta(self, job, **meta):
        self.call({"op": "job_meta", "job": job, "meta": meta})

    def request(self, ftype, payload=b"", timeout=30, ok=(proto.ST_OK,)):
        reply = self.call({"op": "request", "type": ftype, "timeout": timeout,
                           "payload": base64.b64encode(payload).decode()}, timeout)
        if "error" in reply:
            raise AgentError(reply["error"])
        status = reply["status"]
        data = base64.b64decode(reply["payload"])
        if status not in ok:
            text = proto.STATUS_TEXT.get(status, f"status {status}")
            if status == proto.ST_DOS_ERROR and len(data) >= 4:
                text += " " + proto.dos_error(struct.unpack(">I", data[:4])[0])
            raise AgentError(text, status)
        return data

    # ---- typed helpers ---------------------------------------------------------------

    def hello(self):
        return proto.decode_hello(self.request(proto.RQ_HELLO, struct.pack(">I", proto.PROTO_VERSION)))

    def mem_read(self, addr, length, width=1, force=False):
        out = bytearray()
        step = proto.MAX_CHUNK - proto.MAX_CHUNK % 4
        while len(out) < length:
            n = min(step, length - len(out))
            out += self.request(proto.RQ_MEM_READ, proto.rq_mem_read(addr + len(out), n, width, force))
        return bytes(out)

    def mem_write(self, addr, data, width=1, force=False):
        step = 16 * 1024
        for i in range(0, len(data), step):
            self.request(proto.RQ_MEM_WRITE, proto.rq_mem_write(addr + i, data[i:i + step], width, force))

    def tasks(self):
        return proto.decode_tasks(self.request(proto.RQ_TASKS))

    def libs(self, kind):
        return proto.decode_libs(self.request(proto.RQ_LIBS, bytes([kind])), kind)

    def memstats(self):
        return proto.decode_memstats(self.request(proto.RQ_MEMSTATS))

    def signal(self, task, mask):
        self.request(proto.RQ_SIGNAL, struct.pack(">II", task, mask))

    def run(self, cmdline, mode, flags, cwd="", out="", inp="", stack=0, pri=0):
        data = self.request(proto.RQ_RUN, proto.rq_run(cmdline, mode, flags, pri, stack, cwd, out, inp))
        return struct.unpack(">I", data[:4])[0]

    def agent_jobs(self):
        return proto.decode_jobs(self.request(proto.RQ_JOBS))

    def bp(self, job, op, addr=0):
        data = self.request(proto.RQ_BP, proto.rq_bp(job, op, addr))
        r = proto.Reader(data)
        return [r.u32() for _ in range(r.u16())]

    def cont(self, job, mode, rc=20):
        self.request(proto.RQ_CONT, proto.rq_cont(job, mode, rc))

    def regs(self, job):
        return proto.decode_regs(proto.Reader(self.request(proto.RQ_REGS, struct.pack(">I", job))))

    def setreg(self, job, index, value):
        self.request(proto.RQ_SETREG, proto.rq_setreg(job, index, value))

    def segs(self, job):
        r = proto.Reader(self.request(proto.RQ_SEGS, struct.pack(">I", job)))
        entry = r.u32()
        return entry, proto.decode_segs(r)

    def screens(self):
        return proto.decode_screens(self.request(proto.RQ_SCREENS))

    def grab(self, screen, x, y, w, h, fmt):
        return self.request(proto.RQ_GRAB, proto.rq_grab(screen, x, y, w, h, fmt), timeout=60)

    def input(self, events):
        for i in range(0, len(events), 20):
            self.request(proto.RQ_INPUT, proto.rq_input(events[i:i + 20]))

    def reboot(self):
        self.request(proto.RQ_REBOOT, b"", timeout=5)

    def job_break(self, job, mask=0):
        return struct.unpack(">H", self.request(proto.RQ_JOB_BREAK, struct.pack(">II", job, mask))[:2])[0]

    def quit(self):
        self.request(proto.RQ_QUIT)

    def file_read(self, path, offset=0, length=proto.MAX_CHUNK):
        data = self.request(proto.RQ_FILE_READ, proto.rq_file_read(path, offset, length))
        return struct.unpack(">I", data[:4])[0], data[4:]
