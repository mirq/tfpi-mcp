"""Fakes for the tests: a314d's client socket, the Amiga agent (tfdbgd) and
A314shd's a314sh service."""

import socket
import struct
import threading
import time

from tfmcp import proto, share

DRV = struct.Struct("=IIB")
RAM = 0x07000000
RAM_SIZE = 0x40000
CODE = RAM + 0x1000           # the fake program's single code hunk
CODE_SIZE = 0x100


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


class FakeA314d:
    """Speaks a314d's client protocol on 127.0.0.1:<port>. amiga_connect()
    plays the Amiga connecting to a service; bytes the service sends go to
    the attached fake agent."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.services = {}
        self.client = None
        self.stream_id = None
        self.agent = None
        self.connected = threading.Event()
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            while True:
                plen, stream_id, ptype = DRV.unpack(_recv_exact(conn, DRV.size))
                payload = _recv_exact(conn, plen)
                if ptype == 1:          # register
                    name = payload.decode()
                    ok = name not in self.services
                    if ok:
                        self.services[name] = conn
                        self.client = conn
                    conn.sendall(DRV.pack(1, 0, 2) + bytes([1 if ok else 0]))
                elif ptype == 10:       # connect response
                    if payload[0] == 0:
                        self.connected.set()
                elif ptype == 11 and self.agent:
                    self.agent.feed(payload)
                elif ptype in (12, 13):
                    self.stream_id = None
        except (ConnectionError, OSError):
            for k, v in list(self.services.items()):
                if v is conn:
                    del self.services[k]

    def amiga_connect(self, agent, service="tfdbg", stream_id=7):
        self.agent = agent
        agent.a314d = self
        self.stream_id = stream_id
        self.connected.clear()
        deadline = time.time() + 5
        while service not in self.services and time.time() < deadline:
            time.sleep(0.02)
        conn = self.services[service]
        name = service.encode()
        conn.sendall(DRV.pack(len(name), stream_id, 9) + name)
        assert self.connected.wait(5)

    def to_service(self, data):
        with self.lock:
            try:
                for i in range(0, len(data), 224):
                    part = data[i:i + 224]
                    self.client.sendall(DRV.pack(len(part), self.stream_id, 11) + part)
            except OSError:
                pass        # torn down

    def amiga_reset(self):
        with self.lock:
            self.client.sendall(DRV.pack(0, self.stream_id, 13))

    def close(self):
        self.srv.close()
        for conn in list(self.services.values()):
            try:
                conn.close()
            except OSError:
                pass


class FakeAgent:
    """A tfdbgd stand-in with fake memory, tasks, a screen and jobs."""

    def __init__(self):
        self.reader = proto.FrameReader()
        self.a314d = None
        self.mem = bytearray(RAM_SIZE)
        self.mem[CODE - RAM:CODE - RAM + CODE_SIZE] = bytes([0x4E, 0x71]) * (CODE_SIZE // 2)   # nops
        self.jobs = {}
        self.next_job = 1
        self.inputs = []
        self.readonly = False
        self.lock = threading.Lock()

    # framing
    def feed(self, data):
        for ftype, status, req_id, payload in self.reader.feed(data):
            threading.Thread(target=self.handle, args=(ftype, req_id, payload), daemon=True).start()

    def reply(self, ftype, req_id, status=0, payload=b""):
        self.a314d.to_service(proto.pack_frame(ftype, req_id, payload, status))

    def event(self, ftype, payload):
        self.a314d.to_service(proto.pack_frame(ftype, 0, payload))

    def handle(self, ftype, req_id, payload):
        r = proto.Reader(payload)
        method = getattr(self, f"rq_{ftype}", None)
        if method is None:
            return self.reply(ftype, req_id, proto.ST_UNSUPPORTED)
        try:
            status, out = method(r)
        except ValueError:
            status, out = proto.ST_BAD_REQUEST, b""
        self.reply(ftype, req_id, status, out)

    # helpers
    def ram(self, addr, n):
        return RAM <= addr and addr + n <= RAM + RAM_SIZE

    def regs_payload(self, job):
        j = self.jobs[job]
        out = struct.pack(">BBHIIBBHI", j["reason"], j.get("vector", 0), 0, j.get("fault", 0), 0, 1, 0,
                          0x0000, j["pc"])
        out += b"".join(struct.pack(">I", v) for v in j["regs"])
        return out

    # requests
    def rq_1(self, r):        # hello
        return 0, struct.pack(">HHHHHHIIII", 1, 1, 0x80 | 0x08 | 0x04 | 0x02 | 0x01 | 0x40, 47, 0, 47,
                              1 << 20, 64 << 20, 0x07800000, 0) + bytes([50, 50])

    def rq_2(self, r):        # mem read
        addr, n, width, flags = r.u32(), r.u32(), r.u8(), r.u8()
        if not self.ram(addr, n):
            return proto.ST_BAD_ADDRESS, b""
        return 0, bytes(self.mem[addr - RAM:addr - RAM + n])

    def rq_3(self, r):        # mem write
        addr, width, flags, _ = r.u32(), r.u8(), r.u8(), r.u16()
        data = r.rest()
        if self.readonly:
            return proto.ST_DENIED, b""
        if not self.ram(addr, len(data)):
            return proto.ST_BAD_ADDRESS, b""
        self.mem[addr - RAM:addr - RAM + len(data)] = data
        return 0, b""

    def rq_4(self, r):        # tasks
        out = struct.pack(">H", 2)
        for addr, name, cmd, cli in ((0x07800000, "tfdbgd", "tfdbgd", 3), (0x07810000, "input.device", "", 0)):
            out += struct.pack(">IbBBBIIIIIH", addr, 20 if cli == 0 else 0, 4, 13 if cli else 1, 0,
                               0x1000, 0, RAM + 0x2000, RAM, RAM + 0x4000, cli)
            out += proto.pstr(name) + proto.pstr(cmd)
        return 0, out

    def rq_5(self, r):        # libs
        kind = r.u8()
        out = struct.pack(">H", 1) + struct.pack(">IHHHBb", 0x00F80000, 40, 68, 3, 9, 0)
        out += proto.pstr("exec.library") + proto.pstr("exec 40.68 (1.1.93)" if kind <= 1 else "")
        return 0, out

    def rq_6(self, r):        # memstats
        out = struct.pack(">7I", 1 << 20, 64 << 20, 65 << 20, 1 << 19, 32 << 20, 2 << 20, 128 << 20)
        out += struct.pack(">H", 1) + struct.pack(">IIIHbB", 0x400, 0x200000, 1 << 20, 3, -10, 0)
        out += proto.pstr("chip memory")
        return 0, out

    def rq_7(self, r):        # signal
        self.last_signal = (r.u32(), r.u32())
        return 0, b""

    def rq_8(self, r):        # run
        mode, flags, pri, _, stack = r.u8(), r.u8(), r.i8(), r.u8(), r.u32()
        cmd, cwd, out, inp = r.str(), r.str(), r.str(), r.str()
        with self.lock:
            job = self.next_job
            self.next_job += 1
        self.jobs[job] = {"cmd": cmd, "mode": mode, "flags": flags, "out": out, "bps": set(),
                          "pc": CODE, "regs": [0] * 15 + [RAM + 0x3000], "reason": 1}
        threading.Thread(target=self.start_job, args=(job,), daemon=True).start()
        return 0, struct.pack(">I", job)

    def write_output(self, job, text):
        local = share.to_local(self.jobs[job]["out"])
        if local is not None:
            local.write_text(text)

    def start_job(self, job):
        time.sleep(0.05)
        j = self.jobs[job]
        if j["cmd"].startswith("missing"):
            self.event(proto.EV_JOB_EXIT, struct.pack(">IiiB", job, 20, 205, 2))
            return
        segs = struct.pack(">H", 1) + struct.pack(">II", CODE, CODE_SIZE) if j["mode"] == 0 else struct.pack(">H", 0)
        self.event(proto.EV_JOB_STARTED, struct.pack(">IIBBHI", job, 0x07900000 + job, j["mode"], j["flags"], 0,
                                                     CODE if j["mode"] == 0 else 0) + segs)
        if j["mode"] == 0 and j["flags"] & proto.RF_STOP_ENTRY:
            j["bps"].add(CODE)
            self.stop(job, CODE, 1)
            return
        if j["cmd"].startswith("hang"):
            j["running"] = True
            return
        if j["cmd"].startswith("crash"):
            j["vector"] = 2
            j["fault"] = 0x00000004
            self.stop(job, CODE + 0x10, 3)
            return
        self.write_output(job, f"output of {j['cmd']}\n")
        self.exit(job, 5 if "fail" in j["cmd"] else 0)

    def stop(self, job, pc, reason):
        j = self.jobs[job]
        j.update(pc=pc, reason=reason, state="stopped")
        self.event(proto.EV_JOB_STOP, struct.pack(">I", job) + self.regs_payload(job))

    def exit(self, job, rc, how=0):
        self.jobs[job]["state"] = "exited"
        self.event(proto.EV_JOB_EXIT, struct.pack(">IiiB", job, rc, 0, how))

    def rq_9(self, r):        # jobs
        live = [(k, v) for k, v in self.jobs.items() if v.get("state") != "exited"]
        out = struct.pack(">H", len(live))
        for k, v in live:
            out += struct.pack(">IBBBBI", k, v["mode"], 2 if v.get("state") == "stopped" else 1, v["flags"], 0,
                               0x07900000 + k) + proto.pstr(v["cmd"])
        return 0, out

    def rq_10(self, r):       # bp
        job, op, addr = r.u32(), r.u8(), r.u32()
        j = self.jobs.get(job)
        if not j:
            return proto.ST_NO_JOB, b""
        if op == 1:
            if not CODE <= addr < CODE + CODE_SIZE or addr & 1:
                return proto.ST_BAD_ADDRESS, b""
            j["bps"].add(addr)
        elif op == 0:
            if addr not in j["bps"]:
                return proto.ST_BAD_ADDRESS, b""
            j["bps"].discard(addr)
        elif op == 3:
            j["bps"].clear()
        bps = sorted(j["bps"])
        return 0, struct.pack(">H", len(bps)) + b"".join(struct.pack(">I", a) for a in bps)

    def rq_11(self, r):       # cont
        job, mode, rc = r.u32(), r.u8(), r.i32()
        j = self.jobs.get(job)
        if not j:
            return proto.ST_NO_JOB, b""
        if j.get("state") != "stopped":
            if mode == proto.RM_PAUSE and j.get("running"):
                threading.Timer(0.05, self.stop, (job, 0, 4)).start()
                return 0, b""
            return proto.ST_NOT_STOPPED, b""
        if mode in (proto.RM_KILL, proto.RM_STEP) and j["reason"] == 4:
            return proto.ST_UNSUPPORTED, b""
        j["state"] = "running"
        if mode == proto.RM_KILL:
            threading.Timer(0.05, self.exit, (job, rc, 1)).start()
        elif mode == proto.RM_STEP:
            threading.Timer(0.05, self.stop, (job, j["pc"] + 2, 2)).start()
        else:
            nxt = sorted(a for a in j["bps"] if a > j["pc"])
            if nxt:
                threading.Timer(0.05, self.stop, (job, nxt[0], 1)).start()
            else:
                def finish():
                    self.write_output(job, "debugged program output\n")
                    self.exit(job, 0)
                threading.Timer(0.05, finish).start()
        return 0, b""

    def rq_12(self, r):       # regs
        job = r.u32()
        if job not in self.jobs:
            return proto.ST_NO_JOB, b""
        if self.jobs[job].get("state") != "stopped":
            return proto.ST_NOT_STOPPED, b""
        return 0, self.regs_payload(job)

    def rq_13(self, r):       # setreg
        job, idx, val = r.u32(), r.u8(), r.u32()
        j = self.jobs[job]
        if idx < 15:
            j["regs"][idx] = val
        elif idx == 16:
            j["pc"] = val
        return 0, b""

    rtg_lut8 = False        # screen is 8-bit RTG instead of planar
    lut8_supported = True   # agent knows grab format 2

    def rq_14(self, r):       # screens: one 32x4 lores, depth 2
        if self.rtg_lut8:
            out = struct.pack(">H", 1)
            out += struct.pack(">IIHHhhHHIHHHHI", RAM + 0x8000, RAM + 0x8100, 32, 4, 0, 0, 8, 3, 0x50011000,
                               32, 4, 32, 8, 0)
            out += struct.pack(">8I", *[0] * 8)
            out += struct.pack(">H", 4) + bytes([170, 170, 170, 0, 0, 0, 255, 255, 255, 102, 136, 187])
            out += proto.pstr("Workbench Screen")
            return 0, out
        out = struct.pack(">H", 1)
        out += struct.pack(">IIHHhhHHIHHHHI", RAM + 0x8000, RAM + 0x8100, 32, 4, 0, 0, 2, 2, 0x00000000,
                           4, 4, 32, 0, 0)
        out += struct.pack(">8I", RAM + 0x9000, RAM + 0x9100, 0, 0, 0, 0, 0, 0)
        out += struct.pack(">H", 4) + bytes([0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255])
        out += proto.pstr("Workbench Screen")
        return 0, out

    def rq_15(self, r):       # grab planar: plane 0 = 0xFF..., plane 1 = 0x0F...
        screen, x, y, w, h, fmt = r.u32(), r.u16(), r.u16(), r.u16(), r.u16(), r.u8()
        if self.rtg_lut8:
            if fmt == 2 and self.lut8_supported:
                return 0, bytes((i % 4) for i in range(w)) * h
            if fmt == 2:
                return proto.ST_BAD_REQUEST, b""
            if fmt == 1:        # Picasso96's RGB of a LUT8 screen: wrong colours
                return 0, b"\x0a\xd2\x25" * w * h
        if fmt != 0:
            return proto.ST_UNSUPPORTED, b""
        rowbytes = (w + 15) // 16 * 2
        return 0, (b"\xFF" * rowbytes + b"\x0F" * rowbytes) * h

    def rq_16(self, r):       # input
        n = r.u8()
        for _ in range(n):
            self.inputs.append((r.u8(), r.u8(), r.u16(), r.u16(), r.i16(), r.i16()))
        return 0, b""

    def rq_17(self, r):       # reboot: never answers
        time.sleep(30)
        return 0, b""

    def rq_18(self, r):
        return 0, struct.pack(">I", CODE) + struct.pack(">H", 1) + struct.pack(">II", CODE, CODE_SIZE)

    def rq_19(self, r):       # job break
        job, mask = r.u32(), r.u32()
        j = self.jobs.get(job)
        if not j:
            return proto.ST_NO_JOB, b""
        if j.get("running"):
            j["running"] = False
            threading.Timer(0.05, self.exit, (job, 10, 0)).start()
        return 0, struct.pack(">H", 1)

    def rq_20(self, r):
        return 0, b""

    def rq_21(self, r):       # file read
        path, offset, n = r.str(), r.u32(), r.u32()
        if path.upper() == "S:STARTUP-SEQUENCE":
            data = b"C:SetPatch QUIET\nLoadWB\n"
            return 0, struct.pack(">I", len(data)) + data[offset:offset + n]
        return proto.ST_DOS_ERROR, struct.pack(">I", 205)


class FakeShell:
    """A314shd through a314sh's control port."""

    def __init__(self, connected=True):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.connected = connected
        self.commands = []
        self.on_command = None
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                try:
                    (n,) = struct.unpack(">I", _recv_exact(conn, 4))
                    cmd = _recv_exact(conn, n).decode("latin-1")
                except ConnectionError:
                    continue
                self.commands.append(cmd)
                if not self.connected:
                    rc, out = -1, b"a314sh: the Amiga-side daemon is not connected\n"
                else:
                    rc, out = 0, (cmd.split(" ", 1)[1] + "\n").encode() if cmd.startswith("echo ") else b""
                    if self.on_command:
                        self.on_command(cmd)
                conn.sendall(struct.pack(">iI", rc, len(out)) + out)

    def close(self):
        self.srv.close()
