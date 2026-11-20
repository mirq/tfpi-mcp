"""The bridge: owns the "tfdbg" a314 service and shares the Amiga agent
(tfdbgd) with every MCP session.

a314d (localhost:7110) <-> bridge <-> Unix socket (newline-delimited JSON)
                                       <- tfmcp.agent.Bridge (MCP tools)

Client operations (one JSON object per line, one reply line each):

  {"op": "status"}
  {"op": "request", "type": N, "payload": "<base64>", "timeout": s}
      -> {"status": ST_*, "payload": "<base64>"} or {"error": "..."}
  {"op": "events", "since": seq, "timeout": s}
      -> {"events": [...], "seq": last}
  {"op": "jobs"}                      the job table built from events
  {"op": "job_meta", "job": id, "meta": {...}}   notes kept with a job

The bridge reconnects to a314d after it restarts (firmware flashes and
diagnostics stop it) and accepts the agent again when it reconnects.
"""

import base64
import collections
import json
import logging
import os
import socket
import struct
import threading
import time

from . import config, proto

log = logging.getLogger("tfmcp.bridge")

# a314d client protocol (see a314d/a314d.py in a314)
MSG_REGISTER_REQ, MSG_REGISTER_RES = 1, 2
MSG_READ_MEM_REQ, MSG_READ_MEM_RES, MSG_WRITE_MEM_REQ, MSG_WRITE_MEM_RES = 5, 6, 7, 8
MSG_CONNECT, MSG_CONNECT_RESPONSE, MSG_DATA, MSG_EOS, MSG_RESET = 9, 10, 11, 12, 13
DRV_HEADER = struct.Struct("=IIB")
CONNECT_OK, CONNECT_UNKNOWN_SERVICE = 0, 3
MAX_PKT = 224
KEEP_EVENTS = 2000
KEEP_EXITED = 50


class AgentGone(Exception):
    pass


class Bridge:
    def __init__(self, a314d_addr=None, socket_path=None):
        self.a314d_addr = a314d_addr or (config.A314D_HOST, config.A314D_PORT)
        self.socket_path = str(socket_path or config.BRIDGE_SOCKET)
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.drv = None
        self.registered = False
        self.stream_id = None
        self.reader = proto.FrameReader()
        self.next_id = 1
        self.pending = {}               # id -> [threading.Event, status, payload]
        self.events = collections.deque(maxlen=KEEP_EVENTS)
        self.seq = 0
        self.jobs = collections.OrderedDict()
        self.hello = None
        self.agent_since = None
        self.stopping = False
        self.send_lock = threading.Lock()
        self.server = None

    # ---- a314d side ---------------------------------------------------------

    def _send_drv(self, ptype, stream_id, payload=b""):
        with self.send_lock:
            if self.drv is None:
                raise AgentGone("a314d is not connected")
            self.drv.sendall(DRV_HEADER.pack(len(payload), stream_id, ptype) + payload)

    def _send_stream(self, data):
        with self.lock:
            stream_id = self.stream_id
        if stream_id is None:
            raise AgentGone("the Amiga agent (tfdbgd) is not connected")
        for i in range(0, len(data), MAX_PKT):
            self._send_drv(MSG_DATA, stream_id, data[i:i + MAX_PKT])

    def _recv_exact(self, sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("a314d closed the connection")
            data += chunk
        return data

    def _connect_a314d(self):
        sock = socket.create_connection(self.a314d_addr, timeout=5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        name = proto.SERVICE_NAME.encode()
        sock.sendall(DRV_HEADER.pack(len(name), 0, MSG_REGISTER_REQ) + name)
        plen, _, ptype = DRV_HEADER.unpack(self._recv_exact(sock, DRV_HEADER.size))
        payload = self._recv_exact(sock, plen)
        if ptype != MSG_REGISTER_RES or not payload or payload[0] != 1:
            sock.close()
            raise ConnectionError(f'a314d refused the "{proto.SERVICE_NAME}" service (already registered?)')
        sock.settimeout(None)
        return sock

    def _drv_loop(self):
        backoff = 1
        while not self.stopping:
            try:
                sock = self._connect_a314d()
            except OSError as error:
                with self.lock:
                    self.registered = False
                log.debug("a314d not available: %s", error)
                time.sleep(min(backoff, 5))
                backoff = min(backoff * 2, 5)
                continue
            backoff = 1
            with self.lock:
                self.drv = sock
                self.registered = True
            log.info("registered %s with a314d", proto.SERVICE_NAME)
            try:
                buf = b""
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    buf += data
                    while len(buf) >= DRV_HEADER.size:
                        plen, stream_id, ptype = DRV_HEADER.unpack_from(buf)
                        if len(buf) < DRV_HEADER.size + plen:
                            break
                        payload = buf[DRV_HEADER.size:DRV_HEADER.size + plen]
                        buf = buf[DRV_HEADER.size + plen:]
                        self._drv_msg(ptype, stream_id, payload)
            except OSError as error:
                log.info("a314d connection lost: %s", error)
            finally:
                with self.lock:
                    self.drv = None
                    self.registered = False
                try:
                    sock.close()
                except OSError:
                    pass
                self._agent_lost("a314d went away")

    def _drv_msg(self, ptype, stream_id, payload):
        if ptype == MSG_CONNECT:
            if payload != proto.SERVICE_NAME.encode():
                self._send_drv(MSG_CONNECT_RESPONSE, stream_id, bytes([CONNECT_UNKNOWN_SERVICE]))
                return
            with self.lock:
                old = self.stream_id
            if old is not None:
                try:
                    self._send_drv(MSG_RESET, old)
                except (OSError, AgentGone):
                    pass
                self._agent_lost("the agent reconnected")
            with self.lock:
                self.stream_id = stream_id
                self.reader = proto.FrameReader()
                self.agent_since = time.time()
            self._send_drv(MSG_CONNECT_RESPONSE, stream_id, bytes([CONNECT_OK]))
            log.info("agent connected")
            threading.Thread(target=self._after_connect, daemon=True).start()
            return
        with self.lock:
            ours = stream_id == self.stream_id
        if not ours:
            return
        if ptype == MSG_DATA:
            try:
                frames = self.reader.feed(payload)
            except ValueError as error:
                log.error("protocol error from the agent: %s", error)
                try:
                    self._send_drv(MSG_RESET, stream_id)
                except (OSError, AgentGone):
                    pass
                self._agent_lost("protocol error")
                return
            for ftype, status, req_id, body in frames:
                self._frame(ftype, status, req_id, body)
        elif ptype == MSG_EOS:
            try:
                self._send_drv(MSG_EOS, stream_id)
            except (OSError, AgentGone):
                pass
            self._agent_lost("the agent closed the connection")
        elif ptype == MSG_RESET:
            self._agent_lost("the connection to the agent was reset")

    def _after_connect(self):
        try:
            status, payload = self.request(proto.RQ_HELLO, struct.pack(">I", proto.PROTO_VERSION), 10)
            hello = proto.decode_hello(payload) if status == proto.ST_OK else None
        except (AgentGone, TimeoutError, ValueError) as error:
            log.warning("hello failed: %s", error)
            hello = None
        with self.lock:
            self.hello = hello
        self._event({"type": "agent_connected", "hello": hello})
        # jobs that outlived a previous connection
        try:
            status, payload = self.request(proto.RQ_JOBS, b"", 10)
            if status == proto.ST_OK:
                with self.lock:
                    for j in proto.decode_jobs(payload):
                        entry = self.jobs.setdefault(j["job"], {"job": j["job"], "meta": {}})
                        entry.update(j)
        except (AgentGone, TimeoutError, ValueError):
            pass

    def _agent_lost(self, why):
        with self.lock:
            had = self.stream_id is not None
            self.stream_id = None
            self.hello = None
            self.agent_since = None
            pending = list(self.pending.values())
            self.pending.clear()
            for entry in self.jobs.values():
                if entry.get("state") not in ("exited",):
                    entry["state"] = "unknown"
        for slot in pending:
            slot[1] = None
            slot[2] = why
            slot[0].set()
        if had:
            log.info("agent lost: %s", why)
            self._event({"type": "agent_disconnected", "reason": why})

    def _frame(self, ftype, status, req_id, body):
        if req_id:
            with self.lock:
                slot = self.pending.pop(req_id, None)
            if slot:
                slot[1] = status
                slot[2] = body
                slot[0].set()
            return
        try:
            event = proto.decode_event(ftype, body)
        except ValueError as error:
            log.error("bad event %#x: %s", ftype, error)
            return
        self._track(event)
        self._event(event)

    def _track(self, ev):
        with self.lock:
            job_id = ev.get("job")
            if not job_id:
                return
            entry = self.jobs.setdefault(job_id, {"job": job_id, "meta": {}})
            if ev["type"] == "job_started":
                entry.update(state="running", task=ev["task"], mode=ev["mode"], entry=ev["entry"],
                             segments=ev["segments"], started=time.time())
            elif ev["type"] == "job_stop":
                entry.update(state="stopped", stop={k: v for k, v in ev.items() if k not in ("type", "job")})
            elif ev["type"] == "job_exit":
                entry.update(state="exited", rc=ev["rc"], result2=ev["result2"], how=ev["how"],
                             ended=time.time())
                entry.pop("stop", None)
                exited = [k for k, v in self.jobs.items() if v.get("state") == "exited"]
                for k in exited[:-KEEP_EXITED]:
                    del self.jobs[k]

    def _event(self, ev):
        with self.cond:
            self.seq += 1
            ev = dict(ev, seq=self.seq, time=time.time())
            self.events.append(ev)
            self.cond.notify_all()

    def request(self, ftype, payload, timeout=30):
        with self.lock:
            if self.stream_id is None:
                raise AgentGone("the Amiga agent (tfdbgd) is not connected")
            req_id = self.next_id
            self.next_id = self.next_id % 0xFFFFFFF0 + 1
            slot = [threading.Event(), None, None]
            self.pending[req_id] = slot
        try:
            self._send_stream(proto.pack_frame(ftype, req_id, payload))
        except (OSError, AgentGone) as error:
            with self.lock:
                self.pending.pop(req_id, None)
            raise AgentGone(str(error)) from None
        if not slot[0].wait(timeout):
            with self.lock:
                self.pending.pop(req_id, None)
            raise TimeoutError(f"the agent did not answer within {timeout} s")
        if slot[1] is None:
            raise AgentGone(slot[2])
        return slot[1], slot[2]

    # ---- client side --------------------------------------------------------------

    def status(self):
        with self.lock:
            return {"a314d": self.registered, "agent": self.stream_id is not None,
                    "agent_since": self.agent_since, "hello": self.hello, "seq": self.seq}

    def wait_events(self, since, timeout):
        deadline = time.time() + max(0.0, min(float(timeout), 600))
        with self.cond:
            while True:
                found = [e for e in self.events if e["seq"] > since]
                if found or time.time() >= deadline:
                    return found, self.seq
                self.cond.wait(max(0.01, deadline - time.time()))

    def handle(self, msg):
        op = msg.get("op")
        if op == "status":
            return self.status()
        if op == "request":
            try:
                status, payload = self.request(int(msg["type"]), base64.b64decode(msg.get("payload", "")),
                                               float(msg.get("timeout", 30)))
            except (AgentGone, TimeoutError) as error:
                return {"error": str(error)}
            return {"status": status, "payload": base64.b64encode(payload).decode()}
        if op == "events":
            events, seq = self.wait_events(int(msg.get("since", 0)), msg.get("timeout", 0))
            return {"events": events, "seq": seq}
        if op == "jobs":
            with self.lock:
                return {"jobs": json.loads(json.dumps(list(self.jobs.values())))}
        if op == "job_meta":
            with self.lock:
                entry = self.jobs.setdefault(int(msg["job"]), {"job": int(msg["job"]), "meta": {},
                                                               "state": "starting"})
                entry["meta"].update(msg.get("meta") or {})
            return {"ok": True}
        return {"error": f"unknown op {op!r}"}

    def _client(self, conn):
        with conn:
            f = conn.makefile("rwb")
            for line in f:
                try:
                    reply = self.handle(json.loads(line))
                except (ValueError, KeyError, TypeError) as error:
                    reply = {"error": f"bad request: {error}"}
                try:
                    f.write(json.dumps(reply).encode() + b"\n")
                    f.flush()
                except OSError:
                    return

    def serve(self, ready=None):
        path = self.socket_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o007)           # the Pi user and its group
        try:
            server.bind(path)
        finally:
            os.umask(old)
        server.listen(16)
        self.server = server
        threading.Thread(target=self._drv_loop, daemon=True, name="a314d").start()
        if ready:
            ready.set()
        while not self.stopping:
            try:
                conn, _ = server.accept()
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def stop(self):
        self.stopping = True
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        with self.lock:
            drv = self.drv
        if drv:
            try:
                drv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
