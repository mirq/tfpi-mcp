"""Test sandbox: temp share/serial/run dirs, fake a314d + agent + a314sh,
and a bridge serving a Unix socket, all wired through TFMCP_* variables."""

import importlib
import json
import os
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tfmcp import config  # noqa: E402


class Env(unittest.TestCase):
    """Only paths and config (no fakes)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tfmcp")
        self.tmp = Path(self._tmp.name)
        self.share_dir = self.tmp / "share"
        self.share_dir.mkdir()
        self.serial_dir = self.tmp / "serial"
        self.serial_dir.mkdir()
        (self.serial_dir / "serial.log").write_bytes(b"~ boot ~\n")
        conf = self.tmp / "a314fs.conf"
        conf.write_text(json.dumps({"devices": {"PI0": {"volume": "PiDisk", "path": str(self.share_dir)}}}))
        self.env = {
            "TFMCP_ETC": str(self.tmp / "etc"), "TFMCP_RUN_DIR": str(self.tmp / "run"),
            "TFMCP_BRIDGE_SOCKET": str(self.tmp / "run" / "b.sock"),
            "TFMCP_A314FS_CONF": str(conf), "TFMCP_SERIAL_DIRS": str(self.serial_dir),
            "TFMCP_TFPI_LOCK": str(self.tmp / "flash.lock"),
        }
        self._saved = {k: os.environ.get(k) for k in list(self.env) + ["TFMCP_A314D_PORT", "TFMCP_A314SH_PORT"]}
        os.environ.update(self.env)
        importlib.reload(config)

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        importlib.reload(config)
        self._tmp.cleanup()

    def set_conf(self, **values):
        path = config.CONFIG_FILE
        stored = json.loads(path.read_text()) if path.exists() else {}
        stored.update(values)
        config.write_json(path, stored)

    def serial_append(self, text):
        with open(self.serial_dir / "serial.log", "ab") as handle:
            handle.write(text.encode("latin-1"))


class Rig(Env):
    """Env + fake a314d/agent/a314sh + a running bridge + Tools."""

    connect_agent = True

    def setUp(self):
        super().setUp()
        import fakes
        from tfmcp import agent, bridge, tools
        self.fakes = fakes
        self.a314d = fakes.FakeA314d()
        self.shell = fakes.FakeShell()
        os.environ["TFMCP_A314D_PORT"] = str(self.a314d.port)
        os.environ["TFMCP_A314SH_PORT"] = str(self.shell.port)
        importlib.reload(config)
        self.bridge = bridge.Bridge(("127.0.0.1", self.a314d.port), config.BRIDGE_SOCKET)
        ready = threading.Event()
        threading.Thread(target=self.bridge.serve, args=(ready,), daemon=True).start()
        assert ready.wait(5)
        self.client = agent.Bridge(config.BRIDGE_SOCKET)
        self.tools = tools.Tools(self.client)
        self.agent = fakes.FakeAgent()
        import time
        deadline = time.time() + 5
        while not self.client.status()["a314d"] and time.time() < deadline:
            time.sleep(0.02)
        if self.connect_agent:
            self.connect()

    def connect(self):
        self.a314d.amiga_connect(self.agent)
        import time
        deadline = time.time() + 5
        while time.time() < deadline:
            st = self.client.status()
            if st["agent"] and st["hello"]:
                return
            time.sleep(0.02)
        raise AssertionError("agent did not come up")

    def tearDown(self):
        self.bridge.stop()
        self.a314d.close()
        self.shell.close()
        super().tearDown()


def hunk_file(symbols=(), lines=(), code_size=0x100, source="main.c"):
    """A one-hunk executable with HUNK_SYMBOL and a LINE debug hunk."""
    L = lambda *v: b"".join(struct.pack(">I", x) for x in v)    # noqa: E731
    out = L(0x3F3, 0, 1, 0, 0, code_size // 4)
    out += L(0x3E9, code_size // 4) + b"\x4e\x71" * (code_size // 2)
    if symbols:
        out += L(0x3F0)
        for name, value in symbols:
            raw = name.encode()
            raw += b"\0" * (-len(raw) % 4)
            out += L(len(raw) // 4) + raw + L(value)
        out += L(0)
    if lines:
        name = source.encode()
        name += b"\0" * (-len(name) % 4)
        body = L(0) + b"LINE" + L(len(name) // 4) + name + b"".join(L(ln, off) for ln, off in lines)
        out += L(0x3F1, len(body) // 4) + body
    out += L(0x3F2)
    return out
