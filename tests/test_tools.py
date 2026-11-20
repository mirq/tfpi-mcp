"""The tools end to end: bridge + fake a314d + fake agent + fake a314sh."""

import base64
import fcntl
import socket
import time
import zlib

from helpers import Rig, hunk_file

from tfmcp import config, proto
from tfmcp.mcp import ToolError


class Status(Rig):
    def test_status(self):
        st = self.tools.amiga_status()
        self.assertTrue(st["a314d"])
        self.assertTrue(st["agent"]["connected"])
        self.assertEqual(st["agent"]["info"]["cpu"], "68060")
        self.assertEqual(st["a314sh"], "ok")
        self.assertEqual(st["share"]["device"], "PI0:")
        self.assertTrue(st["serial"]["present"])
        self.assertEqual(st["hints"], [])

    def test_tfpi_lock_blocks(self):
        with open(config.TFPI_LOCK, "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            self.assertTrue(self.tools.amiga_status()["tfpi_busy"])
            with self.assertRaisesRegex(ToolError, "flashing"):
                self.tools.mem_read("0x07000000")
        self.tools.mem_read("0x07000000", 4)

    def test_agent_lost_and_back(self):
        self.a314d.amiga_reset()
        deadline = time.time() + 3
        while self.client.status()["agent"] and time.time() < deadline:
            time.sleep(0.02)
        with self.assertRaisesRegex(ToolError, "agent_start"):
            self.tools.list_tasks()
        events, _ = self.client.events(0)
        self.assertIn("agent_disconnected", [e["type"] for e in events])
        self.connect()
        self.assertTrue(self.tools.list_tasks()["tasks"])


class AgentStart(Rig):
    connect_agent = False

    def test_agent_start_copies_and_launches(self):
        self.shell.on_command = lambda cmd: (cmd.startswith("run ") and
                                             self.a314d.amiga_connect(self.agent))
        out = self.tools.agent_start(wait=5)
        self.assertTrue(out["started"])
        for name in ("tfdbgd", "A314shd", "Install"):
            self.assertTrue((self.share_dir / ".tfmcp" / name).exists(), name)
        self.assertIn("run >NIL: PI0:.tfmcp/tfdbgd", self.shell.commands[-1])

    def test_without_a314shd_points_to_install(self):
        # a314d starts a314sh only when A314shd connects: nothing listens on its port
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        config.A314SH_PORT = free.getsockname()[1]
        free.close()
        st = self.tools.amiga_status()
        self.assertIn("A314shd isn't running", st["a314sh"])
        self.assertTrue(any("Execute PI0:.tfmcp/Install" in hint for hint in st["hints"]))
        self.assertFalse(any(hint.startswith("call agent_start") for hint in st["hints"]))
        with self.assertRaisesRegex(ToolError, "Execute PI0:.tfmcp/Install"):
            self.tools.agent_start(wait=1)
        self.assertTrue((self.share_dir / ".tfmcp" / "Install").exists())


class Running(Rig):
    def test_run_through_agent(self):
        self.serial_append("")
        out = self.tools.amiga_run("list SYS:", timeout=5)
        self.assertEqual(out["via"], "agent")
        self.assertEqual(out["rc"], 0)
        self.assertEqual(out["output"], "output of list SYS:\n")

    def test_run_failure_rc_and_load_failure(self):
        self.assertEqual(self.tools.amiga_run("fail now", timeout=5)["rc"], 5)
        out = self.tools.amiga_run("missing", timeout=5)
        self.assertEqual(out["how"], "load_failed")
        self.assertIn("object not found", out["error"])

    def test_run_timeout_sends_break(self):
        out = self.tools.amiga_run("hang", timeout=0.3)
        self.assertTrue(out["timed_out"])
        self.assertEqual(out["rc"], 10)

    def test_run_via_a314sh(self):
        out = self.tools.amiga_run("echo hello", via="a314sh")
        self.assertEqual((out["via"], out["rc"], out["output"]), ("a314sh", 0, "hello\n"))

    def test_start_job_and_wait(self):
        job = self.tools.amiga_start("hang forever")["job"]
        self.assertEqual(self.tools.amiga_job(job)["state"], "running")
        self.tools.amiga_break(job=job)
        out = self.tools.amiga_job(job, wait=3)
        self.assertEqual((out["state"], out["rc"]), ("exited", 10))
        self.assertIn(job, [j["job"] for j in self.tools.amiga_jobs()["jobs"]])

    def test_break_task(self):
        self.tools.amiga_break(task="0x07800000", signal="CD")
        self.assertEqual(self.agent.last_signal, (0x07800000, 0x3000))


class Files(Rig):
    def test_write_read_list_delete(self):
        self.tools.files_mkdir("Game")
        self.tools.files_write("game/hello.txt", text="hi\n")
        data = bytes(range(256))
        self.tools.files_write("PI0:game/bin", base64_data=base64.b64encode(data[:100]).decode(), executable=True)
        self.tools.files_write("game/bin", base64_data=base64.b64encode(data[100:]).decode(), offset=100)
        self.assertEqual((self.share_dir / "Game" / "bin").read_bytes(), data)
        names = [e["name"] for e in self.tools.files_list("GAME")["entries"]]
        self.assertEqual(names, ["bin", "hello.txt"])
        self.assertEqual(self.tools.files_read("PiDisk:Game/hello.txt")["text"], "hi\n")
        self.assertIn("base64", self.tools.files_read("game/bin"))
        self.tools.files_delete("game/hello.txt")
        self.assertFalse((self.share_dir / "Game" / "hello.txt").exists())

    def test_escape_refused(self):
        for bad in ("../x", "game/../../x", "DH0:foo"):
            with self.assertRaises(ToolError):
                self.tools.files_write(bad, text="x")

    def test_amiga_read_file(self):
        out = self.tools.amiga_read_file("S:Startup-Sequence")
        self.assertIn("LoadWB", out["text"])
        with self.assertRaisesRegex(ToolError, "object not found"):
            self.tools.amiga_read_file("S:nope")


class Serial(Rig):
    def test_read_and_wait(self):
        out = self.tools.serial_read()
        self.assertIn("boot", out["text"])
        cursor = out["cursor"]

        def later():
            time.sleep(0.2)
            self.serial_append("ready> ")
        import threading
        threading.Thread(target=later).start()
        out = self.tools.serial_read(cursor=cursor, wait_for="ready>", timeout=3)
        self.assertTrue(out["matched"])
        self.assertEqual(out["text"], "ready> ")


class Inspect(Rig):
    def test_mem_read_write(self):
        self.agent.mem[0x100:0x104] = b"ABCD"
        out = self.tools.mem_read("$07000100", 16)
        self.assertIn("41 42 43 44", out["dump"])
        with self.assertRaisesRegex(ToolError, "allow_mem_write"):
            self.tools.mem_write("0x07000100", value="0x1234", width=2)
        self.set_conf(allow_mem_write=True)
        self.tools.mem_write("0x07000100", value="0x1234", width=2)
        self.assertEqual(self.agent.mem[0x100:0x102], b"\x12\x34")
        with self.assertRaisesRegex(ToolError, "not allowed"):
            self.tools.mem_read("0x00DFF000", 2)

    def test_lists(self):
        self.assertEqual(self.tools.list_tasks("input")["tasks"][0]["name"], "input.device")
        libs = self.tools.list_libraries()["libraries"]
        self.assertEqual((libs[0]["name"], libs[0]["version"]), ("exec.library", 40))
        self.assertEqual(self.tools.memory_stats()["regions"][0]["kind"], "chip")

    def test_screenshot(self):
        screens = self.tools.list_screens()["screens"]
        self.assertEqual(screens[0]["title"], "Workbench Screen")
        out = self.tools.screenshot(aspect=False)
        png = base64.b64decode(out["_content"][0]["data"])
        self.assertTrue(png.startswith(b"\x89PNG"))
        idat = png[png.index(b"IDAT") + 4:]
        raw = zlib.decompressobj().decompress(idat)
        row = raw[1:1 + 32 * 3]
        self.assertEqual(row[:3], b"\xff\x00\x00")          # index 1 = red
        self.assertEqual(row[4 * 3:5 * 3], b"\x00\x00\xff")  # index 3 = blue
        self.assertTrue(out["saved"].startswith("PI0:.tfmcp/screens/"))

    def test_input(self):
        self.tools.send_keys(text="Hi", keys=["ramiga+m"], delay_ms=0)
        codes = [e[2] for e in self.agent.inputs]
        self.assertIn(0x25, codes)          # h
        self.assertIn(0x60, codes)          # shift for H
        self.assertIn(0x67, codes)          # right amiga
        self.agent.inputs.clear()
        self.tools.send_mouse(dx=100, dy=-10, button="left")
        self.assertEqual(sum(e[4] for e in self.agent.inputs), 100)
        self.assertEqual([e[2] for e in self.agent.inputs][-2:], [0x68, 0xE8])
        self.set_conf(allow_input=False)
        with self.assertRaises(ToolError):
            self.tools.send_keys(text="x")

    def test_reboot_gated(self):
        with self.assertRaisesRegex(ToolError, "allow_reboot"):
            self.tools.amiga_reboot(confirm=True)


class Debug(Rig):
    def setUp(self):
        super().setUp()
        (self.share_dir / "prog").write_bytes(hunk_file(
            symbols=[("_main", 0x0), ("_helper", 0x20), ("_loop", 0x40)],
            lines=[(10, 0x0), (11, 0x8), (20, 0x20), (30, 0x40)]))

    def test_launch_breakpoints_step_kill(self):
        from fakes import CODE
        out = self.tools.debug_launch("PI0:prog", breakpoints=["helper", "main.c:30", "nonsense"])
        job = out["job"]
        self.assertEqual(out["state"], "stopped")
        self.assertEqual(out["stopped_at"], "entry")
        self.assertEqual(out["location"], "_main (main.c:10)")
        self.assertEqual(out["symbols"]["symbols"], 3)
        bps = out["breakpoints"]
        self.assertEqual(bps[0]["address"], f"{CODE + 0x20:08X}")
        self.assertEqual(bps[1]["address"], f"{CODE + 0x40:08X}")
        self.assertIn("error", bps[2])
        # entry breakpoint removed, the two asked for stay
        listed = self.tools.debug_breakpoint(job, "list")["breakpoints"]
        self.assertEqual([b["at"] for b in listed], ["_helper (main.c:20)", "_loop (main.c:30)"])

        out = self.tools.debug_continue(job)
        self.assertEqual((out["reason"], out["location"]), ("breakpoint", "_helper (main.c:20)"))
        out = self.tools.debug_continue(job, "step", count=3)
        self.assertEqual(out["pc"], f"{CODE + 0x26:08X}")
        self.assertEqual(len(out["stepped_through"]), 3)

        regs = self.tools.debug_registers(job)
        self.assertEqual(regs["location"], "_helper+0x6 (main.c:20)")
        bt = self.tools.debug_backtrace(job)
        self.assertEqual(bt["frames"][0]["at"], "_helper+0x6 (main.c:20)")
        dis_symbols = self.tools.debug_symbols(job=job, filter="loop")
        self.assertEqual(dis_symbols["symbols"][0]["address"], f"{CODE + 0x40:08X}")

        out = self.tools.debug_run_to(job, "h0:0x40")
        self.assertEqual(out["location"], "_loop (main.c:30)")
        out = self.tools.debug_continue(job, "kill")
        self.assertEqual((out["state"], out["how"]), ("exited", "killed"))

    def test_disassemble(self):
        import os
        import shutil
        from pathlib import Path
        tool = shutil.which("m68k-linux-gnu-objdump") or str(Path.home() / "amiga-gcc16/bin/m68k-amigaos-objdump")
        if not os.path.exists(tool):
            self.skipTest("no m68k objdump")
        os.environ["TFMCP_OBJDUMP"] = tool
        try:
            job = self.tools.debug_launch("PI0:prog")["job"]
            code = self.tools.disassemble("pc", 3, job=job)["code"].splitlines()
            self.assertEqual(len(code), 3)
            self.assertTrue(code[0].startswith("=>"))
            self.assertIn("nop", code[0])
            self.assertIn("<_main", code[0])
        finally:
            del os.environ["TFMCP_OBJDUMP"]

    def test_run_to_completion_and_output(self):
        out = self.tools.debug_launch("PI0:prog", stop_at_entry=False)
        out = self.tools.debug_wait(out["job"], timeout=3)
        self.assertEqual(out["state"], "exited")
        self.assertEqual(out["output"], "debugged program output\n")

    def test_crash_caught(self):
        job = self.tools.amiga_start("crash now", mode="exec")["job"]
        out = self.tools.debug_wait(job, timeout=3)
        self.assertEqual(out["reason"], "exception")
        self.assertEqual(out["exception"], "bus error / access fault")
        self.assertEqual(out["fault_address"], "00000004")
        report = self.tools.crash_report()
        self.assertEqual(report["agent_caught_crashes"][0]["job"], job)

    def test_pause_running(self):
        job = self.tools.amiga_start("hang", mode="exec")["job"]
        with self.assertRaisesRegex(ToolError, "amiga_break"):
            self.tools.debug_continue(job, "kill")
        out = self.tools.debug_continue(job, "pause", wait=3)
        self.assertEqual(out["reason"], "pause")
        with self.assertRaisesRegex(ToolError, "only continue"):
            self.tools.debug_continue(job, "kill")
        with self.assertRaisesRegex(ToolError, "only continue"):
            self.tools.debug_continue(job, "step")

    def test_load_failure(self):
        out = self.tools.debug_launch("missing")
        self.assertEqual(out["how"], "load_failed")


class Crash(Rig):
    HIT = """
LONG READ from 00000004                        PC: 07001008
USP:  0783A5D0 SR: 0015 SW: 0729  (U0)(-)(-)  TCB: 07836AD8
Data: 00000000 00000001 00000002 00000003 00000004 00000005 00000006 00000007
Addr: 00000000 07000100 00000000 00000000 00000000 00000000 00000000 00000000
Stck: 07001040 00000000
----> 07001008 - "PI0:prog"  Hunk 0000 Offset 00000008
Name: "Shell Process"  CLI: "prog"  Hunk 0000 Offset 00000008

Alert !! Alert 81000005 Task: 07836AD8
"""

    def test_report(self):
        (self.share_dir / "prog").write_bytes(hunk_file(symbols=[("_main", 0)], lines=[(10, 0), (12, 8)]))
        self.serial_append(self.HIT)
        out = self.tools.crash_report(symbols_path="prog")
        hit = out["enforcer_hits"][0]
        self.assertEqual((hit["access"], hit["address"], hit["pc"]), ("LONG READ", "00000004", "07001008"))
        self.assertEqual(hit["segments"][0]["at"], "_main+0x8 (main.c:12)")
        self.assertEqual(hit["task_name"], "Shell Process")
        self.assertEqual(out["alerts"][0]["meaning"], "corrupt memory list detected in FreeMem (AN_MemCorrupt)")
        self.assertTrue(out["alerts"][0]["dead_end"])

    def test_alert_decode(self):
        self.assertEqual(self.tools.alert_decode("80000004")["meaning"], "illegal instruction")
        self.assertIn("out of memory", self.tools.alert_decode("#82010000")["meaning"])
