"""Hunk/ELF symbols, planar/HAM/EHB pixels, keys, crash parsing, the agent build."""

import filecmp
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, hunk_file

from tfmcp import config, crash, hunk, keys, screen, symbols

GCC_PREFIX = Path(os.environ.get("AMIGA_GCC", str(Path.home() / "amiga-gcc16")))
GCC = GCC_PREFIX / "bin" / "m68k-amigaos-gcc"


class Hunks(unittest.TestCase):
    def test_synthetic(self):
        data = hunk_file(symbols=[("_main", 0), ("_f", 0x10)], lines=[(5, 0), (9, 0x12)])
        syms = symbols.Symbols.from_bytes(data)
        segs = [{"start": 0x1000, "size": 0x100}]
        self.assertEqual(symbols.describe(syms.lookup(0x1014, segs)), "_f+0x4 (main.c:9)")
        self.assertEqual(symbols.resolve("f", syms, segs)[0], 0x1010)
        self.assertEqual(symbols.resolve("main.c:6", syms, segs)[0], 0x1012)     # next line with code
        self.assertEqual(symbols.resolve("h0:$20", syms, segs)[0], 0x1020)
        self.assertEqual(symbols.resolve("$7000", syms, segs)[0], 0x7000)
        self.assertIsNone(syms.check_segments(segs))
        self.assertIn("wrong symbol file", syms.check_segments(segs * 2))

    @unittest.skipUnless(GCC.exists(), "no m68k-amigaos-gcc")
    def test_gcc_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "t.c"
            src.write_text("int counter;\nstatic int helper(int x){return x*3;}\n"
                           "int main(void){counter=helper(4);return counter;}\n")
            out = Path(tmp) / "t"
            subprocess.run([str(GCC), "-noixemul", "-O1", "-g", "-o", str(out), str(src)], check=True)
            parsed = hunk.parse(out.read_bytes())
            names = {n for _, _, n in parsed["symbols"]}
            self.assertIn("_main", names)
            self.assertIn("_counter", names)
            self.assertEqual([h["type"] for h in parsed["hunks"]], ["code", "data", "bss"])


class Pixels(unittest.TestCase):
    def test_planar(self):
        # 16 pixels, 2 planes: plane0 = 0xAAAA, plane1 = 0xFF00
        rows = screen.planar_rows(b"\xAA\xAA\xFF\x00", 16, 1, 2, 2)
        self.assertEqual(list(rows[0]), [3, 2, 3, 2, 3, 2, 3, 2, 1, 0, 1, 0, 1, 0, 1, 0])

    def test_ham6_and_ehb(self):
        pal = [(0, 0, 0), (255, 255, 255)] + [(0, 0, 0)] * 30
        # HAM6: set colour 1, then modify red to 0, then blue to 0xF
        rgb = screen.indices_to_rgb([bytes([1, 0x20 | 0, 0x10 | 0xF])], pal, screen.HAM_KEY, 6)[0]
        self.assertEqual(list(rgb), [255, 255, 255, 0, 255, 255, 0, 255, 255])
        rgb = screen.indices_to_rgb([bytes([33])], pal, screen.EHB_KEY, 6)[0]
        self.assertEqual(list(rgb), [127, 127, 127])

    def test_png_and_scale(self):
        rows, w = screen.scale_rgb([b"\x01\x02\x03" * 2], 2, 2, 2)
        self.assertEqual((w, len(rows), rows[0]), (4, 2, b"\x01\x02\x03" * 4))
        png = screen.png(rows, w)
        self.assertEqual(struct.unpack(">II", png[16:24]), (4, 2))


class Keys(unittest.TestCase):
    def test_text_and_combos(self):
        ev = keys.text_events("a")
        self.assertEqual([e[1] for e in ev], [0x20, 0xA0])
        ev = keys.combo_events("ramiga+m")
        self.assertEqual([e[1] for e in ev], [0x67, 0x37, 0xB7, 0xE7])
        self.assertEqual(ev[1][2], 0x80)
        self.assertEqual(keys.combo_events("f10")[0][1], 0x59)
        with self.assertRaises(keys.KeyError_):
            keys.combo_events("hyper+x")
        moves = keys.mouse_events(200, 0)
        self.assertEqual(sum(e[3] for e in moves), 200)
        self.assertTrue(all(abs(e[3]) <= 64 for e in moves))


class Crash(unittest.TestCase):
    def test_muforce_word_write(self):
        text = ("WORD-WRITE to  00000100        data=1234       PC: 07812A44\n"
                "USP:  0781C1B8 SR: 0015 SW: 0729  (U0)(-)(-)  TCB: 07816A60\n"
                "----> 07812A44 - \"Work:game\"  Hunk 0001 Offset 0000005C\n\n")
        hit = crash.parse(text)["hits"][0]
        self.assertEqual((hit["access"], hit["data"], hit["task"]), ("WORD WRITE", 0x1234, 0x07816A60))
        self.assertEqual(hit["segments"][0]["hunk"], 1)

    def test_alerts(self):
        self.assertEqual(crash.decode_alert(0x8000000B)["meaning"], "line F emulator (opcode 1111 / FPU)")
        self.assertFalse(crash.decode_alert(0x01000009)["dead_end"])
        self.assertIn("dos.library", crash.decode_alert(0x07010000)["meaning"])


class AgentBinary(unittest.TestCase):
    @unittest.skipUnless(GCC.exists(), "no m68k-amigaos-gcc")
    def test_committed_binary_matches_source(self):
        src = ROOT / "amiga" / "tfdbgd"
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "amiga" / "tfdbgd"
            shutil.copytree(src, work, ignore=shutil.ignore_patterns("*.o"))
            (Path(tmp) / "tfmcp" / "amiga").mkdir(parents=True)
            subprocess.run(["make", "-s", f"PREFIX={GCC_PREFIX}"], cwd=work, check=True, capture_output=True)
            self.assertTrue(filecmp.cmp(Path(tmp) / "tfmcp" / "amiga" / "tfdbgd", config.AGENT_BINARY,
                                        shallow=False), "tfmcp/amiga/tfdbgd is stale: run make in amiga/tfdbgd")

    def test_binary_is_an_amiga_executable(self):
        data = config.AGENT_BINARY.read_bytes()
        self.assertTrue(hunk.is_hunk(data))


class Safety(unittest.TestCase):
    def test_never_touches_flash_tools(self):
        for path in (ROOT / "tfmcp").glob("*.py"):
            text = path.read_text()
            for word in ("fomu-flash", "xc3sprog", "tfdiag", "openocd", "setgpio"):
                self.assertNotIn(word, text, f"{path.name} mentions {word}")


ELF_SAMPLE = Path(os.environ.get("TFMCP_TEST_ELF", str(Path.home() / "amiga/ace-cmake-starter/build/showcase.elf")))
ADDR2LINE = shutil.which("m68k-amiga-elf-addr2line") or next(
    iter(sorted(Path.home().glob(".vscode/extensions/bartmanabyss.amiga-debug-*/bin/linux/opt/bin/"
                                 "m68k-amiga-elf-addr2line"))), None)


class Elf(unittest.TestCase):
    @unittest.skipUnless(ELF_SAMPLE.exists() and ADDR2LINE, "no sample ELF / Bartman addr2line")
    def test_lines_match_addr2line(self):
        syms = symbols.Symbols.from_file(ELF_SAMPLE)
        self.assertGreater(len(syms.lines), 100)
        text = syms.hunks[0]
        offs = list(range(0x100, text["size"] - 2, max(2, (text["size"] // 50) & ~1)))[:50]
        out = subprocess.run([str(ADDR2LINE), "-e", str(ELF_SAMPLE)] + [hex(text["addr"] + o) for o in offs],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        for off, expected in zip(offs, out):
            if "??" in expected:
                continue
            info = syms.lookup_hunk(0, off)
            self.assertIn(f"{os.path.basename(info.get('file', '?'))}:{info.get('line')}", expected, hex(off))
