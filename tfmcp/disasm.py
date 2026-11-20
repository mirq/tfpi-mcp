"""68k disassembly through binutils' objdump (Debian package
binutils-m68k-linux-gnu, installed by install.sh), on raw bytes read from
the Amiga."""

import os
import re
import shutil
import subprocess
import tempfile

CANDIDATES = ("m68k-linux-gnu-objdump", "m68k-amigaos-objdump", "m68k-elf-objdump")
LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} )+)\s*(.*)$")


def objdump():
    custom = os.environ.get("TFMCP_OBJDUMP")
    if custom:
        return custom if shutil.which(custom) or os.path.exists(custom) else None
    for name in CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def disassemble(data, address, cpu="68060"):
    """[(address, hex bytes, text)] or raises RuntimeError."""
    tool = objdump()
    if tool is None:
        raise RuntimeError("no 68k objdump on the Pi: sudo apt install binutils-m68k-linux-gnu")
    with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
        handle.write(data)
        handle.flush()
        result = subprocess.run(
            [tool, "-D", "-b", "binary", "-m", f"m68k:{cpu}", f"--adjust-vma={address:#x}",
             "--endian=big", handle.name], capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "objdump failed")
    out = []
    for line in result.stdout.splitlines():
        m = LINE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2).replace(" ", ""), m.group(3).strip()))
    return out
