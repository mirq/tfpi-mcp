"""Post-mortem: Enforcer/MuForce hits, Mungwall reports and alerts (gurus)
found in the serial log, and Alert number decoding."""

import re

HIT = re.compile(r"(BYTE|WORD|LONG|LINE)[- ](READ|WRITE)\s+(?:from|to)\s+([0-9A-Fa-f]{8})"
                 r"(?:\s+data=([0-9A-Fa-f]+))?\s+PC:\s*([0-9A-Fa-f]{8})")
TCB = re.compile(r"USP:\s*([0-9A-Fa-f]{8})\s+SR:\s*([0-9A-Fa-f]{4}).*?TCB:\s*([0-9A-Fa-f]{8})")
REGS = re.compile(r"^(Data|Addr|Stck):\s*((?:[0-9A-Fa-f]{8}\s*)+)")
SEGHIT = re.compile(r"([0-9A-Fa-f]{8})\s+-\s+\"([^\"]*)\"\s+Hunk\s+([0-9A-Fa-f]+)\s+Offset\s+([0-9A-Fa-f]+)")
NAME = re.compile(r"Name:\s*\"([^\"]*)\"(?:\s+CLI:\s*\"([^\"]*)\")?(?:\s+Hunk\s+([0-9A-Fa-f]+)\s+Offset\s+([0-9A-Fa-f]+))?")
ALERT = re.compile(r"(?:Alert\s*!!\s*Alert|Guru Meditation|Software Failure|Recoverable Alert|ALERT)"
                   r"[^0-9A-Fa-f#]*#?\s*([0-9A-Fa-f]{8})(?:[.\s]+(?:Task:?\s*)?([0-9A-Fa-f]{8}))?", re.I)
MUNGWALL = re.compile(r"(?i)mungwall|muguardianangel|wipeout|memory corruption")

SUBSYSTEMS = {
    0x00: "CPU trap", 0x01: "exec.library", 0x02: "graphics.library", 0x03: "layers.library",
    0x04: "intuition.library", 0x05: "math library", 0x07: "dos.library", 0x08: "ramlib",
    0x09: "icon.library", 0x0A: "expansion.library", 0x0B: "diskfont.library",
    0x0C: "utility.library", 0x0D: "keymap.library", 0x10: "audio.device", 0x11: "console.device",
    0x12: "gameport.device", 0x13: "keyboard.device", 0x14: "trackdisk.device", 0x15: "timer.device",
    0x20: "cia.resource", 0x21: "disk.resource", 0x22: "misc.resource", 0x30: "bootstrap",
    0x31: "Workbench", 0x32: "DiskCopy", 0x33: "gadtools.library", 0x34: "utility.library",
    0x35: "unknown", 0x3F: "tfdbgd",
}
GENERAL = {
    0x01: "out of memory", 0x02: "MakeLibrary failed", 0x03: "OpenLibrary failed",
    0x04: "OpenDevice failed", 0x05: "OpenResource failed", 0x06: "I/O error",
    0x07: "no signal available", 0x08: "bad parameter", 0x09: "CloseLibrary failed",
    0x0A: "CloseDevice failed", 0x0B: "process creation failed",
}
SPECIFIC = {
    0x01000001: "exception vector checksum (AN_ExcptVect)",
    0x01000002: "ExecBase checksum (AN_BaseChkSum)",
    0x01000003: "library checksum failure (AN_LibChkSum)",
    0x01000005: "corrupt memory list detected in FreeMem (AN_MemCorrupt)",
    0x01000006: "no memory for interrupt servers (AN_IntrMem)",
    0x01000007: "InitStruct() of an APTR source (AN_InitAPtr)",
    0x01000008: "a semaphore is in an illegal state (AN_SemCorrupt)",
    0x01000009: "freeing memory that is already free (AN_FreeTwice)",
    0x0100000A: "illegal 68k exception taken (AN_BogusExcpt)",
    0x0100000B: "attempt to reuse an active IORequest (AN_IOUsedTwice)",
    0x0100000C: "sanity check on memory list failed (AN_MemoryInsane)",
    0x0100000D: "I/O attempted on a closed IORequest (AN_IOAfterClose)",
    0x0100000E: "stack appears to extend out of range (AN_StackProbe)",
    0x0100000F: "memory header not located: bad address to FreeMem (AN_BadFreeAddr)",
    0x01000010: "attempt to use the old message semaphore (AN_BadSemaphore)",
    0x07000002: "EndTask didn't (AN_EndTask)",
    0x07000003: "Qpkt failure (AN_QPktFail)",
    0x07000004: "unexpected packet received (AN_AsyncPkt)",
    0x07000005: "freevec failed (AN_FreeVec)",
    0x07000006: "disk block sequence error (AN_DiskBlkSeq)",
    0x07000007: "bitmap corrupt (AN_BitMap)",
    0x07000008: "key already free (AN_KeyFree)",
    0x07000009: "invalid checksum (AN_BadChkSum)",
    0x0700000A: "disk error (AN_DiskError)",
    0x0700000B: "key out of range (AN_KeyRange)",
    0x0700000C: "bad overlay (AN_BadOverlay)",
    0x0700000D: "invalid init packet for cli/shell (AN_BadInitFunc)",
    0x0700000E: "a filehandle was closed more than once (AN_FileReclosed)",
}
CPU_TRAPS = {
    2: "bus error / access fault", 3: "address error", 4: "illegal instruction", 5: "divide by zero",
    6: "CHK instruction", 7: "TRAPV instruction", 8: "privilege violation", 9: "trace",
    10: "line A emulator (opcode 1010)", 11: "line F emulator (opcode 1111 / FPU)", 14: "format error",
    15: "uninitialized interrupt", 24: "spurious interrupt",
}
for _n in range(16):
    CPU_TRAPS[32 + _n] = f"TRAP #{_n}"


def decode_alert(code):
    code &= 0xFFFFFFFF
    dead = bool(code & 0x80000000)
    sub = (code >> 24) & 0x7F
    general = (code >> 16) & 0xFF
    specific = code & 0xFFFF
    out = {"code": f"{code:08X}", "dead_end": dead, "subsystem": SUBSYSTEMS.get(sub, f"subsystem {sub:#04x}")}
    base = code & 0x7FFFFFFF
    if sub == 0 and general == 0:
        out["meaning"] = CPU_TRAPS.get(specific, f"CPU exception vector {specific}")
    elif base in SPECIFIC:
        out["meaning"] = SPECIFIC[base]
    elif general in GENERAL:
        out["meaning"] = f"{out['subsystem']}: {GENERAL[general]}" + (f" (object {specific:#06x})" if specific else "")
    else:
        out["meaning"] = f"{out['subsystem']}: error {general:#04x}/{specific:#06x}"
    out["text"] = ("DEAD END " if dead else "recoverable ") + out["meaning"]
    return out


def _hexes(text):
    return [int(v, 16) for v in text.split()]


def parse(text):
    """{"hits": [...], "alerts": [...], "mungwall": [...]} from serial output."""
    hits, alerts, mung = [], [], []
    current = None
    for raw in text.splitlines():
        line = raw.strip("\r")
        m = HIT.search(line)
        if m:
            current = {"access": f"{m.group(1)} {m.group(2)}", "address": int(m.group(3), 16),
                       "pc": int(m.group(5), 16), "raw": [line]}
            if m.group(4):
                current["data"] = int(m.group(4), 16)
            hits.append(current)
            continue
        if current is not None and line.strip():
            current["raw"].append(line)
            m = TCB.search(line)
            if m:
                current.update(usp=int(m.group(1), 16), sr=int(m.group(2), 16), task=int(m.group(3), 16))
                continue
            m = REGS.match(line.strip())
            if m:
                key = {"Data": "data_regs", "Addr": "addr_regs", "Stck": "stack"}[m.group(1)]
                current.setdefault(key, []).extend(_hexes(m.group(2)))
                continue
            m = SEGHIT.search(line)
            if m:
                current.setdefault("segments", []).append({
                    "address": int(m.group(1), 16), "program": m.group(2),
                    "hunk": int(m.group(3), 16), "offset": int(m.group(4), 16)})
                continue
            m = NAME.search(line)
            if m:
                current["task_name"] = m.group(1)
                if m.group(2):
                    current["cli"] = m.group(2)
                if m.group(3):
                    current["name_hunk"] = int(m.group(3), 16)
                    current["name_offset"] = int(m.group(4), 16)
                continue
        elif not line.strip():
            current = None
        m = ALERT.search(line)
        if m:
            alert = decode_alert(int(m.group(1), 16))
            if m.group(2):
                alert["task"] = int(m.group(2), 16)
            alert["raw"] = line
            alerts.append(alert)
            current = None
            continue
        if MUNGWALL.search(line):
            mung.append(line)
    for h in hits:
        h["raw"] = "\n".join(h["raw"])
    return {"hits": hits, "alerts": alerts, "mungwall": mung}
