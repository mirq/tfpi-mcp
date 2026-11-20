"""AmigaDOS load files (hunk format): hunk sizes, HUNK_SYMBOL symbols and
LINE debug hunks (SAS/C, vbcc/vlink -g) for symbolication."""

import struct

HUNK_UNIT, HUNK_NAME, HUNK_CODE, HUNK_DATA, HUNK_BSS = 0x3E7, 0x3E8, 0x3E9, 0x3EA, 0x3EB
HUNK_RELOC32, HUNK_RELOC16, HUNK_RELOC8, HUNK_EXT, HUNK_SYMBOL = 0x3EC, 0x3ED, 0x3EE, 0x3EF, 0x3F0
HUNK_DEBUG, HUNK_END, HUNK_HEADER, HUNK_OVERLAY, HUNK_BREAK = 0x3F1, 0x3F2, 0x3F3, 0x3F5, 0x3F6
HUNK_DREL32, HUNK_DREL16, HUNK_DREL8, HUNK_LIB, HUNK_INDEX = 0x3F7, 0x3F8, 0x3F9, 0x3FA, 0x3FB
HUNK_RELOC32SHORT, HUNK_RELRELOC32, HUNK_ABSRELOC16 = 0x3FC, 0x3FD, 0x3FE

TYPE_NAMES = {HUNK_CODE: "code", HUNK_DATA: "data", HUNK_BSS: "bss"}


class HunkError(ValueError):
    pass


class _R:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def long(self):
        if self.p + 4 > len(self.d):
            raise HunkError("truncated hunk file")
        v = struct.unpack_from(">I", self.d, self.p)[0]
        self.p += 4
        return v

    def word(self):
        if self.p + 2 > len(self.d):
            raise HunkError("truncated hunk file")
        v = struct.unpack_from(">H", self.d, self.p)[0]
        self.p += 2
        return v

    def bytes(self, n):
        if self.p + n > len(self.d):
            raise HunkError("truncated hunk file")
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def name(self, nlongs):
        return self.bytes(nlongs * 4).rstrip(b"\0").decode("latin-1")

    def done(self):
        return self.p >= len(self.d)


def is_hunk(data):
    return len(data) >= 4 and struct.unpack_from(">I", data)[0] == HUNK_HEADER


def parse(data):
    """{"hunks": [{"type", "size", "mem", "data_offset"}], "symbols": [(hunk, offset, name)],
        "lines": [(hunk, offset, file, line)]}"""
    r = _R(data)
    if r.long() != HUNK_HEADER:
        raise HunkError("not an Amiga executable (no HUNK_HEADER)")
    while True:
        n = r.long()
        if not n:
            break
        r.bytes(n * 4)                  # resident library names
    r.long()                            # table size
    first, last = r.long(), r.long()
    hunks = []
    for _ in range(last - first + 1):
        v = r.long()
        mem = v >> 30
        if mem == 3:
            r.long()
        hunks.append({"type": None, "size": (v & 0x3FFFFFFF) * 4,
                      "mem": {0: "any", 1: "chip", 2: "fast", 3: "other"}[mem], "data_offset": None})
    symbols, lines = [], []
    index = 0
    while not r.done() and index < len(hunks):
        t = r.long() & 0x3FFFFFFF
        if t in (HUNK_CODE, HUNK_DATA):
            n = r.long() * 4
            hunks[index]["type"] = TYPE_NAMES[t]
            hunks[index]["data_offset"] = r.p
            hunks[index]["data_size"] = n
            r.bytes(n)
        elif t == HUNK_BSS:
            r.long()
            hunks[index]["type"] = "bss"
        elif t in (HUNK_RELOC32, HUNK_RELOC16, HUNK_RELOC8, HUNK_RELRELOC32, HUNK_DREL16, HUNK_DREL8):
            while True:
                n = r.long()
                if not n:
                    break
                r.long()
                r.bytes(n * 4)
        elif t in (HUNK_RELOC32SHORT, HUNK_DREL32, HUNK_ABSRELOC16):
            # word format in load files (V37+ treat DREL32 in executables like this)
            while True:
                n = r.word()
                if not n:
                    break
                r.word()
                r.bytes(n * 2)
            if r.p % 4:
                r.bytes(4 - r.p % 4)
        elif t == HUNK_SYMBOL:
            while True:
                n = r.long()
                if not n:
                    break
                name = r.name(n)
                symbols.append((index, r.long(), name))
        elif t == HUNK_EXT:
            while True:
                v = r.long()
                if not v:
                    break
                kind, n = v >> 24, v & 0xFFFFFF
                name = r.name(n)
                if kind < 128:          # definitions: value
                    value = r.long()
                    if kind in (1, 2, 3):
                        symbols.append((index, value, name))
                elif kind == 130:       # common: size + references
                    r.long()
                    r.bytes(r.long() * 4)
                else:                   # references
                    r.bytes(r.long() * 4)
        elif t == HUNK_DEBUG:
            n = r.long() * 4
            lines.extend(_debug_lines(index, r.bytes(n)))
        elif t == HUNK_NAME:
            r.bytes(r.long() * 4)
        elif t == HUNK_END:
            index += 1
        elif t in (HUNK_OVERLAY, HUNK_BREAK):
            break                       # overlays: what we have so far
        else:
            raise HunkError(f"unknown hunk type {t:#x} at offset {r.p - 4}")
    return {"hunks": hunks, "symbols": symbols, "lines": lines}


def _debug_lines(index, data):
    """SAS/C / vlink LINE format: base, "LINE", name length (longs), name, (line, offset) pairs."""
    if len(data) < 12 or data[4:8] != b"LINE":
        return []
    base = struct.unpack_from(">I", data, 0)[0]
    nlen = struct.unpack_from(">I", data, 8)[0] * 4
    if 12 + nlen > len(data):
        return []
    name = data[12:12 + nlen].rstrip(b"\0").decode("latin-1")
    out = []
    for p in range(12 + nlen, len(data) - 7, 8):
        line, offset = struct.unpack_from(">II", data, p)
        out.append((index, base + offset, name, line & 0xFFFFFF))
    return out
