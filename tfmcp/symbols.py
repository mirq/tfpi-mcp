"""Symbols and line numbers for a loaded program.

A table comes from the executable itself (hunk symbols / LINE debug hunks)
or from an ELF with DWARF (elf2hunk builds). Addresses on the Amiga are
found through the segment list the agent reports when the job starts.
"""

import bisect
import os
import re

from . import elf, hunk


class SymbolError(ValueError):
    pass


class Symbols:
    def __init__(self, parsed, source=""):
        self.source = source
        self.hunks = parsed["hunks"]
        self.syms = sorted(parsed["symbols"], key=lambda s: (s[0], s[1]))
        self.lines = sorted(parsed["lines"], key=lambda s: (s[0], s[1]))
        self._sym_keys = [(s[0], s[1]) for s in self.syms]
        self._line_keys = [(s[0], s[1]) for s in self.lines]

    @classmethod
    def from_bytes(cls, data, source=""):
        if hunk.is_hunk(data):
            return cls(hunk.parse(data), source)
        if elf.is_elf(data):
            return cls(elf.parse(data), source)
        raise SymbolError(f"{source or 'file'} is neither an Amiga executable nor an ELF file")

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as handle:
            return cls.from_bytes(handle.read(), str(path))

    def summary(self):
        return {"source": os.path.basename(self.source), "hunks": len(self.hunks),
                "symbols": len(self.syms), "lines": len(self.lines)}

    def check_segments(self, segments):
        """A warning when the program's segments don't look like these hunks."""
        if len(segments) != len(self.hunks):
            return (f"the symbol file has {len(self.hunks)} hunks but the program has "
                    f"{len(segments)} segments: wrong symbol file?")
        for i, (h, s) in enumerate(zip(self.hunks, segments)):
            if s["size"] < h["size"]:
                return f"hunk {i} is {h['size']} bytes but segment {i} only {s['size']}: wrong symbol file?"
        return None

    # ---- address -> name -------------------------------------------------------------

    @staticmethod
    def where(addr, segments):
        """(hunk, offset) for an absolute address, or None."""
        for i, s in enumerate(segments):
            if s["start"] <= addr < s["start"] + s["size"]:
                return i, addr - s["start"]
        return None

    def lookup(self, addr, segments):
        where = self.where(addr, segments)
        if where is None:
            return None
        return self.lookup_hunk(*where)

    def lookup_hunk(self, h, off):
        out = {"hunk": h, "offset": off}
        i = bisect.bisect_right(self._sym_keys, (h, off)) - 1
        if i >= 0 and self.syms[i][0] == h:
            name = self.syms[i][2]
            delta = off - self.syms[i][1]
            out["symbol"] = name
            out["symbol_offset"] = delta
        i = bisect.bisect_right(self._line_keys, (h, off)) - 1
        if i >= 0 and self.lines[i][0] == h:
            out["file"] = self.lines[i][2]
            out["line"] = self.lines[i][3]
        return out

    # ---- name -> address -------------------------------------------------------------

    def find_symbol(self, name):
        for cand in (name, "_" + name, name.lstrip("_")):
            for h, off, sym in self.syms:
                if sym == cand:
                    return h, off
        return None

    def find_line(self, fname, line):
        base = os.path.basename(fname).lower()
        best = None
        for h, off, f, ln in self.lines:
            if os.path.basename(f).lower() != base or ln < line:
                continue
            key = (ln, h, off)
            if best is None or key < best:
                best = key
        if best is None:
            return None
        return best[1], best[2], best[0]

    def search(self, pattern, limit=100):
        rx = re.compile(pattern, re.I) if pattern else None
        out = []
        for h, off, name in self.syms:
            if rx is None or rx.search(name):
                out.append({"name": name, "hunk": h, "offset": off})
                if len(out) >= limit:
                    break
        return out


def describe(info):
    """'main+0x1c (main.c:42)' style text for lookup() results."""
    if not info:
        return ""
    text = ""
    if "symbol" in info:
        text = info["symbol"] + (f"+{info['symbol_offset']:#x}" if info["symbol_offset"] else "")
    else:
        text = f"hunk {info['hunk']}+{info['offset']:#x}"
    if "file" in info:
        text += f" ({os.path.basename(info['file'])}:{info['line']})"
    return text


LOCATION_HELP = ("an address (0x1234, $1234), a symbol (main, _main), file:line (main.c:42) "
                 "or hunk:offset (h0:0x40)")


def parse_int(text):
    text = str(text).strip()
    if text.startswith("$"):
        return int(text[1:], 16)
    return int(text, 0)


def resolve(location, symbols, segments):
    """Absolute address for a location string; (address, note)."""
    loc = str(location).strip()
    m = re.fullmatch(r"[hH](\d+):(\S+)", loc)
    if m:
        h, off = int(m.group(1)), parse_int(m.group(2))
        if h >= len(segments):
            raise SymbolError(f"the program has no hunk {h}")
        return segments[h]["start"] + off, f"hunk {h}+{off:#x}"
    try:
        return parse_int(loc), "address"
    except ValueError:
        pass
    m = re.fullmatch(r"(.+):(\d+)", loc)
    if m:
        if symbols is None:
            raise SymbolError("no symbols loaded for this job (pass symbols= when launching)")
        found = symbols.find_line(m.group(1), int(m.group(2)))
        if not found:
            raise SymbolError(f"no code for {loc} in the line table")
        h, off, ln = found
        return segments[h]["start"] + off, f"{os.path.basename(m.group(1))}:{ln}"
    if symbols is None:
        raise SymbolError("no symbols loaded for this job (pass symbols= when launching)")
    found = symbols.find_symbol(loc)
    if not found:
        raise SymbolError(f"no symbol {loc!r}")
    h, off = found
    if h >= len(segments):
        raise SymbolError(f"symbol {loc!r} is in hunk {h}, which the program doesn't have")
    return segments[h]["start"] + off, loc
