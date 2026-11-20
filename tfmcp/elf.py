"""m68k ELF files (Bartman's toolchain / elf2hunk builds): symbols and DWARF
.debug_line, mapped onto hunks.

elf2hunk turns each allocated, non-empty section into one hunk, in section
header order; an address in the ELF maps to (that hunk, address - section
address). The match is checked against the segment sizes the Amiga reports
when they are given.
"""

import struct


class ElfError(ValueError):
    pass


SHF_ALLOC = 2
SHT_SYMTAB, SHT_NOBITS = 2, 8
STT_OBJECT, STT_FUNC = 1, 2


def is_elf(data):
    return data[:4] == b"\x7fELF"


def _sections(data):
    if data[4] != 1 or data[5] != 2:
        raise ElfError("only 32-bit big-endian ELF (m68k) is supported")
    shoff, = struct.unpack_from(">I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from(">HHH", data, 0x2E)
    secs = []
    for i in range(shnum):
        name, stype, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            ">IIIIIIIIII", data, shoff + i * shentsize)
        secs.append({"name_off": name, "type": stype, "flags": flags, "addr": addr, "offset": off,
                     "size": size, "link": link, "entsize": entsize, "index": i})
    if shstrndx < len(secs):
        strtab = secs[shstrndx]
        for s in secs:
            s["name"] = _cstr(data, strtab["offset"] + s["name_off"])
    return secs


def _cstr(data, off):
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else len(data)].decode("latin-1")


def parse(data):
    """Same shape as hunk.parse: hunks, symbols, lines (hunk-relative)."""
    if not is_elf(data):
        raise ElfError("not an ELF file")
    secs = _sections(data)
    alloc = [s for s in secs if s["flags"] & SHF_ALLOC and s["size"] > 0]
    hunk_of = {s["index"]: h for h, s in enumerate(alloc)}
    hunks = [{"type": "bss" if s["type"] == SHT_NOBITS else
              ("code" if s["name"].startswith(".text") else "data"),
              "size": s["size"], "mem": "any", "section": s["name"], "addr": s["addr"]} for s in alloc]

    def locate(addr):
        for h, s in enumerate(alloc):
            if s["addr"] <= addr < s["addr"] + s["size"]:
                return h, addr - s["addr"]
        return None

    symbols = []
    for s in secs:
        if s["type"] != SHT_SYMTAB or not s["entsize"]:
            continue
        strtab = secs[s["link"]]
        for i in range(s["size"] // s["entsize"]):
            name, value, size, info, other, shndx = struct.unpack_from(
                ">IIIBBH", data, s["offset"] + i * s["entsize"])
            if (info & 0xF) not in (STT_FUNC, STT_OBJECT, 0) or not name or shndx not in hunk_of:
                continue
            sym = _cstr(data, strtab["offset"] + name)
            if sym.startswith("$") or sym.startswith(".L"):
                continue
            symbols.append((hunk_of[shndx], value - secs[shndx]["addr"], sym))

    lines = []
    by_name = {s.get("name"): s for s in secs}
    if ".debug_line" in by_name:
        line_str = by_name.get(".debug_line_str")
        dstr = by_name.get(".debug_str")
        for addr, fname, line in _debug_line(data, by_name[".debug_line"], line_str, dstr):
            where = locate(addr)
            if where:
                lines.append((where[0], where[1], fname, line))
    return {"hunks": hunks, "symbols": symbols, "lines": lines}


# ---- DWARF .debug_line (versions 2-5) -------------------------------------------

class _D:
    def __init__(self, data, pos, end):
        self.d, self.p, self.end = data, pos, end

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self):
        v = struct.unpack_from(">H", self.d, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        v = struct.unpack_from(">I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        v = struct.unpack_from(">Q", self.d, self.p)[0]
        self.p += 8
        return v

    def uleb(self):
        result = shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return result

    def sleb(self):
        result = shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if b & 0x40:
                    result -= 1 << shift
                return result

    def cstr(self):
        end = self.d.index(b"\0", self.p)
        s = self.d[self.p:end].decode("latin-1")
        self.p = end + 1
        return s


def _form(r, form, data, line_str, dstr):
    if form == 0x08:                    # string
        return r.cstr()
    if form in (0x1F, 0x0E):            # line_strp / strp
        off = r.u32()
        sec = line_str if form == 0x1F else dstr
        return _cstr(data, sec["offset"] + off) if sec else ""
    if form == 0x0F:                    # udata
        return r.uleb()
    if form == 0x0B:
        return r.u8()
    if form == 0x05:
        return r.u16()
    if form == 0x06:
        return r.u32()
    if form == 0x07:
        return r.u64()
    if form == 0x1E:                    # data16 (MD5)
        r.p += 16
        return None
    if form == 0x09:                    # block
        r.p += r.uleb()
        return None
    raise ElfError(f"unsupported DWARF form {form:#x} in .debug_line")


def _debug_line(data, sec, line_str, dstr):
    """[(address, file, line)]. Sequences of functions removed by --gc-sections
    keep address 0; when several sequences start at 0 they are all dropped."""
    sequences = _sequences(data, sec, line_str, dstr)
    at_zero = sum(1 for seq in sequences if seq and seq[0][0] == 0)
    out = []
    for seq in sequences:
        if seq and not (seq[0][0] == 0 and at_zero > 1):
            out.extend(seq)
    return out


def _sequences(data, sec, line_str, dstr):
    pos, end = sec["offset"], sec["offset"] + sec["size"]
    out = []
    while pos + 4 <= end:
        unit_len = struct.unpack_from(">I", data, pos)[0]
        if unit_len == 0xFFFFFFFF:
            raise ElfError("64-bit DWARF is not supported")
        unit_end = pos + 4 + unit_len
        r = _D(data, pos + 4, unit_end)
        version = r.u16()
        if version >= 5:
            r.u8()                      # address size
            r.u8()                      # segment selector size
        header_len = r.u32()
        prog = r.p + header_len
        min_inst = r.u8()
        if version >= 4:
            r.u8()                      # max ops per instruction
        default_is_stmt = r.u8()
        line_base = struct.unpack("b", bytes([r.u8()]))[0]
        line_range = r.u8()
        opcode_base = r.u8()
        std_lens = [r.u8() for _ in range(opcode_base - 1)]
        dirs, files = [], []
        if version >= 5:
            fmt = [(r.uleb(), r.uleb()) for _ in range(r.u8())]
            for _ in range(r.uleb()):
                entry = {ct: _form(r, form, data, line_str, dstr) for ct, form in fmt}
                dirs.append(entry.get(1) or "")
            fmt = [(r.uleb(), r.uleb()) for _ in range(r.u8())]
            for _ in range(r.uleb()):
                entry = {ct: _form(r, form, data, line_str, dstr) for ct, form in fmt}
                files.append(entry.get(1) or "?")
        else:
            dirs.append("")
            while True:
                d = r.cstr()
                if not d:
                    break
                dirs.append(d)
            files.append("?")
            while True:
                f = r.cstr()
                if not f:
                    break
                r.uleb()
                r.uleb()
                r.uleb()
                files.append(f)
        r.p = prog

        def reset():
            return {"addr": 0, "file": 1, "line": 1}
        st = reset()
        seq = []

        def emit():
            idx = st["file"]
            name = files[idx] if 0 <= idx < len(files) else "?"
            seq.append((st["addr"], name, st["line"]))

        while r.p < unit_end:
            op = r.u8()
            if op >= opcode_base:
                adj = op - opcode_base
                st["addr"] += (adj // line_range) * min_inst
                st["line"] += line_base + adj % line_range
                emit()
            elif op == 0:
                n = r.uleb()
                sub_end = r.p + n
                sub = r.u8() if n else 0
                if sub == 1:            # end_sequence
                    st = reset()
                    out.append(seq)
                    seq = []
                elif sub == 2:          # set_address
                    st["addr"] = r.u32() if n - 1 == 4 else r.u64()
                r.p = sub_end
            elif op == 1:
                emit()
            elif op == 2:
                st["addr"] += r.uleb() * min_inst
            elif op == 3:
                st["line"] += r.sleb()
            elif op == 4:
                st["file"] = r.uleb()
            elif op == 5:
                r.uleb()
            elif op in (6, 7, 10, 11):
                pass
            elif op == 8:
                st["addr"] += ((255 - opcode_base) // line_range) * min_inst
            elif op == 9:
                st["addr"] += r.u16()
            elif op == 12:
                r.uleb()
            else:
                for _ in range(std_lens[op - 1]):
                    r.uleb()
        if seq:
            out.append(seq)
        pos = unit_end
        _ = default_is_stmt
    return out
