"""Call stacks for a stopped job.

gcc builds usually omit the frame pointer, so besides following a5/a6
frame chains this scans the stack for return addresses: longs that point
into the program's code right after a JSR/BSR. Results from the scan are
marked "scan" -- they can include stale return addresses.
"""

import struct


def _word(code, addr):
    data = code(addr, 2)
    if not data or len(data) < 2:
        return None
    return struct.unpack(">H", data)[0]


def is_return_address(addr, code):
    """True when the instruction before addr is a call (JSR/BSR forms)."""
    if addr & 1:
        return False
    w = _word(code, addr - 2)
    if w is not None and ((0x4E90 <= w <= 0x4E97) or ((w & 0xFF00) == 0x6100 and w & 0xFF not in (0, 0xFF))):
        return True
    w = _word(code, addr - 4)
    if w is not None and (w == 0x6100 or 0x4EA8 <= w <= 0x4EB7 or w in (0x4EB8, 0x4EBA, 0x4EBB)):
        return True
    w = _word(code, addr - 6)
    if w is not None and w in (0x4EB9, 0x61FF):
        return True
    return False


def in_code(addr, segments):
    return any(s["start"] <= addr < s["start"] + s["size"] for s in segments)


def walk(regs, pc, stack, sp, segments, code, depth=16):
    """frames: [{"address", "kind": "pc"|"fp"|"scan", "stack_offset"}]"""
    frames = [{"address": pc, "kind": "pc"}]

    def long_at(addr):
        off = addr - sp
        if 0 <= off <= len(stack) - 4:
            return struct.unpack_from(">I", stack, off)[0]
        return None

    best = []
    for reg in ("a5", "a6"):
        chain, fp, seen = [], regs.get(reg, 0), set()
        while len(chain) < depth and fp not in seen:
            seen.add(fp)
            ret, prev = long_at(fp + 4), long_at(fp)
            if ret is None or prev is None or not in_code(ret, segments) or not is_return_address(ret, code):
                break
            chain.append({"address": ret, "kind": "fp", "stack_offset": fp + 4 - sp})
            if prev <= fp:
                break
            fp = prev
        if len(chain) > len(best):
            best = chain
    if len(best) >= 2:
        return frames + best[:depth]

    for off in range(0, len(stack) - 3, 2):
        value = struct.unpack_from(">I", stack, off)[0]
        if in_code(value, segments) and is_return_address(value, code):
            frames.append({"address": value, "kind": "scan", "stack_offset": off})
            if len(frames) > depth:
                break
    return frames
