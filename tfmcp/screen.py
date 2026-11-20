"""Screenshots: planar (OCS/ECS/AGA incl. HAM6/HAM8/EHB) or RTG RGB rows
into PNG, with nothing but the standard library."""

import struct
import zlib

HAM_KEY = 0x800
EHB_KEY = 0x80

# byte -> 8 pixels, one byte each, holding that bit (MSB = leftmost pixel)
_EXPAND = [bytes((b >> (7 - i)) & 1 for i in range(8)) for b in range(256)]


def planar_rows(data, width, height, depth, rowbytes):
    """Rows of colour indices from interleaved-per-row planar data:
    for each row, for each plane, rowbytes bytes."""
    rows = []
    npix = rowbytes * 8
    for y in range(height):
        acc = 0
        base = y * depth * rowbytes
        for p in range(depth):
            chunk = data[base + p * rowbytes: base + (p + 1) * rowbytes]
            expanded = b"".join(_EXPAND[b] for b in chunk)
            acc |= int.from_bytes(expanded, "big") << p
        rows.append(acc.to_bytes(npix, "big")[:width])
    return rows


def indices_to_rgb(rows, palette, mode_id, depth):
    pal = list(palette) + [(0, 0, 0)] * (256 - len(palette))
    ham = bool(mode_id & HAM_KEY) and depth in (5, 6, 7, 8)
    ehb = bool(mode_id & EHB_KEY) and depth == 6 and not ham
    out = []
    for row in rows:
        line = bytearray(len(row) * 3)
        if ham:
            ham8 = depth >= 7
            shift = 6 if ham8 else 4
            vmask = (1 << shift) - 1
            r, g, b = pal[0]
            for x, idx in enumerate(row):
                ctl, val = idx >> shift, idx & vmask
                if ham8:
                    v = (val << 2) | (val >> 4)
                else:
                    v = (val << 4) | val
                if ctl == 0:
                    r, g, b = pal[val]
                elif ctl == 1:
                    b = v
                elif ctl == 2:
                    r = v
                else:
                    g = v
                line[x * 3:x * 3 + 3] = bytes((r, g, b))
        else:
            for x, idx in enumerate(row):
                if ehb and idx >= 32:
                    c = pal[idx - 32]
                    c = (c[0] >> 1, c[1] >> 1, c[2] >> 1)
                else:
                    c = pal[idx]
                line[x * 3:x * 3 + 3] = bytes(c)
        out.append(bytes(line))
    return out


def scale_rgb(rows, width, sx, sy):
    """Nearest-neighbour scale by factors sx, sy (floats)."""
    if sx == 1 and sy == 1:
        return rows, width
    new_w = max(1, int(width * sx))
    new_h = max(1, int(len(rows) * sy))
    xs = [min(width - 1, int(x / sx)) for x in range(new_w)]
    out = []
    for y in range(new_h):
        src = rows[min(len(rows) - 1, int(y / sy))]
        out.append(b"".join(src[x * 3:x * 3 + 3] for x in xs))
    return out, new_w


def png(rows, width):
    raw = b"".join(b"\0" + row for row in rows)

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, len(rows), 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


def mode_aspect(mode_id, width, height):
    """(sx, sy) to roughly square pixels: hires doubles rows, lace doubles columns."""
    hires = width >= 600
    lace = height >= 400
    if hires and not lace:
        return 1, 2
    if lace and not hires:
        return 2, 1
    return 1, 1
