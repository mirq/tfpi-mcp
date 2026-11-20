"""Amiga raw key codes (US keymap) for send_keys."""

import re

QUAL = {"lshift": 0x0001, "rshift": 0x0002, "caps": 0x0004, "ctrl": 0x0008, "lalt": 0x0010,
        "ralt": 0x0020, "lamiga": 0x0040, "ramiga": 0x0080}
QUAL_ALIASES = {"shift": "lshift", "alt": "lalt", "amiga": "ramiga", "control": "ctrl",
                "lcommand": "lamiga", "rcommand": "ramiga", "cmd": "ramiga"}
QUAL_KEYS = {"lshift": 0x60, "rshift": 0x61, "caps": 0x62, "ctrl": 0x63, "lalt": 0x64,
             "ralt": 0x65, "lamiga": 0x66, "ramiga": 0x67}

NAMED = {
    "space": 0x40, "backspace": 0x41, "tab": 0x42, "enter": 0x43, "return": 0x44, "esc": 0x45,
    "escape": 0x45, "del": 0x46, "delete": 0x46, "help": 0x5F, "up": 0x4C, "down": 0x4D,
    "right": 0x4E, "left": 0x4F, "kp(": 0x5A, "kp)": 0x5B, "kp/": 0x5C, "kp*": 0x5D, "kp+": 0x5E,
    "kp-": 0x4A, "kp.": 0x3C,
}
for i in range(10):
    NAMED[f"f{i + 1}"] = 0x50 + i
for i, code in enumerate((0x0F, 0x1D, 0x1E, 0x1F, 0x2D, 0x2E, 0x2F, 0x3D, 0x3E, 0x3F)):
    NAMED[f"kp{i}"] = code

# unshifted, shifted
_ROWS = [
    ("`1234567890-=\\", "~!@#$%^&*()_+|", 0x00),
    ("qwertyuiop[]", "QWERTYUIOP{}", 0x10),
    ("asdfghjkl;'", "ASDFGHJKL:\"", 0x20),
    ("zxcvbnm,./", "ZXCVBNM<>?", 0x31),
]
CHARS = {}
for plain, shifted, base in _ROWS:
    for i, (a, b) in enumerate(zip(plain, shifted)):
        CHARS[a] = (base + i, False)
        CHARS[b] = (base + i, True)
CHARS[" "] = (0x40, False)
CHARS["\n"] = (0x44, False)
CHARS["\t"] = (0x42, False)


class KeyError_(ValueError):
    pass


def _press(code, qual):
    return [(1, code, qual, 0, 0), (1, code | 0x80, qual, 0, 0)]


def text_events(text):
    events = []
    for ch in text:
        if ch not in CHARS:
            raise KeyError_(f"no key for {ch!r} on the US keymap")
        code, shift = CHARS[ch]
        if shift:
            events.append((1, 0x60, QUAL["lshift"], 0, 0))
            events += _press(code, QUAL["lshift"])
            events.append((1, 0x60 | 0x80, 0, 0, 0))
        else:
            events += _press(code, 0)
    return events


def combo_events(spec):
    """'ctrl+c', 'ramiga+m', 'f1', 'return', 'shift+tab', 'a'."""
    parts = [p.strip().lower() for p in re.split(r"\+(?=.)", spec.strip()) if p.strip()]
    if not parts:
        raise KeyError_("empty key")
    *mods, key = parts
    qual = 0
    down, up = [], []
    for mod in mods:
        mod = QUAL_ALIASES.get(mod, mod)
        if mod not in QUAL:
            raise KeyError_(f"unknown modifier {mod!r} (use {', '.join(sorted(QUAL))})")
        qual |= QUAL[mod]
        down.append((1, QUAL_KEYS[mod], qual, 0, 0))
        up.insert(0, (1, QUAL_KEYS[mod] | 0x80, 0, 0, 0))
    if key in NAMED:
        code = NAMED[key]
    elif len(key) == 1 and key in CHARS:
        code, shift = CHARS[key]
        if shift:
            qual |= QUAL["lshift"]
    elif re.fullmatch(r"0x[0-9a-f]{1,2}|raw\d+", key):
        code = int(key[3:]) if key.startswith("raw") else int(key, 16)
    else:
        raise KeyError_(f"unknown key {key!r}")
    return down + _press(code, qual) + up


BUTTONS = {"left": 0x68, "right": 0x69, "middle": 0x6A}


def mouse_events(dx=0, dy=0, button=None, action="click"):
    events = []
    if dx or dy:
        # input.device takes relative moves; big jumps in steps keep acceleration predictable
        steps = max(1, (max(abs(dx), abs(dy)) + 63) // 64)
        sx = sy = 0
        for i in range(1, steps + 1):
            tx, ty = dx * i // steps, dy * i // steps
            events.append((2, 0xFF, 0, tx - sx, ty - sy))
            sx, sy = tx, ty
    if button:
        if button not in BUTTONS:
            raise KeyError_(f"button must be one of {', '.join(BUTTONS)}")
        code = BUTTONS[button]
        if action in ("click", "down", "double"):
            events.append((2, code, 0, 0, 0))
        if action in ("click", "up", "double"):
            events.append((2, code | 0x80, 0, 0, 0))
        if action == "double":
            events += [(2, code, 0, 0, 0), (2, code | 0x80, 0, 0, 0)]
    return events
