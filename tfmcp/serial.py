"""The Amiga's serial port as a314d keeps it (TF4060 firmware with the fake
serial port): everything sent with RawPutChar/kprintf (debug output,
Enforcer/MuForce hits) is appended to serial.log; writing to the pty "tty"
reaches RawMayGetChar on the Amiga.

Cursors are byte offsets into serial.log. a314d moves the log to serial.log.1
at 1 MB and starts a new one; a cursor past the end of the current log means
that happened, and reading continues with the rest of the old log.
"""

import os
import re
import time

from . import config

LOG_NAME = "serial.log"
OLD_NAME = "serial.log.1"
TTY_NAME = "tty"


class SerialError(Exception):
    pass


def directory():
    for d in config.SERIAL_DIRS:
        if (d / LOG_NAME).exists() or (d / TTY_NAME).exists():
            return d
    return None


def _read(path, offset, limit):
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            return handle.read(limit)
    except FileNotFoundError:
        return b""


def size():
    d = directory()
    if d is None:
        return 0
    try:
        return (d / LOG_NAME).stat().st_size
    except FileNotFoundError:
        return 0


def read(cursor=None, limit=65536, tail=None):
    """(text, next cursor). cursor None: the last `tail` bytes (default 4 KB)."""
    d = directory()
    if d is None:
        raise SerialError("no serial log: a314d is not running, or the FPGA firmware has no fake serial port")
    path = d / LOG_NAME
    try:
        current = path.stat().st_size
    except FileNotFoundError:
        current = 0
    data = b""
    if cursor is None:
        cursor = max(0, current - (tail if tail is not None else 4096))
    elif cursor > current:
        data = _read(d / OLD_NAME, cursor, limit)
        cursor = 0
    new = _read(path, cursor, max(0, limit - len(data)))
    return (data + new).decode("latin-1"), cursor + len(new)


def wait_for(pattern, cursor, timeout, limit=65536):
    """Read from cursor until the regex matches or timeout.
    (matched, text, next cursor)."""
    regex = re.compile(pattern) if pattern else None
    deadline = time.time() + timeout
    text = ""
    while True:
        chunk, cursor = read(cursor, limit - len(text))
        text += chunk
        if regex and regex.search(text):
            return True, text, cursor
        if time.time() >= deadline or len(text) >= limit:
            return (regex is None), text, cursor
        time.sleep(0.1)


def write(text):
    d = directory()
    if d is None or not (d / TTY_NAME).exists():
        raise SerialError("no serial pty: a314d is not running, or this a314d has no serial port")
    data = text.encode("latin-1", "replace")
    fd = os.open(d / TTY_NAME, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return len(data)
