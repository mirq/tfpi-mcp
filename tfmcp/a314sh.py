"""Client for a314's a314sh service (A314shd on the Amiga runs the command
with Execute() and sends back output and return code).

Request: u32 length + command. Reply: i32 rc, u32 length, output (big-endian).
A314shd runs one command at a time and can't be interrupted: a command that
never ends blocks it until the Amiga is reset. Prefer tfdbgd jobs for
anything that may hang.
"""

import socket
import struct

from . import config

FAILURE_RC = -1


class ShellError(Exception):
    pass


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(65536, n - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def run(command, timeout=30.0, host=None, port=None):
    """(rc, output text). Raises ShellError when the service is unreachable
    or the command does not finish in time."""
    try:
        sock = socket.create_connection((host or config.A314SH_HOST, port or config.A314SH_PORT), timeout=5)
    except OSError:
        # a314d starts the Pi side of a314sh only once A314shd on the Amiga
        # connects, so a closed port nearly always means A314shd isn't running.
        raise ShellError("A314shd isn't running on the Amiga (the a314sh service is not reachable "
                         "on the Pi). Set it up once on the Amiga with: "
                         + config.INSTALL_COMMAND) from None
    try:
        sock.settimeout(timeout)
        data = command.encode("latin-1", "replace")
        sock.sendall(struct.pack(">I", len(data)) + data)
        try:
            header = _recv_exact(sock, 8)
            if header is None:
                raise ShellError("the a314sh service closed the connection")
            rc, length = struct.unpack(">iI", header)
            body = _recv_exact(sock, length)
        except socket.timeout:
            raise ShellError(f"no answer within {timeout:g} s; A314shd stays busy until the command "
                             "ends (use amiga_run with the agent to be able to break it)") from None
        if body is None:
            raise ShellError("the a314sh service closed the connection")
        text = body.decode("latin-1", "replace")
        if rc == FAILURE_RC and text.startswith("a314sh:"):
            raise ShellError(text.strip() + " -- set it up once on the Amiga with: " + config.INSTALL_COMMAND)
        return rc, text
    finally:
        sock.close()
