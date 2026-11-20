"""Paths, ports and settings. Everything can be redirected with TFMCP_*
environment variables (the tests run against fakes on a desktop)."""

import copy
import json
import os
import secrets
import tempfile
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def _env(name, default):
    return os.environ.get("TFMCP_" + name, default)


ETC = Path(_env("ETC", "/etc/tfpi-mcp"))
CONFIG_FILE = ETC / "config.json"
RUN_DIR = Path(_env("RUN_DIR", "/run/tfpi-mcp"))
BRIDGE_SOCKET = Path(_env("BRIDGE_SOCKET", str(RUN_DIR / "bridge.sock")))

A314D_HOST = _env("A314D_HOST", "127.0.0.1")
A314D_PORT = int(_env("A314D_PORT", "7110"))
A314SH_HOST = _env("A314SH_HOST", "127.0.0.1")
A314SH_PORT = int(_env("A314SH_PORT", "23891"))
A314FS_CONF = Path(_env("A314FS_CONF", "/etc/opt/a314/a314fs.conf"))
SERIAL_DIRS = tuple(Path(p) for p in _env("SERIAL_DIRS", "/run/a314d:/tmp/a314d").split(":") if p)
TFPI_LOCK = Path(_env("TFPI_LOCK", "/var/lib/tfpi/flash.lock"))
SYSTEMCTL = _env("SYSTEMCTL", "systemctl")
A314_SERVICE = _env("A314_SERVICE", "a314d")

AGENT_BINARY = Path(_env("AGENT_BINARY", str(PACKAGE_DIR / "amiga" / "tfdbgd")))
SHARE_DIR_NAME = ".tfmcp"           # on PI0: -- the agent, job output, screenshots

DEFAULTS = {
    # Things that change the Amiga's state beyond running programs. Edit
    # /etc/tfpi-mcp/config.json (or `tfpi-mcp config set KEY VALUE`).
    "allow_mem_write": False,       # mem_write, debug_set_register
    "allow_input": True,            # send_keys / send_mouse
    "allow_reboot": False,          # amiga_reboot
    "allow_kill": True,             # killing debugged jobs
    "max_output": 65536,            # bytes of program output returned per call
    "http": {"enabled": False, "bind": "0.0.0.0", "port": 8765, "token": ""},
}


def write_json(path, data):
    """fsync + atomic rename: the Pi loses power with the Amiga."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    if os.geteuid() == 0:
        # `sudo tfpi-mcp config set`: keep the file readable by the service user
        st = os.stat(path.parent)
        os.chown(temporary, st.st_uid, st.st_gid)
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _merge(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load():
    conf = copy.deepcopy(DEFAULTS)
    try:
        _merge(conf, json.loads(CONFIG_FILE.read_text()))
    except (OSError, ValueError):
        pass
    return conf


def ensure_token(conf):
    """The HTTP transport's bearer token; created on first use."""
    if not conf["http"].get("token"):
        conf["http"]["token"] = secrets.token_urlsafe(32)
        stored = {}
        try:
            stored = json.loads(CONFIG_FILE.read_text())
        except (OSError, ValueError):
            pass
        stored.setdefault("http", {})["token"] = conf["http"]["token"]
        write_json(CONFIG_FILE, stored)
    return conf["http"]["token"]


def set_value(key, value):
    """`tfpi-mcp config set http.port 9000`: dotted keys, JSON values."""
    try:
        parsed = json.loads(value)
    except ValueError:
        parsed = value
    try:
        stored = json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError):
        stored = {}
    node = stored
    parts = key.split(".")
    known = DEFAULTS
    for part in parts[:-1]:
        if not isinstance(known.get(part), dict):
            raise KeyError(key)
        known = known[part]
        node = node.setdefault(part, {})
    if parts[-1] not in known:
        raise KeyError(key)
    node[parts[-1]] = parsed
    write_json(CONFIG_FILE, stored)
    return parsed
