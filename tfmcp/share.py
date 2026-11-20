"""The a314fs share: the Pi directory the Amiga mounts as PI0: (volume PiDisk:).

Paths given by the agent are relative to the share root, or Amiga paths on it
("PI0:dir/file", "PiDisk:dir/file"). a314fs matches names without regard to
case, so lookups here do too. Nothing outside the share is reachable.
"""

import base64
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from . import config

META = ":a314"          # a314fs keeps protection bits/comments in "<name>:a314"


class ShareError(ValueError):
    pass


@dataclass
class Share:
    device: str
    volume: str
    root: Path


def find():
    try:
        devices = json.loads(config.A314FS_CONF.read_text())["devices"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(devices, dict) or not devices:
        return None
    device = "PI0" if "PI0" in devices else next(iter(devices))
    entry = devices[device]
    try:
        root = Path(entry["path"])
    except (KeyError, TypeError):
        return None
    if not root.is_dir():
        return None
    return Share(device=device, volume=entry.get("volume", "PiDisk"), root=root)


def need():
    share = find()
    if share is None:
        raise ShareError(f"the a314fs share isn't set up ({config.A314FS_CONF} missing or its directory "
                         "doesn't exist)")
    return share


def _strip_amiga_prefix(share, path):
    path = path.strip()
    if ":" in path:
        prefix, rest = path.split(":", 1)
        if prefix.lower() not in (share.device.lower(), share.volume.lower(), ""):
            raise ShareError(f"{path!r} is not on {share.device}: (the share); use amiga_read_file "
                             "for other Amiga volumes")
        path = rest
    return path


def resolve(path, must_exist=False):
    """Local Path for a share path, matching existing names case-insensitively."""
    share = need()
    rel = _strip_amiga_prefix(share, path or "").replace("\\", "/").strip("/")
    current = share.root
    for part in [p for p in rel.split("/") if p not in ("", ".")]:
        if part == "..":
            raise ShareError("'..' is not allowed")
        if part.endswith(META):
            raise ShareError(f"{part!r} is a314fs metadata")
        candidate = current / part
        if not candidate.exists() and current.is_dir():
            for entry in os.listdir(current):
                if entry.lower() == part.lower():
                    candidate = current / entry
                    break
        current = candidate
    resolved = current.resolve() if current.exists() else current
    root = share.root.resolve()
    if resolved != root and root not in resolved.parents:
        raise ShareError("path leaves the share")
    if must_exist and not current.exists():
        raise ShareError(f"{path!r} not found on the share")
    return current


def amiga_path(local):
    """PI0:relative for a local path inside the share."""
    share = need()
    rel = Path(local).resolve().relative_to(share.root.resolve())
    text = str(rel).replace(os.sep, "/")
    return f"{share.device}:" + ("" if text == "." else text)


def to_local(amiga):
    """Local path for an Amiga path on the share, or None if it isn't on it."""
    share = find()
    if share is None or ":" not in amiga:
        return None
    try:
        return resolve(amiga)
    except ShareError:
        return None


def work_dir(*parts):
    """<share>/.tfmcp/... (created, owned by whoever runs us: the Pi user)."""
    path = need().root / config.SHARE_DIR_NAME
    for part in parts:
        path = path / part
    path.mkdir(parents=True, exist_ok=True)
    return path


def listing(path=""):
    directory = resolve(path, must_exist=True)
    if not directory.is_dir():
        raise ShareError(f"{path!r} is not a directory")
    out = []
    for entry in sorted(os.listdir(directory), key=str.lower):
        if entry.endswith(META):
            continue
        st = (directory / entry).stat()
        out.append({"name": entry, "dir": stat.S_ISDIR(st.st_mode), "size": st.st_size,
                    "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))})
    return out


def read(path, offset=0, length=65536, encoding="auto"):
    target = resolve(path, must_exist=True)
    if target.is_dir():
        raise ShareError(f"{path!r} is a directory")
    size = target.stat().st_size
    with open(target, "rb") as handle:
        handle.seek(offset)
        data = handle.read(max(0, length))
    result = {"path": amiga_path(target), "size": size, "offset": offset, "length": len(data),
              "more": offset + len(data) < size}
    if encoding == "auto":
        encoding = "text" if _looks_text(data) else "base64"
    if encoding == "text":
        result["text"] = data.decode("latin-1")
    else:
        result["base64"] = base64.b64encode(data).decode()
    return result


def _looks_text(data):
    if not data:
        return True
    if b"\0" in data:
        return False
    bad = sum(1 for b in data if b < 9 or 13 < b < 32)
    return bad <= len(data) // 100


def write(path, data, offset=0, executable=False):
    """offset 0 replaces the file; otherwise it must be the current size
    (chunked uploads). Data is synced to the card before returning."""
    target = resolve(path)
    if target.exists() and target.is_dir():
        raise ShareError(f"{path!r} is a directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    if offset:
        size = target.stat().st_size if target.exists() else 0
        if offset != size:
            raise ShareError(f"offset {offset} must equal the current size {size} (chunks in order)")
        with open(target, "ab") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    else:
        temporary = target.with_name(".tfmcp-part-" + target.name)
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    if executable:
        target.chmod(target.stat().st_mode | 0o111)
    return {"path": amiga_path(target), "size": target.stat().st_size}


def delete(path):
    target = resolve(path, must_exist=True)
    if target == need().root:
        raise ShareError("won't delete the share itself")
    name = amiga_path(target)
    if target.is_dir():
        target.rmdir()      # empty directories only
    else:
        target.unlink()
        meta = target.with_name(target.name + META)
        if meta.exists():
            meta.unlink()
    return {"deleted": name}


def mkdir(path):
    target = resolve(path)
    target.mkdir(parents=True, exist_ok=True)
    return {"path": amiga_path(target)}
