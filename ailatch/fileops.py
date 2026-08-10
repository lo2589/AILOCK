import os
import random
import stat
from pathlib import Path


def read_bytes(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def atomic_write(path: Path, data: bytes) -> None:
    rand_id = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    tmp = path.with_name(f".{path.name}.tmp-{rand_id}")
    existing_mode = None
    try:
        existing_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        pass

    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        if existing_mode is not None:
            os.chmod(tmp, existing_mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def safe_backup(path: Path, data: bytes) -> Path:
    backup = path.with_suffix(path.suffix + ".bak")
    if backup.exists():
        import time
        backup = path.with_suffix(path.suffix + f".bak-{int(time.time())}")

    with open(backup, "wb") as f:
        f.write(data)

    return backup
