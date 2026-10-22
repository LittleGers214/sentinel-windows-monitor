"""Read-only SHA-256 scan. Incomplete scans must never imply deletions."""

import hashlib
import os
from pathlib import Path


def scan_folder(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or root.is_junction():
        raise OSError("Папка недоступна или является ссылкой")
    result = {}

    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = [
            name
            for name in dirs
            if not (Path(directory) / name).is_symlink()
            and not (Path(directory) / name).is_junction()
        ]
        for name in files:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            before = path.stat()
            if before.st_size > 128 * 1024 * 1024:
                raise OSError(f"Файл больше лимита 128 МБ: {path}")
            if len(result) >= 10000:
                raise OSError("Превышен лимит 10 000 файлов на папку")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ino,
            ):
                raise OSError(f"Файл изменился во время чтения: {path}")
            result[str(path)] = digest
    return result
