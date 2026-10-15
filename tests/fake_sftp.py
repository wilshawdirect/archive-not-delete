"""An in-memory stand-in for ``paramiko.SFTPClient`` (the subset the SFTP destination uses). No network."""

from __future__ import annotations

import posixpath
from types import SimpleNamespace


class FakeSftpFile:
    def __init__(self, client: FakeSftp, path: str, mode: str) -> None:
        self._client = client
        self._path = path
        self._mode = mode
        self._pos = 0
        self.closed = False

    def write(self, data: bytes) -> int:
        client = self._client
        if client.fail_after is not None and client.written + len(data) > client.fail_after:
            raise OSError(28, "no space left on device")
        client.files[self._path].extend(data)
        client.written += len(data)
        return len(data)

    def read(self, size: int = -1) -> bytes:
        data = bytes(self._client.files[self._path])
        end = len(data) if size is None or size < 0 else self._pos + size
        chunk = data[self._pos : end]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeSftpFile:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class FakeSftp:
    def __init__(self) -> None:
        self.files: dict[str, bytearray] = {}
        self.dirs: set[str] = {"/"}
        self.fail_after: int | None = None  # simulate a full disk after this many bytes written
        self.written = 0
        self.closed = False
        self.removed: list[str] = []

    def _parent_ok(self, path: str) -> bool:
        return posixpath.dirname(path) in self.dirs

    def open(self, filename: str, mode: str = "r", bufsize: int = -1) -> FakeSftpFile:
        if "w" in mode:
            if not self._parent_ok(filename):
                raise FileNotFoundError(2, "no such directory", filename)
            self.files[filename] = bytearray()
        elif filename not in self.files:
            raise FileNotFoundError(2, "no such file", filename)
        return FakeSftpFile(self, filename, mode)

    def stat(self, path: str) -> SimpleNamespace:
        if path in self.files:
            return SimpleNamespace(st_size=len(self.files[path]))
        if path in self.dirs:
            return SimpleNamespace(st_size=0)
        raise FileNotFoundError(2, "no such file", path)

    def mkdir(self, path: str, mode: int = 0o777) -> None:
        if not self._parent_ok(path):
            raise FileNotFoundError(2, "no such directory", path)
        if path in self.dirs:
            raise FileExistsError(17, "exists", path)
        self.dirs.add(path)

    def rename(self, oldpath: str, newpath: str) -> None:
        if newpath in self.files:
            raise OSError(4, "failure: destination exists")
        self.files[newpath] = self.files.pop(oldpath)

    def remove(self, path: str) -> None:
        if path not in self.files:
            raise FileNotFoundError(2, "no such file", path)
        del self.files[path]
        self.removed.append(path)

    def close(self) -> None:
        self.closed = True
