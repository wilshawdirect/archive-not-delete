"""Run lock: an OS-level advisory lock, released automatically if the process dies (no stale lock files)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import TracebackType

from .errors import LockHeldError, from_os_error
from .util import fs

if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import msvcrt

    def _try_lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:  # pragma: no cover - exercised on POSIX CI
    import fcntl

    def _try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class RunLock:
    """Exclusive, non-blocking lock on ``path``. Use as a context manager; a second holder gets ``LockHeldError``."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> None:
        if self._fd is not None:
            raise LockHeldError(f"lock {self.path} is already held by this object")
        try:
            os.makedirs(fs(self.path.parent), exist_ok=True)
            fd = os.open(fs(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise from_os_error(exc, f"cannot create the run lock {self.path}") from exc
        try:
            _try_lock(fd)
        except OSError as exc:
            os.close(fd)
            raise LockHeldError(f"another run holds the lock {self.path}") from exc
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            _unlock(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


def run_lock(path: str | os.PathLike[str]) -> RunLock:
    """Convenience constructor: ``with run_lock(path): ...``."""
    return RunLock(path)
