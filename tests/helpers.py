"""Shared test helpers: a fixed clock, an environment builder, and misbehaving destinations."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from archive_not_delete import Destination, Engine, LocalDestination, Policy, SourceStream, policy_from_dict
from archive_not_delete.util import Digest

NOW = 1_800_000_000.0  # the fixed "current time" every test runs at (epoch seconds)
DAY = 86400


def make_file(path: Path, data: bytes | int = b"payload", age_days: float = 30.0) -> Path:
    """Create a file with deterministic content and a modification time ``age_days`` before NOW."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, int):
        data = (b"0123456789abcdef" * (data // 16 + 1))[:data]
    path.write_bytes(data)
    mtime_ns = int((NOW - age_days * DAY) * 1e9)
    os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


def tree(path: Path) -> dict[str, bytes]:
    """Every file under ``path`` as {posix relative path: bytes}."""
    return {p.relative_to(path).as_posix(): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


def tree_usage(root: Path, capacity: int):
    """A fake ``disk_usage``: a disk of ``capacity`` bytes whose only content is the files under ``root``."""

    def usage(_path: str) -> SimpleNamespace:
        used = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
        return SimpleNamespace(total=capacity, used=used, free=capacity - used)

    return usage


@dataclass
class Env:
    tmp: Path
    policy: Policy
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def root(self) -> Path:
        return self.policy.roots[0].path

    @property
    def archive(self) -> Path:
        return Path(self.policy.destination.options["path"])

    @property
    def manifest(self) -> Path:
        return self.policy.manifest

    def engine(self, **kwargs: Any) -> Engine:
        kwargs.setdefault("now", lambda: NOW)
        return Engine(self.policy, **kwargs)

    def file(self, rel: str, data: bytes | int = b"payload", age_days: float = 30.0) -> Path:
        return make_file(self.root.joinpath(*rel.split("/")), data, age_days)

    def records(self) -> list[dict[str, Any]]:
        if not self.manifest.exists():
            return []
        return [json.loads(line) for line in self.manifest.read_text(encoding="utf-8").splitlines()]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.records() if r["event"] == name]


def make_policy(tmp: Path, root: dict[str, Any] | None = None, **top: Any) -> Policy:
    table: dict[str, Any] = {"name": "data", "path": str(tmp / "data"), "min_age": "1d"}
    table.update(root or {})
    data: dict[str, Any] = {
        "manifest": str(tmp / "state" / "manifest.jsonl"),
        "destination": {"type": "local", "path": str(tmp / "archive")},
        "root": [table],
    }
    data.update(top)
    return policy_from_dict(data, tmp)


def make_env(tmp: Path, root: dict[str, Any] | None = None, **top: Any) -> Env:
    (tmp / "data").mkdir(parents=True, exist_ok=True)
    return Env(tmp, make_policy(tmp, root, **top))


def make_dir_link(link: Path, target: Path) -> None:
    """Create a directory symlink (or, on Windows without the privilege, a junction). Skips if neither works."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False)
        if done.returncode == 0:
            return
    pytest.skip("cannot create a directory link on this machine")


class FlipDestination(LocalDestination):
    """Stores the copy, then flips one byte of it: a disk that corrupts data."""

    def put(self, stream: SourceStream, key: str):
        digest = super().put(stream, key)
        target = self._path(key)
        data = bytearray(target.read_bytes())
        data[len(data) // 2] ^= 0xFF
        target.write_bytes(bytes(data))
        return digest


class TouchDestination(LocalDestination):
    """Stores the copy, then appends to the source file: the source changed while it was being copied."""

    def __init__(self, base: Path, victim: Path) -> None:
        super().__init__(base)
        self.victim = victim

    def put(self, stream: SourceStream, key: str):
        digest = super().put(stream, key)
        with open(self.victim, "ab") as handle:
            handle.write(b"appended while archiving")
        return digest


class AliasDestination(LocalDestination):
    """Claims to be an archive elsewhere, but its objects land inside the source tree.

    This is what a network-share alias, a bind mount or a loopback mount of the source folder looks like to the tool:
    a different spelling of the same storage, which a path comparison cannot see.
    """

    def __init__(self, harmless_base: Path, into: Path) -> None:
        super().__init__(harmless_base)
        self.into = into

    def _path(self, key: str) -> Path:
        return self.into.joinpath(*key.split("/"))

    def uri(self, key: str) -> str:
        return self._path(key).as_uri()


class LoopbackDestination(Destination):
    """A destination with no local path (like SFTP) whose server happens to store into a given directory."""

    def __init__(self, base: Path) -> None:
        self.base = base

    def uri(self, key: str) -> str:
        return "loopback://host/" + key

    def exists(self, key: str) -> bool:
        return (self.base / key).exists()

    def put(self, stream: SourceStream, key: str) -> Digest:
        target = self.base / key
        target.parent.mkdir(parents=True, exist_ok=True)
        data = b""
        while chunk := stream.read(1 << 20):
            data += chunk
        target.write_bytes(data)
        import hashlib

        return Digest(hashlib.sha256(data).hexdigest(), len(data))

    def open_read(self, key: str):
        return open(self.base / key, "rb")

    def remove(self, key: str) -> None:
        (self.base / key).unlink()
