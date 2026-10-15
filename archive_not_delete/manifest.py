"""Append-only JSONL manifest: what was archived, where, and when it was verified and trimmed.

Every line is one event. Lines are chained (``seq`` plus the sha256 of the previous line), so an edited, removed or
reordered line is detectable by :meth:`Manifest.read`. The file is only ever opened for append.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ManifestError, from_os_error
from .util import ZERO_HASH, fs

EVENTS = ("archived", "trimmed", "purged", "restored")
REQUIRED = {
    "archived": (
        "id",
        "root",
        "rel",
        "source",
        "size",
        "sha256",
        "mtime_ns",
        "dest_uri",
        "dest_key",
        "verified_at",
    ),
    "trimmed": ("id", "trimmed_at"),
    "restored": ("id", "restored_at"),
    "purged": ("root", "rel", "source", "size", "kind", "purged_at"),
}


def entry_id(root: str, rel: str, sha256: str, dest_key: str) -> str:
    """Stable identifier of one archived object version."""
    return hashlib.sha256(f"{root}\0{rel}\0{sha256}\0{dest_key}".encode()).hexdigest()[:16]


@dataclass
class Entry:
    """The folded state of one archived object: archived, possibly trimmed, possibly restored."""

    id: str
    root: str
    rel: str
    source: str
    size: int
    sha256: str
    mtime_ns: int
    dest_uri: str
    dest_key: str
    verified_at: str
    trimmed_at: str | None = None
    restored_at: str | None = None

    @property
    def trimmed(self) -> bool:
        return self.trimmed_at is not None


@dataclass
class ManifestState:
    """Everything the manifest says, folded in order."""

    entries: dict[str, Entry] = field(default_factory=dict)
    purged: list[dict[str, Any]] = field(default_factory=list)
    lines: int = 0
    problems: list[str] = field(default_factory=list)

    def apply(self, rec: dict[str, Any]) -> None:
        event = rec.get("event")
        if event == "archived":
            self.entries[rec["id"]] = Entry(
                id=rec["id"],
                root=rec["root"],
                rel=rec["rel"],
                source=rec["source"],
                size=int(rec["size"]),
                sha256=rec["sha256"],
                mtime_ns=int(rec["mtime_ns"]),
                dest_uri=rec["dest_uri"],
                dest_key=rec["dest_key"],
                verified_at=rec["verified_at"],
            )
        elif event == "trimmed":
            entry = self.entries.get(rec["id"])
            if entry is not None:
                entry.trimmed_at = rec["trimmed_at"]
        elif event == "restored":
            entry = self.entries.get(rec["id"])
            if entry is not None:
                entry.restored_at = rec["restored_at"]
                entry.trimmed_at = None
        elif event == "purged":
            self.purged.append(rec)

    def for_root(self, root: str) -> list[Entry]:
        return [e for e in self.entries.values() if e.root == root]

    def find(self, source_or_key: str) -> list[Entry]:
        """Entries whose recorded source path, ``root/rel`` key, or id equals the argument (oldest first)."""
        norm = os.path.normcase(source_or_key)
        return [
            e
            for e in self.entries.values()
            if e.id == source_or_key or f"{e.root}/{e.rel}" == source_or_key or os.path.normcase(e.source) == norm
        ]


def _line_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Manifest:
    """Reader/appender for one manifest file. Appends need the run lock; reads do not."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._seq = 0
        self._prev = ZERO_HASH
        self.state = ManifestState()

    def read(self, *, strict: bool = True) -> ManifestState:
        """Load and fold the manifest. ``strict`` raises ``ManifestError`` on the first problem; otherwise problems
        are collected in ``state.problems`` and every parseable line is still folded."""
        state = ManifestState()
        seq = 0
        prev = ZERO_HASH
        try:
            data = Path(fs(self.path)).read_bytes()
        except FileNotFoundError:
            data = b""
        except OSError as exc:
            raise from_os_error(exc, f"cannot read manifest {self.path}") from exc

        def problem(message: str) -> None:
            if strict:
                raise ManifestError(f"manifest {self.path}: {message}")
            state.problems.append(message)

        chunks = data.split(b"\n")
        if chunks and chunks[-1] == b"":
            chunks.pop()
        elif chunks:
            problem(f"line {len(chunks)} is not newline-terminated (torn write?)")
        for number, raw in enumerate(chunks, start=1):
            state.lines = number
            try:
                rec = json.loads(raw)
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
            except ValueError:
                problem(f"line {number} is not valid JSON")
                prev = _line_hash(raw)
                continue
            if rec.get("seq") != seq + 1:
                problem(f"line {number}: expected seq {seq + 1}, found {rec.get('seq')!r} (line removed or reordered?)")
            if rec.get("prev") != prev:
                problem(f"line {number}: hash chain broken (an earlier line was edited or removed)")
            seq = rec.get("seq") if isinstance(rec.get("seq"), int) else seq + 1
            prev = _line_hash(raw)
            if rec.get("event") not in EVENTS:
                problem(f"line {number}: unknown event {rec.get('event')!r}")
                continue
            try:
                state.apply(rec)
            except (KeyError, TypeError, ValueError):
                problem(f"line {number}: {rec.get('event')} record is missing fields")
        self._seq, self._prev, self.state = seq, prev, state
        return state

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one event (flushed and fsynced). Call :meth:`read` first so the chain position is known."""
        if event not in EVENTS:
            raise ManifestError(f"unknown event {event!r}")
        missing = [name for name in REQUIRED[event] if name not in fields]
        if missing:
            raise ManifestError(f"{event} record is missing {', '.join(missing)}")
        rec: dict[str, Any] = {"seq": self._seq + 1, "prev": self._prev, "event": event, **fields}
        raw = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            os.makedirs(fs(self.path.parent), exist_ok=True)
            with open(fs(self.path), "ab") as handle:
                handle.write(raw + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise from_os_error(exc, f"cannot append to manifest {self.path}") from exc
        self._seq += 1
        self._prev = _line_hash(raw)
        self.state.apply(rec)
        self.state.lines += 1
        return rec
