"""Walk a root without ever following a link out of it."""

from __future__ import annotations

import os
import stat
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .util import Matcher, fs, is_inside, is_link_like, real_norm


@dataclass(frozen=True)
class FileInfo:
    """One regular file found under a root."""

    path: Path
    rel: str  # posix-style, relative to the root
    size: int
    mtime_ns: int


@dataclass
class ScanStats:
    """What the walk skipped and why."""

    counts: Counter[str] = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)


def walk_files(
    root: Path,
    exclude: Matcher,
    *,
    skip: frozenset[str] = frozenset(),
    stats: ScanStats | None = None,
) -> Iterator[FileInfo]:
    """Yield regular files under ``root`` in a deterministic order.

    Symbolic links and Windows junctions (to files or directories) are skipped, never followed. A directory whose real
    location is outside the root is skipped. ``skip`` holds absolute, case-normalised paths to ignore (the manifest and
    lock files). Excluded directories are pruned without being entered.
    """
    stats = stats if stats is not None else ScanStats()
    root_real = real_norm(root)
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        if not is_inside(real_norm(directory), root_real):
            stats.counts["escaped_root"] += 1
            continue
        try:
            with os.scandir(fs(directory)) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            stats.errors.append(f"cannot list {directory}: {exc}")
            continue
        subdirs: list[tuple[Path, str]] = []
        for entry in entries:
            rel = prefix + entry.name
            path = directory / entry.name
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                stats.errors.append(f"cannot stat {path}: {exc}")
                continue
            if entry.is_symlink() or is_link_like(st):
                stats.counts["link_skipped"] += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                if exclude.matches_dir(rel):
                    stats.counts["excluded_dir"] += 1
                else:
                    subdirs.append((path, rel + "/"))
            elif stat.S_ISREG(st.st_mode):
                if os.path.normcase(os.path.abspath(path)) in skip:
                    stats.counts["bookkeeping_file"] += 1
                elif exclude.matches(rel):
                    stats.counts["excluded"] += 1
                else:
                    yield FileInfo(path, rel, st.st_size, st.st_mtime_ns)
            else:
                stats.counts["special_file"] += 1
        stack.extend(reversed(subdirs))


def find_name_near_top(root: Path, name: str, *, max_depth: int = 3, max_dirs: int = 2000) -> bool:
    """True if an entry called ``name`` exists in ``root`` or a few levels below it (links are not entered).

    Used to see whether a file written through the archive destination has appeared inside the source tree.
    """
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    visited = 0
    while queue:
        directory, depth = queue.popleft()
        visited += 1
        if visited > max_dirs:
            break
        try:
            with os.scandir(fs(directory)) as it:
                for entry in it:
                    if entry.name == name:
                        return True
                    if depth < max_depth and not entry.is_symlink():
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if stat.S_ISDIR(st.st_mode) and not is_link_like(st):
                            queue.append((directory / entry.name, depth + 1))
        except OSError:
            continue
    return False
