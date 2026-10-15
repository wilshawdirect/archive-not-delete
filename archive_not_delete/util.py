"""Small, dependency-free helpers: sizes, durations, globs, hashing, and Windows path handling."""

from __future__ import annotations

import hashlib
import ntpath
import os
import posixpath
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from .errors import PolicyError, SourceError

CHUNK = 1 << 20
EXTENDED_THRESHOLD = 240
EXTENDED_PREFIX = "\\\\?\\"
ZERO_HASH = "0" * 64

_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_NUMBER_UNIT = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$")

_REPARSE_LINKS = (
    getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C),
    getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003),
)


@dataclass(frozen=True)
class Digest:
    """sha256 (hex) and byte length of a stored or streamed object."""

    sha256: str
    size: int


def parse_size(value: object, what: str = "size") -> int:
    """Parse ``1048576``, ``"500 MB"`` or ``"2GiB"``. KB/MB/GB/TB are decimal, KiB/MiB/GiB/TiB are binary."""
    if isinstance(value, bool):
        raise PolicyError(f"{what}: expected a size, got {value!r}")
    if isinstance(value, int | float):
        if value < 0:
            raise PolicyError(f"{what}: must not be negative")
        return int(value)
    if isinstance(value, str):
        match = _NUMBER_UNIT.match(value)
        if match and match.group(2).lower() in _SIZE_UNITS:
            return round(float(match.group(1)) * _SIZE_UNITS[match.group(2).lower()])
    raise PolicyError(f"{what}: cannot read {value!r} as a size (examples: 1048576, '500MB', '2GiB')")


def parse_duration(value: object, what: str = "duration") -> float:
    """Parse ``90`` (seconds), ``"15m"``, ``"12h"``, ``"14d"`` or ``"2w"`` into seconds."""
    if isinstance(value, bool):
        raise PolicyError(f"{what}: expected a duration, got {value!r}")
    if isinstance(value, int | float):
        if value < 0:
            raise PolicyError(f"{what}: must not be negative")
        return float(value)
    if isinstance(value, str):
        match = _NUMBER_UNIT.match(value)
        if match and match.group(2).lower() in _DURATION_UNITS:
            return float(match.group(1)) * _DURATION_UNITS[match.group(2).lower()]
    raise PolicyError(f"{what}: cannot read {value!r} as a duration (examples: '30m', '14d', '2w')")


def fmt_bytes(count: float) -> str:
    """Human-readable decimal size, e.g. ``1.5 MB``."""
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1000:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def fmt_age(seconds: float) -> str:
    """Compact age such as ``45d`` or ``3h``."""
    if seconds >= 86400:
        return f"{seconds / 86400:.0f}d"
    if seconds >= 3600:
        return f"{seconds / 3600:.0f}h"
    if seconds >= 60:
        return f"{seconds / 60:.0f}m"
    return f"{seconds:.0f}s"


def iso_utc(timestamp: float) -> str:
    """UTC timestamp with second precision, e.g. ``2026-10-15T12:00:00Z``."""
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------------- Windows paths


def extended(path: str | os.PathLike[str], *, windows: bool | None = None) -> str:
    """Return ``path`` as a string safe for very long Windows paths.

    On Windows an absolute path of 240+ characters is returned with the extended-length prefix (``\\\\?\\``, or
    ``\\\\?\\UNC\\`` for network shares) so the system calls accept it. Short paths, and every path on other
    platforms, are returned unchanged.
    """
    text = os.fspath(path)
    if windows is None:
        windows = os.name == "nt"
    if not windows or text.startswith("\\\\?\\"):
        return text
    absolute = ntpath.abspath(text)
    if len(absolute) < EXTENDED_THRESHOLD:
        return text
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def normalize_policy_path(text: str, *, windows: bool | None = None) -> str:
    """Treat a Windows extended-length path (the ones starting with a backslash pair and a question mark) as the
    absolute path it is: strip the prefix so ordinary comparisons and root checks apply."""
    if windows is None:
        windows = os.name == "nt"
    if windows and text[:4] in (EXTENDED_PREFIX, "//?/"):
        return strip_extended(text.replace("/", "\\"))
    return text


def is_filesystem_root(text: str, *, windows: bool | None = None) -> bool:
    """True for the root of a filesystem: a lone slash, a Windows drive root, the current drive's root, or a UNC
    share root. A sweep root must be a folder below one of these."""
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return posixpath.normpath(text) in ("/", "//")
    cleaned = ntpath.normpath(strip_extended(text.replace("/", "\\")))
    drive, rest = ntpath.splitdrive(cleaned)
    return rest in ("", "\\") and (drive != "" or cleaned == "\\")


def fs(path: str | os.PathLike[str]) -> str:
    """Path string to hand to ``open``, ``os.lstat``, ``os.scandir`` and friends."""
    return extended(path)


def strip_extended(text: str) -> str:
    """Undo :func:`extended` so paths can be compared."""
    if text.startswith("\\\\?\\UNC\\"):
        return "\\\\" + text[8:]
    if text.startswith("\\\\?\\"):
        return text[4:]
    return text


def real_norm(path: str | os.PathLike[str]) -> str:
    """Canonical, case-normalised, symlink-resolved form of ``path`` for containment checks."""
    return os.path.normcase(strip_extended(os.path.realpath(fs(path))))


def is_inside(child: str, parent: str) -> bool:
    """True when the already-normalised ``child`` equals or lies under the already-normalised ``parent``."""
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def is_link_like(st: os.stat_result) -> bool:
    """True for symbolic links and, on Windows, junctions / mount points."""
    if stat.S_ISLNK(st.st_mode):
        return True
    return getattr(st, "st_reparse_tag", 0) in _REPARSE_LINKS


def validate_rel(rel: str) -> str:
    """Check a posix-style relative path (root-relative path or archive key). Returns it or raises."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\x00" in rel:
        raise PolicyError(f"unsafe relative path {rel!r}")
    for part in rel.split("/"):
        if part in ("", ".", ".."):
            raise PolicyError(f"unsafe relative path {rel!r}")
        if os.name == "nt" and ("\\" in part or ":" in part):
            raise PolicyError(f"unsafe relative path {rel!r}")
    return rel


# --------------------------------------------------------------------------------------------------- hashing


def sha256_file(path: str | os.PathLike[str]) -> Digest:
    """Hash a local file. Read errors become ``SourceError``."""
    digest = hashlib.sha256()
    size = 0
    try:
        with open(fs(path), "rb") as handle:
            while chunk := handle.read(CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc}") from exc
    return Digest(digest.hexdigest(), size)


# ------------------------------------------------------------------------------------------------- globbing


def _segment_regex(segment: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(segment):
        char = segment[i]
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = segment.find("]", i + 2)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = segment[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def compile_glob(pattern: str, *, case_sensitive: bool = True) -> re.Pattern[str]:
    """Compile a glob over ``/``-separated relative paths: ``*`` and ``?`` stay inside a segment, ``**`` spans them."""
    parts = pattern.split("/")
    regex = ""
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            regex += ".*" if last else "(?:[^/]+/)*"
        else:
            regex += _segment_regex(part) + ("" if last else "/")
    try:
        return re.compile(regex, 0 if case_sensitive else re.IGNORECASE)
    except re.error as exc:
        raise PolicyError(f"bad glob pattern {pattern!r}: {exc}") from exc


class Matcher:
    """A set of glob patterns, evaluated against posix-style paths relative to a root.

    A pattern without ``/`` matches the file name at any depth (``*.log``). A pattern with ``/`` (or a leading ``/``)
    is anchored at the root (``cache/**``, ``**/old/*.bin``). An exclude pattern that matches a directory excludes
    everything beneath it.
    """

    def __init__(self, patterns: Iterable[str], *, case_sensitive: bool | None = None) -> None:
        if case_sensitive is None:
            case_sensitive = os.name != "nt"
        self.patterns = tuple(patterns)
        self._compiled: list[tuple[str, re.Pattern[str], bool]] = []
        for pattern in self.patterns:
            if not isinstance(pattern, str) or not pattern.lstrip("/"):
                raise PolicyError(f"empty or non-text glob pattern {pattern!r}")
            basename_only = "/" not in pattern
            self._compiled.append(
                (pattern, compile_glob(pattern.lstrip("/"), case_sensitive=case_sensitive), basename_only)
            )

    def __bool__(self) -> bool:
        return bool(self._compiled)

    def which(self, rel: str) -> str | None:
        """The first pattern that matches the file ``rel``, or None."""
        name = rel.rsplit("/", 1)[-1]
        for pattern, regex, basename_only in self._compiled:
            if regex.fullmatch(name if basename_only else rel):
                return pattern
        return None

    def matches(self, rel: str) -> bool:
        return self.which(rel) is not None

    def matches_dir(self, rel_dir: str) -> bool:
        """True when a pattern matches the directory itself (so everything under it is excluded)."""
        name = rel_dir.rsplit("/", 1)[-1]
        for _pattern, regex, basename_only in self._compiled:
            if basename_only:
                if regex.fullmatch(name):
                    return True
            elif regex.fullmatch(rel_dir) or regex.fullmatch(rel_dir + "/"):
                return True
        return False

    def excludes(self, rel: str) -> bool:
        """True when the file ``rel`` or any directory above it is matched."""
        if self.matches(rel):
            return True
        parts = rel.split("/")[:-1]
        return any(self.matches_dir("/".join(parts[: i + 1])) for i in range(len(parts)))


def key_of(root: str, rel: str) -> str:
    """Archive key for a file: ``<root name>/<relative path>``."""
    return f"{root}/{rel}"
