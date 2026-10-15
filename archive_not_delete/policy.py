"""Policy file (TOML or JSON): what to sweep, when it is old enough, and where the archive lives."""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import PolicyError
from .util import Matcher, is_filesystem_root, normalize_policy_path, parse_duration, parse_size

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

TOP_KEYS = {"manifest", "lock", "byte_cap", "purge_byte_cap", "max_failures", "measure_csv", "destination", "root"}
ROOT_KEYS = {"name", "path", "include", "exclude", "min_age", "min_size", "max_size", "byte_cap", "order", "purge"}
PURGE_KEYS = {"name", "kind", "globs", "min_age", "exclude"}
LOCAL_KEYS = {"type", "path"}
SFTP_KEYS = {"type", "host", "port", "username", "path", "key_file", "password_env", "known_hosts", "connect_timeout"}
PURGE_KINDS = ("cache", "temp", "duplicate")
ORDERS = ("oldest", "largest")


@dataclass(frozen=True)
class PurgeClass:
    """A class of files the policy explicitly allows to be deleted without an archive copy."""

    name: str
    kind: str
    globs: tuple[str, ...]
    min_age_s: float = 0.0
    exclude: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for pattern in self.globs:
            check_purge_glob(pattern, f"purge class {self.name!r}")

    def matcher(self) -> Matcher:
        return Matcher(self.globs)

    def exclude_matcher(self) -> Matcher:
        return Matcher(self.exclude)


@dataclass(frozen=True)
class RootConfig:
    """One folder tree to sweep."""

    name: str
    path: Path
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    min_age_s: float = 0.0
    min_size: int = 0
    max_size: int | None = None
    byte_cap: int | None = None
    order: str = "oldest"
    purge: tuple[PurgeClass, ...] = ()

    def __post_init__(self) -> None:
        if is_filesystem_root(os.fspath(self.path)):
            raise PolicyError(
                f"root {self.name!r}: {self.path} is the root of a filesystem; "
                "point the root at a folder below it so a mistake cannot reach the whole disk"
            )

    def include_matcher(self) -> Matcher:
        return Matcher(self.include)

    def exclude_matcher(self) -> Matcher:
        return Matcher(self.exclude)


@dataclass(frozen=True)
class DestinationSpec:
    """Where verified copies go. ``type`` is ``local`` or ``sftp``; ``options`` are its settings."""

    type: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    roots: tuple[RootConfig, ...]
    destination: DestinationSpec
    manifest: Path
    lock: Path
    byte_cap: int | None = None
    purge_byte_cap: int | None = None
    max_failures: int = 3
    measure_csv: Path = Path("growth.csv")

    def root(self, name: str) -> RootConfig:
        for root in self.roots:
            if root.name == name:
                return root
        raise PolicyError(f"no root named {name!r} in the policy")


def _check_keys(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(unknown)} (allowed: {', '.join(sorted(allowed))})")


def _table(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where}: expected a table/object")
    return value


def _globs(value: object, where: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{where}: expected a list of glob strings")
    patterns = tuple(value)
    Matcher(patterns)  # validates every pattern now rather than mid-run
    return patterns


def _path(value: object, base_dir: Path, where: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where}: expected a path string")
    expanded = Path(os.path.expanduser(normalize_policy_path(value)))
    return Path(os.path.abspath(expanded if expanded.is_absolute() else base_dir / expanded))


def _int_cap(value: object, where: str) -> int | None:
    if value is None:
        return None
    return parse_size(value, where)


_LITERAL_EXTENSION = re.compile(r"\*(\.[A-Za-z0-9]+)+")
_WILDCARD_CHARS = "*?["


def check_purge_glob(pattern: str, where: str) -> None:
    """A purge glob deletes without a copy, so it must name something specific. It is accepted only if it has

    - a directory segment with no wildcard characters at all (``cache/**``, ``**/__pycache__/**``, ``tmp/*.log``), or
    - a final segment that is a literal extension: ``*`` followed by a dot-suffix of letters and digits only
      (``*.tmp``, ``*.pyc``, ``*.tar.gz``).

    A single literal character is not enough: ``*e*/**`` and ``cache*/**`` are refused.
    """
    segments = [s for s in pattern.strip("/").split("/") if s]
    if not segments:
        raise PolicyError(f"{where}: empty purge glob")
    *directories, last = segments
    literal_directory = any(d not in (".", "..") and not any(c in d for c in _WILDCARD_CHARS) for d in directories)
    if literal_directory or _LITERAL_EXTENSION.fullmatch(last):
        return
    raise PolicyError(
        f"{where}: purge glob {pattern!r} is too broad - it would delete files without a copy. "
        "Use a whole directory name with no wildcards (cache/**, **/__pycache__/**) "
        "or a literal extension (*.tmp, *.tar.gz)"
    )


def _purge(raw: object, where: str) -> PurgeClass:
    table = _table(raw, where)
    _check_keys(table, PURGE_KEYS, where)
    name = table.get("name")
    if not isinstance(name, str) or not _NAME.match(name):
        raise PolicyError(f"{where}: 'name' is required (letters, digits, . _ -)")
    kind = table.get("kind")
    if kind not in PURGE_KINDS:
        raise PolicyError(f"{where}: 'kind' must be one of {', '.join(PURGE_KINDS)}")
    if "globs" not in table:
        raise PolicyError(f"{where}: 'globs' is required (a purge class never means 'everything')")
    globs = _globs(table["globs"], f"{where}.globs")
    return PurgeClass(
        name=name,
        kind=kind,
        globs=globs,
        min_age_s=parse_duration(table.get("min_age", 0), f"{where}.min_age"),
        exclude=_globs(table.get("exclude", []), f"{where}.exclude"),
    )


def _root(raw: object, index: int, base_dir: Path) -> RootConfig:
    where = f"root[{index}]"
    table = _table(raw, where)
    _check_keys(table, ROOT_KEYS, where)
    name = table.get("name")
    if not isinstance(name, str) or not _NAME.match(name):
        raise PolicyError(f"{where}: 'name' is required (letters, digits, . _ -; used as the archive folder)")
    where = f"root {name!r}"
    if "path" not in table:
        raise PolicyError(f"{where}: 'path' is required")
    order = table.get("order", "oldest")
    if order not in ORDERS:
        raise PolicyError(f"{where}: 'order' must be one of {', '.join(ORDERS)}")
    max_size = table.get("max_size")
    purge_raw = table.get("purge", [])
    if not isinstance(purge_raw, list):
        raise PolicyError(f"{where}: 'purge' must be a list of tables")
    purge = tuple(_purge(item, f"{where}.purge[{i}]") for i, item in enumerate(purge_raw))
    if len({p.name for p in purge}) != len(purge):
        raise PolicyError(f"{where}: purge class names must be unique")
    return RootConfig(
        name=name,
        path=_path(table["path"], base_dir, f"{where}.path"),
        include=_globs(table.get("include", ["*"]), f"{where}.include"),
        exclude=_globs(table.get("exclude", []), f"{where}.exclude"),
        min_age_s=parse_duration(table.get("min_age", 0), f"{where}.min_age"),
        min_size=parse_size(table.get("min_size", 0), f"{where}.min_size"),
        max_size=None if max_size is None else parse_size(max_size, f"{where}.max_size"),
        byte_cap=_int_cap(table.get("byte_cap"), f"{where}.byte_cap"),
        order=order,
        purge=purge,
    )


def _destination(raw: object, base_dir: Path) -> DestinationSpec:
    table = _table(raw, "destination")
    kind = table.get("type")
    if kind == "local":
        _check_keys(table, LOCAL_KEYS, "destination")
        return DestinationSpec("local", {"path": _path(table.get("path"), base_dir, "destination.path")})
    if kind == "sftp":
        _check_keys(table, SFTP_KEYS, "destination")
        for required in ("host", "username", "path"):
            if not isinstance(table.get(required), str) or not table[required]:
                raise PolicyError(f"destination: '{required}' is required for sftp")
        options: dict[str, Any] = {
            "host": table["host"],
            "port": int(table.get("port", 22)),
            "username": table["username"],
            "path": table["path"],
            "connect_timeout": float(table.get("connect_timeout", 15)),
        }
        for optional in ("key_file", "known_hosts"):
            if optional in table:
                options[optional] = _path(table[optional], base_dir, f"destination.{optional}")
        if "password_env" in table:
            if not isinstance(table["password_env"], str) or not table["password_env"]:
                raise PolicyError("destination: 'password_env' must name an environment variable")
            options["password_env"] = table["password_env"]
        return DestinationSpec("sftp", options)
    raise PolicyError("destination: 'type' must be 'local' or 'sftp'")


def policy_from_dict(data: object, base_dir: Path) -> Policy:
    """Build and validate a :class:`Policy` from parsed TOML/JSON. Relative paths resolve against ``base_dir``."""
    top = _table(data, "policy")
    _check_keys(top, TOP_KEYS, "policy")
    roots_raw = top.get("root")
    if not isinstance(roots_raw, list) or not roots_raw:
        raise PolicyError("policy: at least one [[root]] is required")
    roots = tuple(_root(item, i, base_dir) for i, item in enumerate(roots_raw))
    if len({r.name for r in roots}) != len(roots):
        raise PolicyError("policy: root names must be unique")
    if "destination" not in top:
        raise PolicyError("policy: a [destination] is required")
    manifest = _path(top.get("manifest", "archive-manifest.jsonl"), base_dir, "manifest")
    lock = _path(top["lock"], base_dir, "lock") if "lock" in top else manifest.with_name(manifest.name + ".lock")
    max_failures = top.get("max_failures", 3)
    if isinstance(max_failures, bool) or not isinstance(max_failures, int) or max_failures < 1:
        raise PolicyError("policy: max_failures must be an integer >= 1")
    return Policy(
        roots=roots,
        destination=_destination(top["destination"], base_dir),
        manifest=manifest,
        lock=lock,
        byte_cap=_int_cap(top.get("byte_cap"), "byte_cap"),
        purge_byte_cap=_int_cap(top.get("purge_byte_cap"), "purge_byte_cap"),
        max_failures=max_failures,
        measure_csv=_path(top.get("measure_csv", "growth.csv"), base_dir, "measure_csv"),
    )


def load_policy(path: str | os.PathLike[str]) -> Policy:
    """Read a policy file. ``.json`` is parsed as JSON, anything else as TOML. Raises :class:`PolicyError`."""
    file = Path(path)
    try:
        raw = file.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy {file}: {exc}") from exc
    try:
        data = json.loads(raw) if file.suffix.lower() == ".json" else tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:  # JSONDecodeError and TOMLDecodeError are ValueErrors
        raise PolicyError(f"cannot parse policy {file}: {exc}") from exc
    return policy_from_dict(data, Path(os.path.abspath(file)).parent)
