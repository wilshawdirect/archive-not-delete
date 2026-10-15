"""The engine: plan, archive, trim, run, verify-manifest, restore, measure.

The one rule: a source file is removed only after a copy of the same bytes has been read back from the archive
destination and matched (sha256 and size), and the file on disk still matches that copy at the moment it is removed.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import time
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .destinations import Destination, LocalDestination, SourceStream, build_destination
from .errors import (
    AliasError,
    ArchiveError,
    DestinationError,
    PolicyError,
    RestoreError,
    SourceError,
    VerificationError,
    from_os_error,
)
from .lock import RunLock
from .manifest import Entry, Manifest, entry_id
from .measure import MeasureRow, measure_roots
from .planner import CapTracker, Plan, build_plan, local_destination_path
from .policy import Policy, RootConfig
from .results import (
    Failure,
    FloorReport,
    Moved,
    PlanItem,
    RestoreResult,
    RunResult,
    VerifyProblem,
    VerifyResult,
)
from .scan import find_name_near_top
from .util import (
    CHUNK,
    Digest,
    fs,
    is_inside,
    is_link_like,
    iso_utc,
    key_of,
    real_norm,
    sha256_file,
    validate_rel,
)

MODES = ("plan", "archive", "trim", "run")
PROBE_BYTES = b"archive-not-delete layout probe: this file is created and removed by the tool\n"


class _LazyDestination:
    """Builds the destination on first use (so a plan or a trim with nothing to check never connects)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._dest: Destination | None = None
        self._owned = False

    def get(self) -> Destination:
        if self._dest is None:
            if self._engine._destination is not None:
                self._dest = self._engine._destination
            else:
                self._dest = build_destination(self._engine.policy.destination)
                self._owned = True
        return self._dest

    def close(self) -> None:
        if self._owned and self._dest is not None:
            self._dest.close()


class Engine:
    """Runs a :class:`~archive_not_delete.policy.Policy`.

    ``destination`` overrides the policy's destination (tests and embedders). ``now`` and ``disk_usage`` are
    injectable so behaviour is deterministic under test.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        destination: Destination | None = None,
        now: Callable[[], float] = time.time,
        disk_usage: Callable[[str], Any] = shutil.disk_usage,
    ) -> None:
        self.policy = policy
        self._destination = destination
        self._now = now
        self._disk_usage = disk_usage

    # ------------------------------------------------------------------------------------------ public API

    def plan(
        self,
        *,
        mode: str = "run",
        roots: Sequence[str] | None = None,
        byte_cap: int | None = None,
        floor_gb: float | None = None,
        purge: bool = False,
    ) -> RunResult:
        """Dry run: list what ``mode`` (archive | trim | run) would do. Writes nothing and never connects.
        Purge classes are only shown with ``purge=True``, exactly as ``trim``/``run`` only run them then."""
        if mode not in ("archive", "trim", "run"):
            raise PolicyError(f"cannot plan mode {mode!r}")
        selected = self._select(roots)
        self._validate_layout(selected)
        result = RunResult(mode="plan")
        before = self._free_map(selected, result)
        state = Manifest(self.policy.manifest).read()
        plan = build_plan(
            self.policy,
            selected,
            state,
            mode=mode,
            purge=purge and mode != "archive",
            byte_cap=byte_cap,
            now=self._now(),
        )
        self._adopt_plan(result, plan)
        freed: Counter[str] = Counter()
        for item in plan.items:
            if mode != "archive":
                freed[item.root] += item.size
        for item in plan.purge:
            freed[item.root] += item.size
        result.floor = self._floor(selected, floor_gb, before, {r: before.get(r, 0) + freed[r] for r in before}, True)
        return result

    def archive(self, **options: Any) -> RunResult:
        """Copy eligible files to the destination and verify each copy. Sources are kept."""
        return self._execute("archive", **options)

    def trim(self, **options: Any) -> RunResult:
        """Remove sources whose verified copy is recorded in the manifest. Pass ``purge=True`` to also run the
        purge classes the policy declares."""
        return self._execute("trim", **options)

    def run(self, **options: Any) -> RunResult:
        """Archive, verify, then trim each file, within the byte cap. Pass ``purge=True`` to also run the purge
        classes the policy declares."""
        return self._execute("run", **options)

    def verify_manifest(self, *, quick: bool = False) -> VerifyResult:
        """Re-check every archived object against the destination. ``quick`` checks existence only."""
        state = Manifest(self.policy.manifest).read(strict=False)
        result = VerifyResult(quick=quick, manifest_problems=list(state.problems))
        if not state.entries:
            return result
        lazy = _LazyDestination(self)
        try:
            dest = lazy.get()
            for entry in state.entries.values():
                result.checked += 1
                status = self._check_entry(dest, entry, quick)
                if status == "ok":
                    result.ok += 1
                else:
                    result.problems.append(VerifyProblem(entry.id, entry.source, entry.dest_uri, status, entry.trimmed))
        finally:
            lazy.close()
        return result

    def restore(
        self,
        target: str,
        *,
        to: str | os.PathLike[str] | None = None,
        force: bool = False,
        sha256: str | None = None,
        preserve_mtime: bool = False,
    ) -> RestoreResult:
        """Copy an archived file back, checking its hash on the way. Never overwrites without ``force``."""
        with RunLock(self.policy.lock):
            manifest = Manifest(self.policy.manifest)
            state = manifest.read()
            matches = state.find(target) or state.find(os.path.abspath(target))
            if sha256:
                matches = [e for e in matches if e.sha256.startswith(sha256.lower())]
            if not matches:
                raise RestoreError(f"nothing in the manifest matches {target!r}")
            entry = matches[-1]
            if to is None:
                try:
                    validate_rel(entry.rel)
                    root = self.policy.root(entry.root)
                except PolicyError as exc:
                    raise RestoreError(f"cannot restore in place: {exc}; pass --to") from exc
                path = root.path.joinpath(*entry.rel.split("/"))
            else:
                path = Path(os.path.abspath(to))
                if path.is_dir():
                    path = path / entry.rel.rsplit("/", 1)[-1]
            if os.path.lexists(fs(path)):
                st = os.lstat(fs(path))
                if is_link_like(st) or not stat.S_ISREG(st.st_mode):
                    raise RestoreError(f"{path} exists and is not a regular file")
                if sha256_file(path).sha256 == entry.sha256:
                    return RestoreResult(entry.id, entry.source, str(path), entry.sha256, entry.size, True)
                if not force:
                    raise RestoreError(f"{path} already exists with different content; use --force to replace it")
            lazy = _LazyDestination(self)
            tmp = path.with_name(f"{path.name}.restore-{uuid.uuid4().hex[:8]}")
            try:
                dest = lazy.get()
                os.makedirs(fs(path.parent), exist_ok=True)
                self._copy_back(dest, entry, tmp)
                if preserve_mtime:
                    os.utime(fs(tmp), ns=(entry.mtime_ns, entry.mtime_ns))
                os.replace(fs(tmp), fs(path))
            except OSError as exc:
                raise RestoreError(f"cannot write {path}: {exc}") from exc
            finally:
                if os.path.lexists(fs(tmp)):
                    try:
                        os.unlink(fs(tmp))
                    except OSError:
                        pass
                lazy.close()
            manifest.append(
                "restored",
                id=entry.id,
                source=entry.source,
                sha256=entry.sha256,
                size=entry.size,
                restored_to=str(path),
                restored_at=iso_utc(self._now()),
            )
            return RestoreResult(entry.id, entry.source, str(path), entry.sha256, entry.size)

    def measure(
        self,
        *,
        depth: int = 1,
        csv_path: str | os.PathLike[str] | None = None,
        roots: Sequence[str] | None = None,
    ) -> list[MeasureRow]:
        """Record per-folder sizes to the growth CSV and return the rows (with growth since the last measurement)."""
        selected = [r for r in self._select(roots) if r.path.is_dir()]
        target = Path(csv_path) if csv_path else self.policy.measure_csv
        try:
            return measure_roots([(r.name, r.path) for r in selected], target, now=self._now(), depth=depth)
        except OSError as exc:
            raise from_os_error(exc, f"cannot write the growth CSV {target}") from exc

    # ----------------------------------------------------------------------------------------- selection

    def _select(self, names: Sequence[str] | None) -> list[RootConfig]:
        if not names:
            return list(self.policy.roots)
        return [self.policy.root(name) for name in names]

    def _validate_layout(self, roots: list[RootConfig]) -> None:
        """A local archive must not sit inside a swept root (it would be swept) or contain one (it would be fed)."""
        if isinstance(self._destination, LocalDestination):
            dest_path: Path | None = self._destination.base
        elif self._destination is None:
            dest_path = local_destination_path(self.policy)
        else:
            dest_path = None
        if dest_path is None:
            return
        dest_real = real_norm(dest_path)
        for root in roots:
            root_real = real_norm(root.path)
            if is_inside(dest_real, root_real) or is_inside(root_real, dest_real):
                raise PolicyError(
                    f"destination {dest_path} and root {root.name!r} ({root.path}) overlap; "
                    "the archive must live outside every swept folder"
                )

    # ---------------------------------------------------------------------------------------- free space

    def _free(self, root: RootConfig) -> int:
        return int(self._disk_usage(os.fspath(root.path)).free)

    def _free_map(self, roots: list[RootConfig], result: RunResult) -> dict[str, int]:
        free: dict[str, int] = {}
        for root in roots:
            try:
                free[root.name] = self._free(root)
            except OSError as exc:
                result.errors.append(f"cannot read free space for root {root.name!r}: {exc}")
        return free

    def _floor(
        self,
        roots: list[RootConfig],
        floor_gb: float | None,
        before: dict[str, int],
        after: dict[str, int],
        projected: bool,
    ) -> list[FloorReport]:
        floor = None if floor_gb is None else int(floor_gb * 1_000_000_000)
        return [
            FloorReport(r.name, str(r.path), floor, before[r.name], after[r.name], projected)
            for r in roots
            if r.name in before and r.name in after
        ]

    # ---------------------------------------------------------------------------------------- execution

    @staticmethod
    def _adopt_plan(result: RunResult, plan: Plan) -> None:
        result.items = plan.items + plan.purge
        result.deferred = list(plan.deferred)
        result.skipped = dict(plan.skipped)
        result.errors.extend(plan.errors)

    def _execute(
        self,
        mode: str,
        *,
        roots: Sequence[str] | None = None,
        byte_cap: int | None = None,
        floor_gb: float | None = None,
        purge: bool = False,
    ) -> RunResult:
        selected = self._select(roots)
        self._validate_layout(selected)
        result = RunResult(mode=mode)
        with RunLock(self.policy.lock):
            before = self._free_map(selected, result)
            manifest = Manifest(self.policy.manifest)
            state = manifest.read()
            cap = byte_cap if byte_cap is not None else self.policy.byte_cap
            plan = build_plan(
                self.policy,
                selected,
                state,
                mode=mode,
                purge=purge and mode != "archive",
                byte_cap=cap,
                now=self._now(),
            )
            self._adopt_plan(result, plan)
            lazy = _LazyDestination(self)
            try:
                self._apply(mode, plan, selected, cap, manifest, lazy, result)
            finally:
                lazy.close()
            after = self._free_map(selected, result)
        result.floor = self._floor(selected, floor_gb, before, after, False)
        return result

    def _apply(
        self,
        mode: str,
        plan: Plan,
        selected: list[RootConfig],
        cap: int | None,
        manifest: Manifest,
        lazy: _LazyDestination,
        result: RunResult,
    ) -> None:
        tracker = CapTracker(cap, {r.name: r.byte_cap for r in selected})
        purge_tracker = CapTracker(self.policy.purge_byte_cap)
        ready: dict[str, bool] = {}
        for item in plan.purge:
            self._purge_one(item, manifest, result, purge_tracker)
        for item in plan.items:
            if result.aborted:
                break
            root = self.policy.root(item.root)
            if item.root not in ready:
                ready[item.root] = self._root_ready(lazy, root, result)
            if not ready[item.root]:
                self._skip(result, "root_refused")
                continue
            if item.action == "archive":
                entry = self._archive_one(item, root, manifest, lazy, result, tracker)
                if entry is not None and mode == "run":
                    self._trim_entry(entry, root, manifest, lazy, result)
            elif item.action == "trim" and mode in ("trim", "run"):
                entry = manifest.state.entries.get(item.entry_id or "")
                if entry is not None and self._take_cap(tracker, item, item.size, result):
                    self._trim_entry(entry, root, manifest, lazy, result)

    def _root_ready(self, lazy: _LazyDestination, root: RootConfig, result: RunResult) -> bool:
        """Layout canary. Write a probe through the destination's own API (so it works for SFTP too) and look for it
        inside the source root. If it shows up there, the archive and the source are the same storage - for instance
        the same folder reached through a network-share alias - and any "copy" would be the source itself."""
        name = f".probe-{uuid.uuid4().hex}"
        key = f"{root.name}/{name}"
        try:
            dest = lazy.get()
            dest.put(SourceStream(io.BytesIO(PROBE_BYTES)), key)
        except ArchiveError as exc:
            self._fail(result, "destination_error", root.path, f"destination probe failed: {exc}")
            return False
        try:
            if find_name_near_top(root.path, name):
                self._fail(
                    result,
                    "destination_aliases_source",
                    root.path,
                    f"root {root.name!r}: the archive destination writes into the source tree "
                    f"({dest.uri(key)} appeared under {root.path}); refusing to treat it as a separate copy",
                )
                return False
            return True
        finally:
            try:
                dest.remove(key)
            except ArchiveError as exc:
                result.errors.append(f"could not remove the layout probe {dest.uri(key)}: {exc}")

    # ------------------------------------------------------------------------------------------ helpers

    @staticmethod
    def _skip(result: RunResult, why: str) -> None:
        result.skipped[why] = result.skipped.get(why, 0) + 1

    def _fail(self, result: RunResult, kind: str, path: Path | str, exc: Exception | str) -> None:
        result.failures.append(Failure(kind, str(path), str(exc)))
        if len(result.failures) >= self.policy.max_failures and result.aborted is None:
            result.aborted = f"stopped after {len(result.failures)} failures (max_failures)"

    @staticmethod
    def _take_cap(tracker: CapTracker, item: PlanItem, size: int, result: RunResult) -> bool:
        reason = tracker.try_take(item.root, size)
        if reason is None:
            return True
        item.deferred = reason
        result.deferred.append(item)
        return False

    @staticmethod
    def _regular(path: Path) -> os.stat_result | None:
        """lstat the path; None unless it is a plain regular file (not a link) that still exists."""
        try:
            st = os.lstat(fs(path))
        except OSError:
            return None
        if is_link_like(st) or not stat.S_ISREG(st.st_mode):
            return None
        return st

    @staticmethod
    def _confined(path: Path, root: RootConfig, rel: str) -> bool:
        """True when ``path`` really is ``<root>/<rel>`` with no link anywhere along the way."""
        expected = os.path.normcase(os.path.join(real_norm(root.path), *[os.path.normcase(p) for p in rel.split("/")]))
        return real_norm(path) == expected

    @staticmethod
    def _same_file(a: Path, b: Path) -> bool:
        """True when both paths are the same file (same device and inode, whatever they are called).
        If that cannot be established the answer is True: refuse rather than guess."""
        try:
            return os.path.samefile(fs(a), fs(b))
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def _require_independent(self, dest: Destination, key: str, source: Path) -> None:
        """Refuse when the archive object is the source file itself (an alias, a hard link) or a link to it."""
        stored = dest.local_path(key)
        if stored is None:
            return  # remote destination: the layout probe covers it
        if os.path.islink(fs(stored)):
            raise AliasError(f"archive object {stored} is a link; it cannot count as an independent copy of {source}")
        if self._same_file(source, stored):
            raise AliasError(f"archive object {stored} is the same file as {source}; there is no second copy")

    # -------------------------------------------------------------------------------------- archive step

    def _store(self, dest: Destination, path: Path, key: str) -> tuple[Digest, str]:
        """Copy ``path`` into the destination and prove the stored bytes match. Never overwrites an existing object."""
        if dest.exists(key):
            source = sha256_file(path)
            if dest.digest(key) == source:
                self._require_independent(dest, key, path)  # identical must not mean the same file
                return source, key  # an identical object is already there: reuse it
            key = f"{key}.{source.sha256[:16]}"  # same name, different content: keep both
            if dest.exists(key):
                if dest.digest(key) == source:
                    self._require_independent(dest, key, path)
                    return source, key
                raise VerificationError(f"archive object {dest.uri(key)} exists with different content")
        try:
            with open(fs(path), "rb") as handle:
                sent = dest.put(SourceStream(handle, str(path)), key)
        except OSError as exc:
            raise SourceError(f"cannot read {path}: {exc}") from exc
        stored = dest.digest(key)  # the verification read: independent of what was sent
        if stored != sent:
            raise VerificationError(
                f"copy of {path} did not verify at {dest.uri(key)}: "
                f"sent {sent.sha256[:12]} ({sent.size} B), read back {stored.sha256[:12]} ({stored.size} B)"
            )
        self._require_independent(dest, key, path)
        return stored, key

    def _archive_one(
        self,
        item: PlanItem,
        root: RootConfig,
        manifest: Manifest,
        lazy: _LazyDestination,
        result: RunResult,
        tracker: CapTracker,
    ) -> Entry | None:
        path = Path(item.path)
        st = self._regular(path)
        if st is None:
            self._skip(result, "source_gone")
            return None
        if not self._confined(path, root, item.rel):
            self._skip(result, "escapes_root")
            return None
        if not self._take_cap(tracker, item, st.st_size, result):
            return None
        try:
            stored, key = self._store(lazy.get(), path, key_of(item.root, item.rel))
        except SourceError as exc:
            self._fail(result, "source_unreadable", path, exc)
            return None
        except AliasError as exc:
            self._fail(result, "destination_aliases_source", path, exc)
            return None
        except VerificationError as exc:
            self._fail(result, "verification_failed", path, exc)
            return None
        except DestinationError as exc:
            self._fail(result, "destination_error", path, exc)
            return None
        after = self._regular(path)
        changed = after is None or (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns)
        dest = lazy.get()
        ident = entry_id(item.root, item.rel, stored.sha256, key)
        manifest.append(
            "archived",
            id=ident,
            root=item.root,
            rel=item.rel,
            source=str(path),
            size=stored.size,
            sha256=stored.sha256,
            mtime_ns=st.st_mtime_ns,
            dest_uri=dest.uri(key),
            dest_key=key,
            verified_at=iso_utc(self._now()),
        )
        result.archived.append(Moved(item.root, item.rel, stored.size, stored.sha256, dest.uri(key)))
        result.bytes_archived += stored.size
        if changed:
            self._skip(result, "changed_during_copy")
            return None
        return manifest.state.entries[ident]

    # ---------------------------------------------------------------------------------------- trim step

    def _trim_entry(
        self,
        entry: Entry,
        root: RootConfig,
        manifest: Manifest,
        lazy: _LazyDestination,
        result: RunResult,
    ) -> None:
        try:
            validate_rel(entry.rel)
        except PolicyError:
            self._skip(result, "invalid_manifest_entry")
            return
        if root.exclude_matcher().excludes(entry.rel):
            self._skip(result, "excluded")
            return
        path = root.path.joinpath(*entry.rel.split("/"))
        st = self._regular(path)
        if st is None:
            self._skip(result, "source_gone")
            return
        if not self._confined(path, root, entry.rel):
            self._skip(result, "escapes_root")
            return
        if st.st_size != entry.size:
            self._skip(result, "changed_since_archive")
            return
        try:
            current = sha256_file(path)
        except SourceError as exc:
            self._fail(result, "source_unreadable", path, exc)
            return
        if current.sha256 != entry.sha256:
            self._skip(result, "changed_since_archive")
            return
        try:
            dest = lazy.get()
        except DestinationError as exc:
            self._fail(result, "destination_missing", path, exc)
            return
        try:  # a link or alias is refused BEFORE the re-read, so the reason names it (a link's read can fail first)
            self._require_independent(dest, entry.dest_key, path)
        except (
            AliasError,
            DestinationError,
        ) as exc:  # a key whose link resolves outside the destination is the same refusal
            self._fail(result, "destination_aliases_source", path, exc)
            return
        try:  # always re-read the archive copy right before removing the source; never trust the ledger alone
            stored = dest.digest(entry.dest_key)
        except DestinationError as exc:
            self._fail(result, "destination_missing", path, exc)
            return
        if stored != Digest(entry.sha256, entry.size):
            self._fail(
                result,
                "verification_failed",
                path,
                f"archive copy at {entry.dest_uri} no longer matches the manifest "
                f"(expected {entry.sha256[:12]} / {entry.size} B, found {stored.sha256[:12]} / {stored.size} B); "
                "source kept",
            )
            return
        try:
            self._require_independent(dest, entry.dest_key, path)
        except AliasError as exc:
            self._fail(result, "destination_aliases_source", path, exc)
            return
        last = self._regular(path)
        if last is None or (last.st_size, last.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
            self._skip(result, "changed_since_archive")
            return
        try:
            os.unlink(fs(path))
        except OSError as exc:
            result.errors.append(f"cannot remove {path}: {exc}")
            return
        manifest.append(
            "trimmed",
            id=entry.id,
            source=entry.source,
            size=entry.size,
            sha256=entry.sha256,
            dest_uri=entry.dest_uri,
            trimmed_at=iso_utc(self._now()),
        )
        result.trimmed.append(Moved(entry.root, entry.rel, entry.size, entry.sha256, entry.dest_uri))
        result.bytes_trimmed += entry.size

    # ---------------------------------------------------------------------------------------- purge step

    def _purge_one(self, item: PlanItem, manifest: Manifest, result: RunResult, tracker: CapTracker) -> None:
        root = self.policy.root(item.root)
        path = Path(item.path)
        try:
            validate_rel(item.rel)
        except PolicyError:
            self._skip(result, "invalid_plan_entry")
            return
        if root.exclude_matcher().excludes(item.rel):
            self._skip(result, "excluded")
            return
        st = self._regular(path)
        if st is None:
            self._skip(result, "source_gone")
            return
        if not self._confined(path, root, item.rel):
            self._skip(result, "escapes_root")
            return
        if (st.st_size, st.st_mtime_ns) != (item.size, item.mtime_ns):
            self._skip(result, "changed_since_plan")
            return
        sha: str | None = None
        keep: str | None = None
        if item.kind == "duplicate":
            keeper = Path(item.keep or "")
            keeper_rel = os.path.relpath(keeper, root.path).replace(os.sep, "/")
            if keeper == path or self._regular(keeper) is None or not self._confined(keeper, root, keeper_rel):
                self._skip(result, "duplicate_keeper_missing")
                return
            if self._same_file(path, keeper):
                self._skip(result, "duplicate_is_same_file")
                return
            try:
                mine, theirs = sha256_file(path), sha256_file(keeper)
            except SourceError as exc:
                result.errors.append(str(exc))
                return
            if mine != theirs or mine.sha256 != item.sha256:
                self._skip(result, "duplicate_changed")
                return
            sha, keep = mine.sha256, str(keeper)
        if not self._take_cap(tracker, item, st.st_size, result):
            return
        try:
            os.unlink(fs(path))
        except OSError as exc:
            result.errors.append(f"cannot remove {path}: {exc}")
            return
        fields: dict[str, Any] = {
            "root": item.root,
            "rel": item.rel,
            "source": str(path),
            "size": st.st_size,
            "kind": item.kind,
            "purged_at": iso_utc(self._now()),
        }
        if sha:
            fields["sha256"] = sha
            fields["kept"] = keep
        manifest.append("purged", **fields)
        result.purged.append(Moved(item.root, item.rel, st.st_size, sha, None, item.kind, keep))
        result.bytes_purged += st.st_size

    # ------------------------------------------------------------------------------------ verify / restore

    @staticmethod
    def _check_entry(dest: Destination, entry: Entry, quick: bool) -> str:
        try:
            if not dest.exists(entry.dest_key):
                return "missing"
            if quick:
                return "ok"
            found = dest.digest(entry.dest_key)
        except ArchiveError:
            return "unreadable"
        if found.size != entry.size:
            return "size_mismatch"
        if found.sha256 != entry.sha256:
            return "hash_mismatch"
        return "ok"

    @staticmethod
    def _copy_back(dest: Destination, entry: Entry, tmp: Path) -> None:
        """Stream the archived object to ``tmp`` and require it to match the manifest's hash and size."""
        sha = hashlib.sha256()
        size = 0
        with dest.open_read(entry.dest_key) as src, open(fs(tmp), "xb") as out:
            while chunk := src.read(CHUNK):
                sha.update(chunk)
                size += len(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if Digest(sha.hexdigest(), size) != Digest(entry.sha256, entry.size):
            raise VerificationError(
                f"archive copy at {entry.dest_uri} does not match the manifest "
                f"(expected {entry.sha256[:12]}, got {sha.hexdigest()[:12]}); nothing was restored"
            )
