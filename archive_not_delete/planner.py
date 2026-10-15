"""Decide what a run would do: which files are old/big/matching enough, which are already safely archived, which
classes the policy lets us delete outright, and what fits under the byte cap."""

from __future__ import annotations

import os
import stat
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PolicyError, SourceError
from .manifest import Entry, ManifestState
from .policy import Policy, PurgeClass, RootConfig
from .results import PlanItem
from .scan import FileInfo, ScanStats, walk_files
from .util import Matcher, fmt_age, fmt_bytes, fs, is_link_like, sha256_file, validate_rel


class CapTracker:
    """Tracks bytes against a global cap and optional per-root caps."""

    def __init__(self, global_cap: int | None, root_caps: dict[str, int | None] | None = None) -> None:
        self.global_cap = global_cap
        self.root_caps = root_caps or {}
        self.used_global = 0
        self.used_root: dict[str, int] = defaultdict(int)

    def try_take(self, root: str, size: int) -> str | None:
        """Reserve ``size`` bytes. Returns None, or why it does not fit (``byte_cap`` / ``larger_than_cap``)."""
        root_cap = self.root_caps.get(root)
        caps = [c for c in (self.global_cap, root_cap) if c is not None]
        if caps and size > min(caps):
            return "larger_than_cap"
        if self.global_cap is not None and self.used_global + size > self.global_cap:
            return "byte_cap"
        if root_cap is not None and self.used_root[root] + size > root_cap:
            return "byte_cap"
        self.used_global += size
        self.used_root[root] += size
        return None


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)  # archive and trim items inside the byte cap
    purge: list[PlanItem] = field(default_factory=list)  # purge items inside the purge cap
    deferred: list[PlanItem] = field(default_factory=list)
    skipped: Counter[str] = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)


def bookkeeping_paths(policy: Policy) -> frozenset[str]:
    """Files the tool itself writes; a scan must never offer them for archiving."""
    return frozenset(os.path.normcase(os.path.abspath(p)) for p in (policy.manifest, policy.lock, policy.measure_csv))


def _item_age(now: float, mtime_ns: int) -> float:
    return max(0.0, now - mtime_ns / 1e9)


def pending_trims(
    root: RootConfig, state: ManifestState, exclude: Matcher, now: float, skipped: Counter[str], errors: list[str]
) -> list[PlanItem]:
    """Manifest entries with a recorded copy whose source is still on disk and still the same size."""
    by_rel: dict[str, list[Entry]] = defaultdict(list)
    for entry in state.for_root(root.name):
        if not entry.trimmed:
            by_rel[entry.rel].append(entry)
    items: list[PlanItem] = []
    for rel in sorted(by_rel):
        try:
            validate_rel(rel)
        except PolicyError:
            skipped["invalid_manifest_entry"] += 1
            continue
        if exclude.excludes(rel):
            skipped["excluded"] += 1
            continue
        path = root.path.joinpath(*rel.split("/"))
        try:
            st = os.lstat(fs(path))
        except FileNotFoundError:
            skipped["source_gone"] += 1
            continue
        except OSError as exc:
            errors.append(f"cannot stat {path}: {exc}")
            continue
        if is_link_like(st) or not stat.S_ISREG(st.st_mode):
            skipped["not_regular_file"] += 1
            continue
        same_size = [e for e in by_rel[rel] if e.size == st.st_size]
        if not same_size:
            skipped["changed_since_archive"] += 1
            continue
        entry = same_size[-1]
        items.append(
            PlanItem(
                action="trim",
                root=root.name,
                rel=rel,
                path=str(path),
                size=st.st_size,
                mtime_ns=st.st_mtime_ns,
                age_s=_item_age(now, st.st_mtime_ns),
                reasons=[f"verified copy recorded {entry.verified_at} at {entry.dest_uri}"],
                entry_id=entry.id,
            )
        )
    return items


def _duplicate_groups(
    members: list[FileInfo], errors: list[str]
) -> tuple[list[tuple[FileInfo, list[FileInfo], str]], list[FileInfo]]:
    """Split members into exact-duplicate groups (keeper, dupes, sha256) and the files that are not duplicated."""
    by_size: dict[int, list[FileInfo]] = defaultdict(list)
    for member in members:
        if member.size > 0:  # empty files are markers, not duplicates worth purging
            by_size[member.size].append(member)
    groups: list[tuple[FileInfo, list[FileInfo], str]] = []
    others: list[FileInfo] = [m for m in members if m.size == 0]
    for _size, same in sorted(by_size.items()):
        if len(same) == 1:
            others.append(same[0])
            continue
        by_hash: dict[str, list[FileInfo]] = defaultdict(list)
        for member in same:
            try:
                by_hash[sha256_file(member.path).sha256].append(member)
            except SourceError as exc:
                errors.append(str(exc))
                others.append(member)
        for sha, group in sorted(by_hash.items()):
            if len(group) == 1:
                others.append(group[0])
                continue
            group.sort(key=lambda m: (m.mtime_ns, m.rel))
            groups.append((group[0], group[1:], sha))
            others.append(group[0])
    return groups, others


def _order(items: list[PlanItem], order: str) -> list[PlanItem]:
    if order == "largest":
        return sorted(items, key=lambda i: (-i.size, i.rel))
    return sorted(items, key=lambda i: (i.mtime_ns, i.rel))


def _consider(
    plan: Plan,
    root: RootConfig,
    include: Matcher,
    pending: dict[str, PlanItem],
    info: FileInfo,
    now: float,
) -> PlanItem | None:
    """Apply the root's include/age/size rules to one file; returns an archive item or None (and counts why not)."""
    age = _item_age(now, info.mtime_ns)
    pattern = include.which(info.rel)
    if pattern is None:
        plan.skipped["not_matched"] += 1
        return None
    if age < root.min_age_s:
        plan.skipped["too_young"] += 1
        return None
    if info.size < root.min_size:
        plan.skipped["too_small"] += 1
        return None
    if root.max_size is not None and info.size > root.max_size:
        plan.skipped["too_large"] += 1
        return None
    seen = pending.get(info.rel)
    if seen is not None and seen.size == info.size and seen.mtime_ns == info.mtime_ns:
        plan.skipped["already_archived"] += 1  # a verified copy exists; a trim item (if wanted) covers it
        return None
    reasons = [f"matches {pattern!r}"]
    if root.min_age_s > 0:
        reasons.append(f"age {fmt_age(age)} >= {fmt_age(root.min_age_s)}")
    if root.min_size > 0:
        reasons.append(f"size {fmt_bytes(info.size)} >= {fmt_bytes(root.min_size)}")
    return PlanItem("archive", root.name, info.rel, str(info.path), info.size, info.mtime_ns, age, reasons)


def _purge_item(root: RootConfig, info: FileInfo, now: float, reason: str, **extra: str | None) -> PlanItem:
    return PlanItem(
        "purge",
        root.name,
        info.rel,
        str(info.path),
        info.size,
        info.mtime_ns,
        _item_age(now, info.mtime_ns),
        [reason],
        **extra,
    )


def _scan_root(
    plan: Plan,
    root: RootConfig,
    pending: dict[str, PlanItem],
    *,
    want_archive: bool,
    purge: bool,
    skip: frozenset[str],
    now: float,
) -> tuple[list[PlanItem], list[PlanItem]]:
    """Walk one root; return (archive items, purge items)."""
    include = root.include_matcher()
    classes = [(pc, pc.matcher(), pc.exclude_matcher()) for pc in root.purge]
    archive_items: list[PlanItem] = []
    purge_items: list[PlanItem] = []
    dup_members: dict[str, list[FileInfo]] = defaultdict(list)
    stats = ScanStats()

    def offer(info: FileInfo) -> None:
        if want_archive:
            item = _consider(plan, root, include, pending, info, now)
            if item is not None:
                archive_items.append(item)

    for info in walk_files(root.path, root.exclude_matcher(), skip=skip, stats=stats):
        owner: PurgeClass | None = None
        pattern = None
        for pc, matcher, pc_exclude in classes:
            pattern = matcher.which(info.rel)
            if pattern is not None and not pc_exclude.matches(info.rel):
                owner = pc
                break
        if owner is None:
            offer(info)
            continue
        young = _item_age(now, info.mtime_ns) < owner.min_age_s
        if owner.kind == "duplicate":
            if young:
                offer(info)
            else:
                dup_members[owner.name].append(info)
        elif young:
            plan.skipped["purge_too_young"] += 1
        elif purge:
            purge_items.append(
                _purge_item(
                    root, info, now, f"purge class {owner.name!r} ({owner.kind}) matches {pattern!r}", kind=owner.kind
                )
            )
        else:
            plan.skipped["purge_disabled"] += 1
    for _name, members in sorted(dup_members.items()):
        if not purge:
            for member in members:
                offer(member)
            continue
        groups, others = _duplicate_groups(members, plan.errors)
        for keeper, dupes, sha in groups:
            for dupe in dupes:
                purge_items.append(
                    _purge_item(
                        root,
                        dupe,
                        now,
                        f"exact duplicate (sha256 {sha[:12]}) of {keeper.rel}",
                        kind="duplicate",
                        keep=str(keeper.path),
                        sha256=sha,
                    )
                )
        for member in others:
            offer(member)
    for key, count in stats.counts.items():
        plan.skipped[key] += count
    plan.errors.extend(stats.errors)
    return archive_items, purge_items


def build_plan(
    policy: Policy,
    roots: list[RootConfig],
    state: ManifestState,
    *,
    mode: str,
    purge: bool,
    byte_cap: int | None,
    now: float,
) -> Plan:
    """Build the ordered, cap-limited list of work for ``mode`` (archive | trim | run)."""
    plan = Plan()
    want_archive = mode in ("archive", "run")
    want_trim = mode in ("trim", "run")
    skip = bookkeeping_paths(policy)
    work: list[PlanItem] = []
    purge_work: list[PlanItem] = []
    for root in roots:
        if not root.path.is_dir():
            plan.errors.append(f"root {root.name!r}: {root.path} is not a directory (unmounted?) - skipped")
            continue
        root_items: list[PlanItem] = []
        pending: dict[str, PlanItem] = {}
        scratch_skipped: Counter[str] = plan.skipped if want_trim else Counter()
        scratch_errors: list[str] = plan.errors if want_trim else []
        for item in pending_trims(root, state, root.exclude_matcher(), now, scratch_skipped, scratch_errors):
            if want_trim:
                root_items.append(item)
            pending[item.rel] = item
        if want_archive or (purge and want_trim and root.purge):
            found, doomed = _scan_root(plan, root, pending, want_archive=want_archive, purge=purge, skip=skip, now=now)
            root_items.extend(found)
            purge_work.extend(doomed)
        work.extend(_order(root_items, root.order))
    tracker = CapTracker(byte_cap if byte_cap is not None else policy.byte_cap, {r.name: r.byte_cap for r in roots})
    for item in work:
        reason = tracker.try_take(item.root, item.size)
        if reason is None:
            plan.items.append(item)
        else:
            item.deferred = reason
            plan.deferred.append(item)
    purge_tracker = CapTracker(policy.purge_byte_cap)
    for item in sorted(purge_work, key=lambda i: (i.root, i.rel)):
        reason = purge_tracker.try_take(item.root, item.size)
        if reason is None:
            plan.purge.append(item)
        else:
            item.deferred = reason
            plan.deferred.append(item)
    return plan


def local_destination_path(policy: Policy) -> Path | None:
    """The local archive directory the policy names, if any."""
    if policy.destination.type == "local":
        return Path(policy.destination.options["path"])
    return None
