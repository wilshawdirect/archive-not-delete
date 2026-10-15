"""Result objects returned by the engine. All are plain dataclasses and convert to JSON with ``dataclasses.asdict``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Failure kinds that mean "a copy could not be proven good": they map to exit code 3.
VERIFY_KINDS = (
    "source_unreadable",
    "destination_error",
    "verification_failed",
    "destination_missing",
    "destination_aliases_source",
)


@dataclass
class PlanItem:
    """One file the engine intends to handle."""

    action: str  # "archive" (copy, verify, then trim), "trim" (a verified copy already exists), "purge"
    root: str
    rel: str
    path: str
    size: int
    mtime_ns: int
    age_s: float
    reasons: list[str] = field(default_factory=list)
    kind: str | None = None  # purge class kind: cache | temp | duplicate
    keep: str | None = None  # for duplicates: the path that is kept
    entry_id: str | None = None  # for "trim": the manifest entry that proves the copy
    sha256: str | None = None  # for duplicate purges: the shared content hash
    deferred: str | None = None  # why it is not in this run: "byte_cap" or "larger_than_cap"


@dataclass
class Failure:
    """A copy or verification that could not be proven good. Nothing was trimmed because of it."""

    kind: str
    path: str
    detail: str


@dataclass
class Moved:
    """A file that was archived, trimmed or purged."""

    root: str
    rel: str
    size: int
    sha256: str | None = None
    dest_uri: str | None = None
    kind: str | None = None
    keep: str | None = None


@dataclass
class FloorReport:
    """Free space on the disk holding a root, measured before and after (or projected, for a plan)."""

    root: str
    path: str
    floor_bytes: int | None
    free_before: int
    free_after: int
    projected: bool = False

    @property
    def met(self) -> bool:
        return self.floor_bytes is None or self.free_after >= self.floor_bytes


@dataclass
class RunResult:
    """Everything a plan or run did, kept separate by kind of action."""

    mode: str
    items: list[PlanItem] = field(default_factory=list)  # what this run will/did attempt, byte cap applied
    deferred: list[PlanItem] = field(default_factory=list)  # eligible but over the byte cap
    archived: list[Moved] = field(default_factory=list)
    trimmed: list[Moved] = field(default_factory=list)
    purged: list[Moved] = field(default_factory=list)  # deleted without a copy, because the policy said so
    skipped: dict[str, int] = field(default_factory=dict)
    failures: list[Failure] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    floor: list[FloorReport] = field(default_factory=list)
    aborted: str | None = None
    bytes_archived: int = 0
    bytes_trimmed: int = 0
    bytes_purged: int = 0

    @property
    def verification_failed(self) -> bool:
        return any(f.kind in VERIFY_KINDS for f in self.failures)

    @property
    def floor_breached(self) -> bool:
        return any(not report.met for report in self.floor)

    @property
    def exit_code(self) -> int:
        """0 ok, 3 a copy failed verification (wins), 1 floor still breached or an operation errored."""
        if self.verification_failed:
            return 3
        if self.floor_breached or self.errors or self.failures:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        data = asdict(self)
        data["exit_code"] = self.exit_code
        for report, raw in zip(self.floor, data["floor"], strict=True):
            raw["met"] = report.met
        return data


@dataclass
class VerifyProblem:
    id: str
    source: str
    dest_uri: str
    status: str  # missing | size_mismatch | hash_mismatch | unreadable
    trimmed: bool  # True means the source is gone, so this problem is a real loss risk


@dataclass
class VerifyResult:
    checked: int = 0
    ok: int = 0
    problems: list[VerifyProblem] = field(default_factory=list)
    manifest_problems: list[str] = field(default_factory=list)
    quick: bool = False

    @property
    def lost(self) -> list[VerifyProblem]:
        """Problems where the source has already been trimmed: the archive copy is now the only copy."""
        return [p for p in self.problems if p.trimmed]

    @property
    def exit_code(self) -> int:
        return 3 if (self.problems or self.manifest_problems) else 0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        data = asdict(self)
        data["exit_code"] = self.exit_code
        data["lost"] = len(self.lost)
        return data


@dataclass
class RestoreResult:
    id: str
    source: str
    restored_to: str
    sha256: str
    size: int
    already_present: bool = False
