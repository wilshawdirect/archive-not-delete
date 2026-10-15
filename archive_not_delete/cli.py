"""Command line: ``python -m archive_not_delete plan|archive|trim|run|verify-manifest|restore|measure``.

Exit codes: 0 ok, 1 floor still breached (or an operation errored), 2 usage/policy error, 3 a copy failed
verification (nothing was trimmed for it), 4 another run holds the lock.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from . import __version__
from .engine import Engine
from .errors import ArchiveError, PolicyError, from_os_error
from .policy import load_policy
from .results import RestoreResult, RunResult, VerifyResult
from .util import fmt_age, fmt_bytes, parse_size

EXIT_OK, EXIT_FLOOR, EXIT_USAGE, EXIT_VERIFY, EXIT_LOCKED = 0, 1, 2, 3, 4


def _size(text: str) -> int:
    try:
        return parse_size(text, "--byte-cap")
    except PolicyError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", "-p", required=True, metavar="FILE", help="policy file (.toml or .json)")
    common.add_argument("--json", action="store_true", help="print the result as JSON")

    run_opts = argparse.ArgumentParser(add_help=False)
    run_opts.add_argument("--root", action="append", metavar="NAME", help="only this root (repeatable)")
    run_opts.add_argument(
        "--byte-cap", type=_size, metavar="SIZE", help="per-run byte cap, e.g. 20GB (overrides policy)"
    )
    run_opts.add_argument("--floor-gb", type=float, metavar="N", help="free-space floor in decimal GB (10^9 bytes)")

    parser = argparse.ArgumentParser(
        prog="archive-not-delete",
        description="Free disk space by moving files to a verified archive. Nothing is deleted without one.",
        epilog="exit codes: 0 ok | 1 floor still breached or an operation errored | 2 usage/policy error | "
        "3 a copy failed verification (nothing trimmed for it) | 4 another run holds the lock",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    plan = sub.add_parser("plan", parents=[common, run_opts], help="dry run: list what would move, bytes and reasons")
    plan.add_argument("--mode", choices=("archive", "trim", "run"), default="run", help="which command to preview")
    plan.add_argument("--purge", action="store_true", help="include the purge classes the policy declares")
    plan.add_argument("--rows", type=int, default=40, metavar="N", help="rows to print in text mode (default 40)")

    sub.add_parser("archive", parents=[common, run_opts], help="copy + verify eligible files; keep the sources")

    for name, text in (
        ("trim", "remove sources whose verified copy is in the manifest (re-read every time)"),
        ("run", "archive, verify, then trim within the byte cap"),
    ):
        cmd = sub.add_parser(name, parents=[common, run_opts], help=text)
        cmd.add_argument(
            "--purge",
            action="store_true",
            help="ALSO delete, without a copy, files in the purge classes the policy declares (off by default)",
        )

    verify = sub.add_parser("verify-manifest", parents=[common], help="re-check every archived object")
    verify.add_argument("--quick", action="store_true", help="existence only, no hashing")

    restore = sub.add_parser("restore", parents=[common], help="copy an archived file back")
    restore.add_argument("target", help="recorded source path, root/relative-path key, or entry id")
    restore.add_argument("--to", metavar="PATH", help="write here instead of the original location")
    restore.add_argument("--force", action="store_true", help="replace an existing file with different content")
    restore.add_argument("--sha256", metavar="PREFIX", help="pick the version whose hash starts with this")
    restore.add_argument("--preserve-mtime", action="store_true", help="keep the archived modification time")

    measure = sub.add_parser("measure", parents=[common], help="record per-folder sizes to the growth CSV")
    measure.add_argument("--depth", type=int, default=1, metavar="N", help="folder levels below each root (default 1)")
    measure.add_argument("--csv", metavar="FILE", help="CSV to append to (default: policy measure_csv)")
    measure.add_argument("--root", action="append", metavar="NAME", help="only this root (repeatable)")
    measure.add_argument("--top", type=int, default=15, metavar="N", help="rows to print (default 15)")
    return parser


# --------------------------------------------------------------------------------------------------- output


def _emit(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _print_floor(result: RunResult) -> None:
    for report in result.floor:
        label = "projected after" if report.projected else "after"
        floor = "none" if report.floor_bytes is None else fmt_bytes(report.floor_bytes)
        state = "met" if report.met else "BREACHED"
        print(
            f"free space [{report.root}] before {fmt_bytes(report.free_before)}  {label} {fmt_bytes(report.free_after)}"
            f"  floor {floor}  {state}"
        )


def _print_problems(result: RunResult) -> None:
    if result.skipped:
        print("skipped: " + ", ".join(f"{k}={v}" for k, v in sorted(result.skipped.items())))
    for failure in result.failures:
        print(f"FAILED  {failure.kind}  {failure.path}: {failure.detail}", file=sys.stderr)
    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    if result.aborted:
        print(f"aborted: {result.aborted}", file=sys.stderr)


def _print_plan(result: RunResult, rows: int) -> None:
    by_action: dict[str, int] = {}
    size_by_action: dict[str, int] = {}
    for item in result.items:
        by_action[item.action] = by_action.get(item.action, 0) + 1
        size_by_action[item.action] = size_by_action.get(item.action, 0) + item.size
    summary = ", ".join(f"{n} to {a} ({fmt_bytes(size_by_action[a])})" for a, n in sorted(by_action.items()))
    print(f"plan: {summary or 'nothing to do'}; {len(result.deferred)} deferred by the byte cap")
    for item in result.items[:rows]:
        print(f"  {item.action.upper():8} {fmt_bytes(item.size):>9} {fmt_age(item.age_s):>5}  {item.root}/{item.rel}")
        print(f"           why: {'; '.join(item.reasons)}")
    if len(result.items) > rows:
        print(f"  ... {len(result.items) - rows} more (use --json for all)")
    for item in result.deferred[: max(0, rows - len(result.items))]:
        print(f"  DEFERRED {fmt_bytes(item.size):>9} {item.root}/{item.rel}  ({item.deferred})")
    _print_problems(result)
    _print_floor(result)


def _print_run(result: RunResult) -> None:
    print(
        f"{result.mode}: archived {len(result.archived)} ({fmt_bytes(result.bytes_archived)}), "
        f"trimmed {len(result.trimmed)} ({fmt_bytes(result.bytes_trimmed)}), "
        f"deferred {len(result.deferred)}"
    )
    if result.purged:
        print(
            f"purged without a copy (declared in policy): {len(result.purged)} files, {fmt_bytes(result.bytes_purged)}"
        )
        kinds: dict[str, int] = {}
        for moved in result.purged:
            kinds[moved.kind or "?"] = kinds.get(moved.kind or "?", 0) + 1
        print("  by kind: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    _print_problems(result)
    _print_floor(result)


def _print_verify(result: VerifyResult) -> None:
    mode = "existence only" if result.quick else "sha256 + size"
    print(f"verify-manifest ({mode}): checked {result.checked}, ok {result.ok}, problems {len(result.problems)}")
    for problem in result.problems:
        risk = "SOURCE TRIMMED - archive copy is the only copy" if problem.trimmed else "source still on disk"
        print(f"  {problem.status.upper():14} {problem.dest_uri}  ({risk})", file=sys.stderr)
    for text in result.manifest_problems:
        print(f"  manifest: {text}", file=sys.stderr)


def _print_restore(result: RestoreResult) -> None:
    if result.already_present:
        print(f"already present with the same content: {result.restored_to}")
    else:
        print(
            f"restored {result.source} -> {result.restored_to} ({fmt_bytes(result.size)}, sha256 {result.sha256[:12]})"
        )


# -------------------------------------------------------------------------------------------------- dispatch


def _dispatch(args: argparse.Namespace) -> int:
    engine = Engine(load_policy(args.policy))
    command = args.command
    if command in ("plan", "archive", "trim", "run"):
        options: dict[str, Any] = {"roots": args.root, "byte_cap": args.byte_cap, "floor_gb": args.floor_gb}
        if command == "plan":
            result = engine.plan(mode=args.mode, purge=args.purge, **options)
        elif command == "archive":
            result = engine.archive(**options)
        else:
            run = engine.trim if command == "trim" else engine.run
            result = run(purge=args.purge, **options)
        if args.json:
            _emit(result.to_dict())
        elif command == "plan":
            _print_plan(result, args.rows)
        else:
            _print_run(result)
        return result.exit_code
    if command == "verify-manifest":
        verified = engine.verify_manifest(quick=args.quick)
        if args.json:
            _emit(verified.to_dict())
        else:
            _print_verify(verified)
        return verified.exit_code
    if command == "restore":
        restored = engine.restore(
            args.target, to=args.to, force=args.force, sha256=args.sha256, preserve_mtime=args.preserve_mtime
        )
        if args.json:
            _emit(asdict(restored))
        else:
            _print_restore(restored)
        return EXIT_OK
    rows = engine.measure(depth=args.depth, csv_path=args.csv, roots=args.root)
    if args.json:
        _emit([asdict(row) for row in rows])
    else:
        ranked = sorted(rows, key=lambda r: (-(r.delta_bytes if r.delta_bytes is not None else -1), -r.bytes, r.folder))
        print(f"measure: {len(rows)} folders recorded")
        for row in ranked[: args.top]:
            delta = "first measurement" if row.delta_bytes is None else f"{row.delta_bytes:+d} B since last"
            print(f"  {fmt_bytes(row.bytes):>10}  {row.files:>7} files  {row.root}/{row.folder}  ({delta})")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on bad usage, 0 on --help/--version
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    try:
        return _dispatch(args)
    except ArchiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError as exc:  # never a traceback: a bad path is a usage error (2), anything else a failure (3)
        error = from_os_error(exc, "I/O error")
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
