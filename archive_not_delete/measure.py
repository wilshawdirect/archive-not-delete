"""Growth measurement: per-folder sizes appended to a CSV so you can see what is growing."""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from pathlib import Path

from .scan import ScanStats, walk_files
from .util import Matcher, fs, iso_utc

HEADER = ["timestamp", "root", "folder", "bytes", "files"]


@dataclass
class MeasureRow:
    timestamp: str
    root: str
    folder: str
    bytes: int
    files: int
    delta_bytes: int | None = None  # versus the previous measurement of the same folder, None on the first one


def measure_tree(root: Path, depth: int = 1) -> dict[str, tuple[int, int]]:
    """Sizes of ``root`` (as ``"."``) and of every folder down to ``depth`` levels: ``{folder: (bytes, files)}``."""
    totals: dict[str, list[int]] = {".": [0, 0]}
    for info in walk_files(root, Matcher([]), stats=ScanStats()):
        folders = ["."]
        parts = info.rel.split("/")[:-1]
        folders.extend("/".join(parts[: i + 1]) for i in range(min(depth, len(parts))))
        for folder in folders:
            bucket = totals.setdefault(folder, [0, 0])
            bucket[0] += info.size
            bucket[1] += 1
    return {folder: (b, n) for folder, (b, n) in sorted(totals.items())}


def read_previous(csv_path: Path) -> dict[tuple[str, str], int]:
    """Last recorded byte count per (root, folder). Malformed rows are ignored."""
    previous: dict[tuple[str, str], int] = {}
    try:
        with open(fs(csv_path), newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                try:
                    previous[(row["root"], row["folder"])] = int(row["bytes"])
                except (KeyError, TypeError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    return previous


def append_rows(csv_path: Path, rows: list[MeasureRow]) -> None:
    """Append rows (writing the header first if the file is new) in a single write."""
    os.makedirs(fs(csv_path.parent), exist_ok=True)
    new_file = not os.path.exists(fs(csv_path)) or os.path.getsize(fs(csv_path)) == 0
    with open(fs(csv_path), "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        if new_file:
            writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.timestamp, row.root, row.folder, row.bytes, row.files])


def measure_roots(roots: list[tuple[str, Path]], csv_path: Path, *, now: float, depth: int = 1) -> list[MeasureRow]:
    """Measure every root, append the rows to ``csv_path`` and return them with growth since the last measurement."""
    previous = read_previous(csv_path)
    stamp = iso_utc(now)
    rows: list[MeasureRow] = []
    for name, path in roots:
        for folder, (size, count) in measure_tree(path, depth).items():
            before = previous.get((name, folder))
            rows.append(MeasureRow(stamp, name, folder, size, count, None if before is None else size - before))
    append_rows(csv_path, rows)
    return rows
