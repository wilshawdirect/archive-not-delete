"""Growth measurement: per-folder sizes over time, in a CSV."""

from __future__ import annotations

import csv

from helpers import NOW, make_dir_link, make_env, make_file

from archive_not_delete.measure import measure_tree


def rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build(env):
    env.file("top.txt", b"t" * 10)
    env.file("a/x.bin", b"x" * 100)
    env.file("a/b/y.bin", b"y" * 50)
    env.file("c/z.bin", b"z" * 25)


def test_measure_tree_depth_one(env):
    build(env)
    assert measure_tree(env.root, 1) == {".": (185, 4), "a": (150, 2), "c": (25, 1)}


def test_measure_tree_depth_two_and_zero(env):
    build(env)
    assert measure_tree(env.root, 2)["a/b"] == (50, 1)
    assert measure_tree(env.root, 0) == {".": (185, 4)}


def test_measure_writes_a_csv_with_header(env):
    build(env)
    out = env.tmp / "growth.csv"
    env.engine().measure(csv_path=out)
    data = rows(out)
    assert list(data[0].keys()) == ["timestamp", "root", "folder", "bytes", "files"]
    by_folder = {r["folder"]: r for r in data}
    assert by_folder["."]["bytes"] == "185" and by_folder["a"]["files"] == "2"
    assert {r["timestamp"] for r in data} == {"2027-01-15T08:00:00Z"} and {r["root"] for r in data} == {"data"}


def test_second_measurement_appends_and_reports_growth(env):
    build(env)
    out = env.tmp / "growth.csv"
    env.engine().measure(csv_path=out)
    env.file("a/new.bin", b"n" * 400)
    result = env.engine(now=lambda: NOW + 3600).measure(csv_path=out)
    deltas = {r.folder: r.delta_bytes for r in result}
    assert deltas == {".": 400, "a": 400, "c": 0}
    data = rows(out)
    assert len(data) == 6 and data[0]["timestamp"] != data[-1]["timestamp"]
    assert sum(1 for line in out.read_text(encoding="utf-8").splitlines() if line.startswith("timestamp")) == 1


def test_first_measurement_has_no_delta(env):
    build(env)
    assert all(r.delta_bytes is None for r in env.engine().measure(csv_path=env.tmp / "g.csv"))


def test_default_csv_comes_from_the_policy(tmp_path):
    env = make_env(tmp_path, measure_csv=str(tmp_path / "state" / "sizes.csv"))
    env.file("a.txt", b"abc")
    env.engine().measure()
    assert (tmp_path / "state" / "sizes.csv").exists()


def test_measure_does_not_follow_links(env, tmp_path):
    build(env)
    outside = tmp_path / "outside"
    make_file(outside / "huge.bin", b"h" * 5000)
    make_dir_link(env.root / "link", outside)
    assert measure_tree(env.root, 1)["."] == (185, 4)


def test_measure_counts_files_the_policy_would_exclude(tmp_path):
    env = make_env(tmp_path, root={"exclude": ["a/**"]})
    build(env)
    assert measure_tree(env.root, 1)["a"] == (150, 2)  # a full disk does not care about excludes


def test_malformed_csv_rows_are_ignored_when_reading_history(env):
    build(env)
    out = env.tmp / "growth.csv"
    out.write_text(
        "timestamp,root,folder,bytes,files\nbad row\nt,data,.,notanumber,1\nt,data,.,100,1\n", encoding="utf-8"
    )
    result = env.engine().measure(csv_path=out)
    assert {r.folder: r.delta_bytes for r in result}["."] == 85


def test_measure_skips_missing_roots(tmp_path):
    env = make_env(tmp_path)
    env.root.rmdir()
    assert env.engine().measure(csv_path=tmp_path / "g.csv") == []
