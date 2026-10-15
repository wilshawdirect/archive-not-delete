"""The per-run byte cap."""

from __future__ import annotations

from helpers import NOW, make_env, make_file, tree

from archive_not_delete import Engine, policy_from_dict


def fill(env, count=5, size=100):
    for i in range(count):
        env.file(f"f{i}.log", bytes([65 + i]) * size, age_days=20 + i)


def test_run_respects_the_byte_cap(env):
    fill(env)
    result = env.engine().run(byte_cap=250)
    assert result.bytes_archived <= 250 and result.bytes_trimmed <= 250
    assert len(result.trimmed) == 2 and len(result.deferred) == 3
    assert len(list(env.root.glob("*.log"))) == 3  # the rest are untouched


def test_successive_runs_finish_the_backlog(env):
    fill(env)
    for _ in range(3):
        env.engine().run(byte_cap=250)
    assert list(env.root.glob("*.log")) == []
    assert len(tree(env.archive)) == 5


def test_archive_mode_respects_the_cap(env):
    fill(env)
    result = env.engine().archive(byte_cap=300)
    assert len(result.archived) == 3 and result.bytes_archived == 300


def test_trim_mode_respects_the_cap(env):
    fill(env)
    env.engine().archive()
    result = env.engine().trim(byte_cap=200)
    assert len(result.trimmed) == 2 and len(list(env.root.glob("*.log"))) == 3


def test_file_larger_than_the_cap_is_flagged_and_smaller_ones_still_move(env):
    env.file("huge.log", b"H" * 1000, age_days=90)  # oldest, so it comes first
    env.file("small.log", b"s" * 50, age_days=10)
    result = env.engine().run(byte_cap=100)
    assert (env.root / "huge.log").exists() and not (env.root / "small.log").exists()
    assert [d.deferred for d in result.deferred] == ["larger_than_cap"]


def test_policy_cap_applies_and_the_argument_overrides_it(tmp_path):
    env = make_env(tmp_path, byte_cap="150")
    fill(env, 4)
    assert len(env.engine().plan().items) == 1
    assert len(env.engine().plan(byte_cap=1000).items) == 4


def test_zero_byte_files_always_fit(env):
    env.file("empty.log", b"", age_days=30)
    result = env.engine().run(byte_cap=0)
    assert not (env.root / "empty.log").exists() and not result.deferred


def test_per_root_cap_limits_that_root_only(tmp_path):
    data = {
        "manifest": str(tmp_path / "m.jsonl"),
        "destination": {"type": "local", "path": str(tmp_path / "archive")},
        "root": [
            {"name": "capped", "path": str(tmp_path / "capped"), "byte_cap": "150"},
            {"name": "free", "path": str(tmp_path / "free")},
        ],
    }
    for name in ("capped", "free"):
        for i in range(3):
            make_file(tmp_path / name / f"f{i}.log", b"q" * 100, age_days=10)
    result = Engine(policy_from_dict(data, tmp_path), now=lambda: NOW).run()
    assert len(list((tmp_path / "capped").glob("*.log"))) == 2
    assert list((tmp_path / "free").glob("*.log")) == []
    assert len(result.deferred) == 2


def test_global_cap_is_shared_across_roots(tmp_path):
    data = {
        "byte_cap": "250",
        "manifest": str(tmp_path / "m.jsonl"),
        "destination": {"type": "local", "path": str(tmp_path / "archive")},
        "root": [{"name": "one", "path": str(tmp_path / "one")}, {"name": "two", "path": str(tmp_path / "two")}],
    }
    for name in ("one", "two"):
        for i in range(2):
            make_file(tmp_path / name / f"f{i}.log", b"q" * 100, age_days=10)
    result = Engine(policy_from_dict(data, tmp_path), now=lambda: NOW).run()
    assert result.bytes_trimmed == 200 and len(result.deferred) == 2


def test_only_named_roots_are_swept(tmp_path):
    data = {
        "manifest": str(tmp_path / "m.jsonl"),
        "destination": {"type": "local", "path": str(tmp_path / "archive")},
        "root": [{"name": "one", "path": str(tmp_path / "one")}, {"name": "two", "path": str(tmp_path / "two")}],
    }
    a = make_file(tmp_path / "one" / "a.log", b"1")
    b = make_file(tmp_path / "two" / "b.log", b"2")
    Engine(policy_from_dict(data, tmp_path), now=lambda: NOW).run(roots=["two"])
    assert a.exists() and not b.exists()
