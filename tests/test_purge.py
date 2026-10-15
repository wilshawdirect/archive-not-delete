"""Purge-allowed classes: deleted without a copy only when the policy declares them, and reported separately."""

from __future__ import annotations

import os

import pytest
from helpers import make_env, tree

from archive_not_delete import PolicyError

CACHE = {"name": "bytecode", "kind": "cache", "globs": ["**/__pycache__/**", "*.pyc"]}
TEMP = {"name": "scratch", "kind": "temp", "globs": ["*.tmp"], "min_age": "2d"}
DUPES = {"name": "dupes", "kind": "duplicate", "globs": ["copies/**"]}


def test_nothing_is_deleted_without_a_copy_unless_declared(env):
    f = env.file("work.tmp", b"scratch data")
    result = env.engine().archive()  # no purge class declared: .tmp is just a file
    assert f.exists() and not result.purged
    result = env.engine().run(purge=True)  # even when purge is requested there is nothing declared to purge
    assert not f.exists() and not result.purged  # archived (copy exists), not purged
    assert (env.archive / "data" / "work.tmp").read_bytes() == b"scratch data"


def test_declared_cache_is_deleted_without_a_copy_and_reported_separately(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    pyc = env.file("pkg/__pycache__/mod.cpython-311.pyc", b"bytecode" * 10)
    keep = env.file("pkg/mod.py", b"source")
    result = env.engine().run(purge=True)
    assert not pyc.exists()
    assert [m.rel for m in result.purged] == ["pkg/__pycache__/mod.cpython-311.pyc"]
    assert result.bytes_purged == 80 and result.purged[0].kind == "cache"
    assert not keep.exists()  # the ordinary file was archived and trimmed
    assert all("pyc" not in key for key in tree(env.archive))  # purged files never reach the archive
    assert [r["event"] for r in env.records()].count("purged") == 1
    assert "mod.py" in " ".join(tree(env.archive))


def test_purge_classes_respect_min_age(tmp_path):
    env = make_env(tmp_path, root={"purge": [TEMP]})
    young = env.file("a.tmp", b"x", age_days=1)
    old = env.file("b.tmp", b"y", age_days=5)
    result = env.engine().run(purge=True)
    assert young.exists() and not old.exists()
    assert result.skipped.get("purge_too_young") == 1
    assert tree(env.archive) == {}  # a young temp file is neither purged nor archived


def test_exclude_beats_a_purge_class(tmp_path):
    env = make_env(tmp_path, root={"purge": [TEMP], "exclude": ["important/**"]})
    saved = env.file("important/a.tmp", b"keep")
    env.engine().run(purge=True)
    assert saved.exists()


def test_purge_class_exclude_protects_matching_files(tmp_path):
    env = make_env(tmp_path, root={"purge": [{**TEMP, "min_age": "0s", "exclude": ["precious.tmp"]}]})
    saved = env.file("precious.tmp", b"keep")
    gone = env.file("junk.tmp", b"junk")
    result = env.engine().run(purge=True)
    assert not gone.exists() and [m.rel for m in result.purged] == ["junk.tmp"]
    assert (env.archive / "data" / "precious.tmp").read_bytes() == b"keep"  # archived, never purged outright
    assert not saved.exists()


def test_archive_mode_never_purges(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    f = env.file("x.pyc", b"b")
    result = env.engine().archive()
    assert f.exists() and not result.purged
    assert result.skipped.get("purge_disabled") == 1


def test_purge_is_off_unless_asked_for(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    f = env.file("x.pyc", b"b")
    result = env.engine().run()  # the default: declared classes are NOT run
    assert f.exists() and not result.purged and result.skipped.get("purge_disabled") == 1
    result = env.engine().trim()
    assert f.exists() and not result.purged
    assert [i.action for i in env.engine().plan().items] == []  # nor shown by the default plan
    assert len(env.engine().run(purge=True).purged) == 1  # opt-in
    assert not f.exists()


def test_plan_shows_purge_items_separately(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    env.file("x.pyc", b"b" * 7)
    env.file("a.log", b"a")
    items = env.engine().plan(purge=True).items
    assert sorted((i.action, i.kind) for i in items) == [("archive", None), ("purge", "cache")]
    assert "bytecode" in next(i for i in items if i.action == "purge").reasons[0]


def test_trim_mode_also_runs_declared_purge_classes(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    f = env.file("x.pyc", b"b")
    result = env.engine().trim(purge=True)
    assert not f.exists() and len(result.purged) == 1


def test_purge_byte_cap(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]}, purge_byte_cap="25")
    for i in range(4):
        env.file(f"{i}.pyc", b"p" * 10, age_days=10 + i)
    result = env.engine().run(purge=True)
    assert len(result.purged) == 2 and result.bytes_purged == 20
    assert len(result.deferred) == 2


def test_duplicates_keep_the_oldest_and_purge_the_rest(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    oldest = env.file("copies/a.bin", b"same bytes", age_days=40)
    dup1 = env.file("copies/b.bin", b"same bytes", age_days=20)
    dup2 = env.file("copies/sub/c.bin", b"same bytes", age_days=10)
    result = env.engine().run(purge=True)
    assert not dup1.exists() and not dup2.exists()
    assert len(result.purged) == 2 and all(m.kind == "duplicate" for m in result.purged)
    assert all(m.keep == str(oldest) for m in result.purged)
    rec = env.events("purged")[0]
    assert rec["sha256"] and rec["kept"] == str(oldest)


def test_same_size_different_content_is_not_a_duplicate(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    a = env.file("copies/a.bin", b"aaaa", age_days=40)
    b = env.file("copies/b.bin", b"bbbb", age_days=20)
    result = env.engine().plan()
    assert [i.action for i in result.items] == ["archive", "archive"]
    assert a.exists() and b.exists()


def test_empty_files_are_never_purged_as_duplicates(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    env.file("copies/a", b"", age_days=40)
    env.file("copies/b", b"", age_days=20)
    assert all(i.action != "purge" for i in env.engine().plan(purge=True).items)


def test_unique_files_in_a_duplicate_class_fall_through_to_archive(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    env.file("copies/only.bin", b"unique", age_days=40)
    items = env.engine().plan(purge=True).items
    assert [(i.action, i.rel) for i in items] == [("archive", "copies/only.bin")]


def test_duplicate_whose_keeper_vanished_is_not_deleted(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    keeper = env.file("copies/a.bin", b"twin", age_days=40)
    twin = env.file("copies/b.bin", b"twin", age_days=20)
    engine = env.engine()
    real_apply = engine._apply

    def vanish_then_apply(*args, **kwargs):
        keeper.unlink()
        return real_apply(*args, **kwargs)

    engine._apply = vanish_then_apply
    result = engine.run(purge=True)
    assert twin.exists() and not result.purged
    assert result.skipped.get("duplicate_keeper_missing") == 1


def test_file_changed_between_plan_and_purge_is_not_deleted(tmp_path):
    env = make_env(tmp_path, root={"purge": [CACHE]})
    f = env.file("x.pyc", b"before")
    engine = env.engine()
    real_apply = engine._apply

    def edit_then_apply(*args, **kwargs):
        f.write_bytes(b"after, and longer")
        return real_apply(*args, **kwargs)

    engine._apply = edit_then_apply
    result = engine.run(purge=True)
    assert f.exists() and result.skipped.get("changed_since_plan") == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "x", "kind": "everything", "globs": ["*"]},
        {"name": "x", "kind": "cache"},
        {"kind": "cache", "globs": ["*"]},
        {"name": "x", "kind": "cache", "globs": ["*"], "surprise": 1},
    ],
)
def test_purge_class_validation(tmp_path, bad):
    with pytest.raises(PolicyError):
        make_env(tmp_path, root={"purge": [bad]})


def _edit_between_plan_and_apply(engine, edits):
    real_apply = engine._apply

    def apply(*args, **kwargs):
        edits()
        return real_apply(*args, **kwargs)

    engine._apply = apply


def _same_size_rewrite(path, data):
    stat = path.stat()
    path.write_bytes(data)
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))  # identical size and mtime: only a hash can tell


def test_duplicate_that_diverged_after_planning_is_not_purged(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    env.file("copies/a.bin", b"twin", age_days=40)
    twin = env.file("copies/b.bin", b"twin", age_days=20)
    engine = env.engine()
    _edit_between_plan_and_apply(engine, lambda: _same_size_rewrite(twin, b"DIFF"))
    result = engine.run(purge=True)
    assert twin.read_bytes() == b"DIFF" and not result.purged
    assert result.skipped.get("duplicate_changed") == 1


def test_duplicate_whose_keeper_diverged_after_planning_is_not_purged(tmp_path):
    env = make_env(tmp_path, root={"purge": [DUPES]})
    keeper = env.file("copies/a.bin", b"twin", age_days=40)
    twin = env.file("copies/b.bin", b"twin", age_days=20)
    engine = env.engine()
    _edit_between_plan_and_apply(engine, lambda: _same_size_rewrite(keeper, b"DIFF"))
    result = engine.run(purge=True)
    assert twin.read_bytes() == b"twin" and not result.purged
    assert result.skipped.get("duplicate_changed") == 1
