"""plan: a dry run that explains itself and changes nothing."""

from __future__ import annotations

import pytest
from helpers import make_env, tree, tree_usage

from archive_not_delete import ManifestError, PolicyError


def snapshot(path):
    return sorted(p.relative_to(path).as_posix() for p in path.rglob("*"))


def test_plan_lists_reasons_bytes_and_age(tmp_path):
    env = make_env(tmp_path, root={"include": ["*.log"], "min_size": "1KB"})
    env.file("a.log", b"x" * 2000, age_days=45)
    result = env.engine().plan()
    (item,) = result.items
    assert (item.action, item.size, item.rel) == ("archive", 2000, "a.log")
    text = " | ".join(item.reasons)
    assert "matches '*.log'" in text and "age 45d >= 1d" in text and "size 2.0 KB >= 1.0 KB" in text
    assert result.mode == "plan"


def test_plan_writes_nothing_anywhere(env):
    env.file("a.log", b"data")
    before = snapshot(env.tmp)
    contents = tree(env.root)
    env.engine().plan()
    assert snapshot(env.tmp) == before  # no archive directory, no manifest, no lock file
    assert tree(env.root) == contents


def test_plan_never_connects_to_the_destination(env):
    class Exploding:
        def __getattr__(self, name):
            raise AssertionError(f"plan touched the destination ({name})")

    env.file("a.log")
    assert len(env.engine(destination=Exploding()).plan().items) == 1


@pytest.mark.parametrize(
    ("root", "age_days", "size", "name", "selected"),
    [
        ({}, 5, 10, "a.log", True),
        ({"min_age": "7d"}, 5, 10, "a.log", False),
        ({"min_age": "7d"}, 8, 10, "a.log", True),
        ({"min_size": "100"}, 5, 99, "a.log", False),
        ({"min_size": "100"}, 5, 100, "a.log", True),
        ({"max_size": "100"}, 5, 101, "a.log", False),
        ({"max_size": "100"}, 5, 100, "a.log", True),
        ({"include": ["*.log"]}, 5, 10, "a.txt", False),
        ({"include": ["*.log", "*.txt"]}, 5, 10, "a.txt", True),
        ({"exclude": ["*.log"]}, 5, 10, "a.log", False),
        ({"include": ["sub/*.log"]}, 5, 10, "other/a.log", False),
        ({"include": ["sub/*.log"]}, 5, 10, "sub/a.log", True),
        ({"exclude": ["sub/**"]}, 5, 10, "sub/deep/a.log", False),
        ({"exclude": ["node_modules"]}, 5, 10, "pkg/node_modules/x.js", False),
    ],
)
def test_selection_rules(tmp_path, root, age_days, size, name, selected):
    env = make_env(tmp_path, root=root)
    env.file(name, size, age_days=age_days)
    assert bool(env.engine().plan().items) is selected


def test_skip_counts_explain_what_was_left_out(env):
    env.file("young.log", b"x", age_days=0.1)
    env.file("old.log", b"x", age_days=9)
    result = env.engine().plan()
    assert result.skipped == {"too_young": 1}
    assert [i.rel for i in result.items] == ["old.log"]


def test_plan_modes_preview_the_matching_command(env):
    env.file("a.log", b"one")
    env.engine().archive()
    env.file("b.log", b"two")
    engine = env.engine()
    assert [(i.action, i.rel) for i in engine.plan(mode="archive").items] == [("archive", "b.log")]
    assert [(i.action, i.rel) for i in engine.plan(mode="trim").items] == [("trim", "a.log")]
    assert sorted((i.action, i.rel) for i in engine.plan(mode="run").items) == [("archive", "b.log"), ("trim", "a.log")]


def test_plan_rejects_unknown_mode(env):
    with pytest.raises(PolicyError):
        env.engine().plan(mode="delete-everything")


def test_plan_orders_oldest_first_by_default(env):
    env.file("new.log", b"1", age_days=2)
    env.file("old.log", b"22", age_days=90)
    env.file("mid.log", b"333", age_days=30)
    assert [i.rel for i in env.engine().plan().items] == ["old.log", "mid.log", "new.log"]


def test_plan_can_order_largest_first(tmp_path):
    env = make_env(tmp_path, root={"order": "largest"})
    env.file("small.log", b"1", age_days=90)
    env.file("big.log", b"1" * 500, age_days=2)
    assert [i.rel for i in env.engine().plan().items] == ["big.log", "small.log"]


def test_plan_applies_the_byte_cap_and_lists_deferred(env):
    for i in range(4):
        env.file(f"f{i}.log", b"y" * 100, age_days=10 + i)
    result = env.engine().plan(byte_cap=250)
    assert len(result.items) == 2 and len(result.deferred) == 2
    assert all(d.deferred == "byte_cap" for d in result.deferred)


def test_plan_corrupt_manifest_fails_closed(env):
    env.file("a.log")
    env.manifest.parent.mkdir(parents=True)
    env.manifest.write_text("this is not json\n")
    with pytest.raises(ManifestError):
        env.engine().plan()


def test_plan_projects_free_space_after(tmp_path):
    env = make_env(tmp_path)
    env.file("a.log", b"z" * 800)
    engine = env.engine(disk_usage=tree_usage(env.root, 1000))
    (report,) = engine.plan(floor_gb=0.0000005).floor  # floor = 500 bytes
    assert report.projected and report.free_before == 200 and report.free_after == 1000
    assert report.met


def test_archive_plan_projects_no_space_freed(tmp_path):
    env = make_env(tmp_path)
    env.file("a.log", b"z" * 800)
    engine = env.engine(disk_usage=tree_usage(env.root, 1000))
    (report,) = engine.plan(mode="archive", floor_gb=0.0000005).floor
    assert report.free_after == 200 and not report.met  # archive keeps the source


def test_plan_json_is_serialisable(env):
    import json

    env.file("a.log")
    data = json.dumps(env.engine().plan().to_dict())
    assert '"exit_code": 0' in data
