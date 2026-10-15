"""The central guarantee: copy, verify, then trim - and never trim on a failed or unverified copy."""

from __future__ import annotations

import hashlib

import pytest
from helpers import NOW, FlipDestination, TouchDestination, make_env, make_file, tree

from archive_not_delete import LocalDestination, PolicyError


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_happy_path_copy_verify_trim(env):
    a = env.file("logs/a.log", b"alpha" * 100)
    b = env.file("b.log", b"bravo" * 50)
    original = {"logs/a.log": a.read_bytes(), "b.log": b.read_bytes()}
    result = env.engine().run()
    assert result.exit_code == 0
    assert not a.exists() and not b.exists()  # trimmed
    assert tree(env.archive / "data") == original  # byte-identical archive copies
    assert len(result.archived) == 2 and len(result.trimmed) == 2
    assert result.bytes_trimmed == sum(len(v) for v in original.values())


def test_manifest_records_every_step(env):
    f = env.file("a.log", b"hello world")
    env.engine().run()
    archived, trimmed = env.events("archived"), env.events("trimmed")
    assert len(archived) == 1 and len(trimmed) == 1
    rec = archived[0]
    assert rec["sha256"] == sha(b"hello world") and rec["size"] == 11
    assert rec["source"] == str(f) and rec["dest_uri"].startswith("file:")
    assert rec["verified_at"] == "2027-01-15T08:00:00Z"
    assert trimmed[0]["id"] == rec["id"] and trimmed[0]["trimmed_at"] == "2027-01-15T08:00:00Z"
    assert [r["seq"] for r in env.records()] == [1, 2]


def test_archive_mode_keeps_sources(env):
    f = env.file("a.log", b"keep me")
    result = env.engine().archive()
    assert f.exists() and f.read_bytes() == b"keep me"
    assert (env.archive / "data" / "a.log").read_bytes() == b"keep me"
    assert len(result.archived) == 1 and not result.trimmed
    assert env.events("trimmed") == []


def test_trim_removes_only_manifest_backed_sources(env):
    a = env.file("a.log", b"archived first")
    env.engine().archive()
    b = env.file("b.log", b"never archived")
    result = env.engine().trim()
    assert not a.exists()
    assert b.exists()  # no verified copy, so trim leaves it alone
    assert len(result.trimmed) == 1


def test_trim_with_empty_manifest_does_nothing(env):
    f = env.file("a.log")
    result = env.engine().trim()
    assert f.exists() and result.exit_code == 0 and not result.trimmed


def test_second_archive_is_idempotent(env):
    env.file("a.log", b"once")
    env.engine().archive()
    before = env.manifest.read_bytes()
    result = env.engine().archive()
    assert not result.archived
    assert result.skipped.get("already_archived") == 1
    assert env.manifest.read_bytes() == before


def test_run_after_archive_trims_without_copying_again(env):
    f = env.file("a.log", b"x" * 64)
    env.engine().archive()
    objects = tree(env.archive)
    result = env.engine().run()
    assert not f.exists() and len(result.trimmed) == 1 and not result.archived
    assert tree(env.archive) == objects


def test_corrupted_destination_copy_is_detected_and_source_not_trimmed(env):
    f = env.file("a.log", b"precious data " * 20)
    engine = env.engine(destination=FlipDestination(env.archive))
    result = engine.run()
    assert result.exit_code == 3
    assert f.exists() and f.read_bytes() == b"precious data " * 20
    assert [x.kind for x in result.failures] == ["verification_failed"]
    assert env.events("trimmed") == [] and env.events("archived") == []  # a bad copy is never recorded as good
    assert not result.trimmed


def test_corrupted_copy_does_not_block_other_files_below_max_failures(env):
    env.file("a.log", b"aaaa" * 10)
    env.file("b.log", b"bbbb" * 10)
    result = env.engine(destination=FlipDestination(env.archive)).run()
    assert len(result.failures) == 2  # both fail, the run is under max_failures=3, no abort
    assert result.aborted is None


def test_unwritable_destination_trims_nothing_and_exits_3(tmp_path):
    env = make_env(tmp_path)
    f = env.file("a.log", b"data")
    env.archive.write_text("a regular file where the archive directory should be")
    result = env.engine().run()
    assert result.exit_code == 3
    assert f.exists()
    assert result.failures[0].kind == "destination_error"
    assert env.events("trimmed") == [] and env.events("archived") == []


def test_repeated_failures_abort_the_run(tmp_path):
    env = make_env(tmp_path, max_failures=2)
    for i in range(5):
        env.file(f"f{i}.log", b"data %d" % i)
    result = env.engine(destination=FlipDestination(env.archive)).run()  # every copy is corrupted
    assert len(result.failures) == 2
    assert result.aborted and "max_failures" in result.aborted
    assert len(list(env.root.glob("*.log"))) == 5


def test_source_changed_during_copy_is_not_trimmed(env):
    f = env.file("a.log", b"before " * 10)
    engine = env.engine(destination=TouchDestination(env.archive, f))
    result = engine.run()
    assert f.exists()
    assert result.skipped.get("changed_during_copy") == 1
    assert env.events("trimmed") == []
    assert result.exit_code == 0


def test_source_modified_after_archive_is_not_trimmed(env):
    f = env.file("a.log", b"original content")
    env.engine().archive()
    f.write_bytes(b"original content, edited later")
    result = env.engine().trim()
    assert f.exists() and f.read_bytes() == b"original content, edited later"
    assert result.skipped.get("changed_since_archive") == 1


def test_same_size_edit_after_archive_is_caught_by_hash(env):
    f = env.file("a.log", b"AAAAAAAAAA")
    env.engine().archive()
    f.write_bytes(b"BBBBBBBBBB")  # same size, different bytes
    result = env.engine().trim()
    assert f.exists() and not result.trimmed
    assert result.skipped.get("changed_since_archive") == 1


def test_archive_copy_deleted_before_trim_keeps_the_source(env):
    f = env.file("a.log", b"still only copy")
    env.engine().archive()
    (env.archive / "data" / "a.log").unlink()
    result = env.engine().trim()
    assert f.exists()
    assert result.exit_code == 3 and result.failures[0].kind == "destination_missing"


def test_archive_copy_corrupted_before_trim_keeps_the_source(env):
    f = env.file("a.log", b"checked again " * 5)
    env.engine().archive()
    copy = env.archive / "data" / "a.log"
    data = bytearray(copy.read_bytes())
    data[3] ^= 1
    copy.write_bytes(bytes(data))
    result = env.engine().trim()
    assert f.exists()
    assert result.exit_code == 3 and result.failures[0].kind == "verification_failed"


def test_there_is_no_way_to_skip_the_reread(env):
    f = env.file("a.log", b"the ledger alone is not proof")
    env.engine().archive()
    (env.archive / "data" / "a.log").unlink()
    with pytest.raises(TypeError):
        env.engine().trim(trust_manifest=True)  # the flag no longer exists
    result = env.engine().trim()
    assert f.exists() and result.exit_code == 3 and result.failures[0].kind == "destination_missing"


def test_run_rereads_the_copy_right_before_trimming(env):
    class Vanishing(LocalDestination):
        """Verifies fine inside the archive step, then loses the object before the trim step re-reads it."""

        def __init__(self, base):
            super().__init__(base)
            self.reads = 0

        def digest(self, key):
            self.reads += 1
            result = super().digest(key)
            if self.reads == 1:
                self.remove(key)  # the verification read passed; now the object disappears
            return result

    f = env.file("a.log", b"verified, then gone")
    result = env.engine(destination=Vanishing(env.archive)).run()
    assert f.exists() and result.exit_code == 3 and not result.trimmed
    assert result.failures[0].kind == "destination_missing"


def test_same_name_different_content_never_overwrites(env):
    f = env.file("a.log", b"first version")
    env.engine().archive()
    first = (env.archive / "data" / "a.log").read_bytes()
    make_file(f, b"second version, longer", age_days=20)
    result = env.engine().archive()
    assert len(result.archived) == 1
    assert (env.archive / "data" / "a.log").read_bytes() == first  # untouched
    stored = tree(env.archive / "data")
    assert len(stored) == 2 and b"second version, longer" in stored.values()


def test_existing_identical_object_is_reused(env):
    env.file("a.log", b"identical bytes")
    env.engine().archive()
    env.manifest.unlink()  # lose the ledger; the archive object is still there
    result = env.engine().archive()
    assert len(result.archived) == 1
    assert len(tree(env.archive)) == 1  # no duplicate object


def test_excluded_file_with_a_manifest_entry_is_not_trimmed(tmp_path):
    env = make_env(tmp_path)
    f = env.file("keep/a.log", b"protected later")
    env.engine().archive()
    stricter = make_env(tmp_path, root={"exclude": ["keep/**"]})
    result = stricter.engine().trim()
    assert f.exists() and result.skipped.get("excluded") == 1


def test_files_younger_than_min_age_are_left_alone(env):
    young = env.file("new.log", b"fresh", age_days=0.5)
    old = env.file("old.log", b"stale", age_days=3)
    result = env.engine().run()
    assert young.exists() and not old.exists()
    assert result.skipped.get("too_young") == 1


def test_missing_root_is_reported_not_crashed(tmp_path):
    env = make_env(tmp_path)
    env.root.rmdir()
    result = env.engine().run()
    assert result.exit_code == 1 and any("not a directory" in e for e in result.errors)


def test_destination_inside_a_root_is_refused(tmp_path):
    env = make_env(tmp_path, root={"path": str(tmp_path / "data")})
    inside = make_env(tmp_path, destination={"type": "local", "path": str(tmp_path / "data" / "archive")})
    env.file("a.log")
    with pytest.raises(PolicyError, match="overlap"):
        inside.engine().plan()
    with pytest.raises(PolicyError, match="overlap"):
        inside.engine().run()


def test_root_inside_the_destination_is_refused(tmp_path):
    env = make_env(tmp_path, destination={"type": "local", "path": str(tmp_path)})
    with pytest.raises(PolicyError, match="overlap"):
        env.engine().run()


def test_manifest_and_lock_files_inside_a_root_are_never_swept(tmp_path):
    env = make_env(tmp_path, manifest=str(tmp_path / "data" / "m.jsonl"))
    env.file("a.log", b"data")
    env.engine().archive()
    result = env.engine().plan()
    assert all(item.rel != "m.jsonl" and not item.rel.endswith(".lock") for item in result.items)
    assert result.skipped.get("bookkeeping_file", 0) >= 1


def test_injected_local_destination_matches_policy_behaviour(env):
    f = env.file("a.log", b"via injected destination")
    result = env.engine(destination=LocalDestination(env.archive)).run()
    assert result.exit_code == 0 and not f.exists()


def test_now_is_injectable(env):
    env.file("a.log", b"x", age_days=1.5)
    assert len(env.engine().plan().items) == 1
    later = env.engine(now=lambda: NOW + 40 * 86400)
    assert len(later.plan().items) == 1
    earlier = env.engine(now=lambda: NOW - 40 * 86400)
    assert earlier.plan().items == []  # the file is "from the future": not old enough


def test_trim_rechecks_exclusion_even_if_the_plan_missed_it(tmp_path):
    from archive_not_delete import Manifest
    from archive_not_delete.engine import _LazyDestination
    from archive_not_delete.results import RunResult

    env = make_env(tmp_path)
    f = env.file("keep/a.log", b"protected later")
    env.engine().archive()
    stricter = make_env(tmp_path, root={"exclude": ["keep/**"]})
    engine = stricter.engine()
    manifest = Manifest(stricter.manifest)
    entry = next(iter(manifest.read().entries.values()))
    result = RunResult("trim")
    engine._trim_entry(entry, stricter.policy.roots[0], manifest, _LazyDestination(engine), result)
    assert f.exists() and result.skipped == {"excluded": 1} and not result.trimmed


def test_archive_step_refuses_a_path_that_reaches_through_a_link(env, tmp_path):
    from helpers import make_dir_link, make_file

    from archive_not_delete import Manifest
    from archive_not_delete.engine import _LazyDestination
    from archive_not_delete.planner import CapTracker
    from archive_not_delete.results import PlanItem, RunResult

    outside = tmp_path / "outside"
    secret = make_file(outside / "secret.txt", b"not yours", age_days=30)
    make_dir_link(env.root / "link", outside)
    engine = env.engine()
    item = PlanItem("archive", "data", "link/secret.txt", str(env.root / "link" / "secret.txt"), 9, 0, 0.0)
    result = RunResult("run")
    manifest = Manifest(env.manifest)
    manifest.read()
    entry = engine._archive_one(item, env.policy.roots[0], manifest, _LazyDestination(engine), result, CapTracker(None))
    assert entry is None and result.skipped == {"escapes_root": 1}
    assert secret.exists() and not env.archive.exists()


def test_source_changing_between_the_hash_and_the_removal_is_not_removed(env, monkeypatch):
    import archive_not_delete.engine as engine_module

    f = env.file("a.log", b"stable at first")
    env.engine().archive()
    real = engine_module.sha256_file

    def hash_then_change(path):
        digest = real(path)
        with open(path, "ab") as handle:  # a writer sneaks in after the hash, before the unlink
            handle.write(b" and then it grew")
        return digest

    monkeypatch.setattr(engine_module, "sha256_file", hash_then_change)
    result = env.engine().trim()
    assert f.exists() and f.read_bytes().endswith(b"and then it grew")
    assert result.skipped.get("changed_since_archive") == 1 and not result.trimmed


def test_regular_rejects_anything_that_looks_like_a_link(monkeypatch, tmp_path):
    import os
    import stat
    from types import SimpleNamespace

    from archive_not_delete.engine import Engine

    f = make_file(tmp_path / "f.bin", b"data")
    assert Engine._regular(f) is not None
    real = os.lstat

    def pretend_symlink(path, *args, **kwargs):
        st = real(path, *args, **kwargs)
        return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_size=st.st_size, st_mtime_ns=st.st_mtime_ns)

    monkeypatch.setattr(os, "lstat", pretend_symlink)
    assert Engine._regular(f) is None


def test_a_source_swapped_for_a_symlink_after_planning_is_left_alone(env, tmp_path):
    import os

    outside = make_file(tmp_path / "outside.txt", b"outside data", age_days=30)
    f = env.file("a.log", b"will be swapped")
    engine = env.engine()
    real_apply = engine._apply

    def swap_then_apply(*args, **kwargs):
        f.unlink()
        try:
            os.symlink(outside, f)
        except (OSError, NotImplementedError):
            pytest.skip("file symlinks are not available on this machine")
        return real_apply(*args, **kwargs)

    engine._apply = swap_then_apply
    result = engine.run()
    assert outside.read_bytes() == b"outside data" and not result.archived and not result.trimmed
