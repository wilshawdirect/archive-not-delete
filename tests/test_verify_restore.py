"""verify-manifest re-checks destinations; restore copies a file back and checks it on the way."""

from __future__ import annotations

import os

import pytest
from helpers import NOW, make_file

from archive_not_delete import ManifestError, RestoreError, RunLock, VerificationError


def archived(env, rel="a.log", data=b"archive me " * 8, run=True):
    env.file(rel, data)
    (env.engine().run if run else env.engine().archive)()
    return data


def copy_of(env, rel="a.log"):
    return env.archive / "data" / rel


# ----------------------------------------------------------------------------------------- verify-manifest


def test_verify_ok_after_a_run(env):
    archived(env)
    result = env.engine().verify_manifest()
    assert (result.checked, result.ok, result.exit_code) == (1, 1, 0)


def test_verify_empty_manifest_is_ok_and_never_connects(env):
    class Exploding:
        def __getattr__(self, name):
            raise AssertionError("connected for nothing")

    result = env.engine(destination=Exploding()).verify_manifest()
    assert result.checked == 0 and result.exit_code == 0


def test_verify_catches_a_missing_destination_file(env):
    archived(env)
    copy_of(env).unlink()
    result = env.engine().verify_manifest()
    assert result.exit_code == 3
    (problem,) = result.problems
    assert problem.status == "missing" and problem.trimmed  # the source is gone too: a real loss
    assert len(result.lost) == 1


def test_missing_copy_with_source_still_present_is_not_counted_lost(env):
    archived(env, run=False)
    copy_of(env).unlink()
    result = env.engine().verify_manifest()
    assert result.exit_code == 3 and result.lost == []


def test_verify_catches_a_flipped_byte(env):
    archived(env)
    data = bytearray(copy_of(env).read_bytes())
    data[5] ^= 0x01
    copy_of(env).write_bytes(bytes(data))
    (problem,) = env.engine().verify_manifest().problems
    assert problem.status == "hash_mismatch"


def test_verify_catches_a_truncated_copy(env):
    archived(env)
    copy_of(env).write_bytes(copy_of(env).read_bytes()[:-3])
    (problem,) = env.engine().verify_manifest().problems
    assert problem.status == "size_mismatch"


def test_quick_verify_checks_existence_only(env):
    archived(env)
    data = bytearray(copy_of(env).read_bytes())
    data[0] ^= 0x01
    copy_of(env).write_bytes(bytes(data))
    assert env.engine().verify_manifest(quick=True).exit_code == 0  # the flip is invisible to --quick
    copy_of(env).unlink()
    assert env.engine().verify_manifest(quick=True).exit_code == 3


def test_verify_reports_a_broken_chain(env):
    archived(env)
    env.manifest.write_bytes(env.manifest.read_bytes().replace(b'"size":88', b'"size":89'))
    result = env.engine().verify_manifest()
    assert result.exit_code == 3 and any("chain" in p for p in result.manifest_problems)


def test_verify_does_not_need_or_take_the_lock(env):
    archived(env)
    with RunLock(env.policy.lock):
        assert env.engine().verify_manifest().exit_code == 0


def test_verify_json_has_a_lost_count(env):
    archived(env)
    copy_of(env).unlink()
    assert env.engine().verify_manifest().to_dict()["lost"] == 1


# ---------------------------------------------------------------------------------------------- restore


def test_restore_round_trip_puts_the_original_bytes_back(env):
    data = archived(env, "logs/a.log")
    original = env.root / "logs" / "a.log"
    assert not original.exists()
    result = env.engine().restore("data/logs/a.log")
    assert original.read_bytes() == data and not result.already_present
    (event,) = env.events("restored")
    assert event["restored_to"] == str(original) and event["sha256"] == result.sha256


def test_restore_by_recorded_source_path_and_by_id(env):
    data = archived(env)
    source = str(env.root / "a.log")
    env.engine().restore(source)
    assert (env.root / "a.log").read_bytes() == data
    (env.root / "a.log").unlink()
    entry_id = env.events("archived")[0]["id"]
    env.engine().restore(entry_id)
    assert (env.root / "a.log").read_bytes() == data


def test_restore_to_another_path_and_into_a_directory(env, tmp_path):
    data = archived(env)
    elsewhere = tmp_path / "recovered" / "copy.log"
    env.engine().restore("data/a.log", to=elsewhere)
    assert elsewhere.read_bytes() == data
    folder = tmp_path / "folder"
    folder.mkdir()
    env.engine().restore("data/a.log", to=folder)
    assert (folder / "a.log").read_bytes() == data


def test_restore_refuses_to_overwrite_different_content(env):
    archived(env)
    target = env.root / "a.log"
    target.write_bytes(b"someone made a new file")
    with pytest.raises(RestoreError, match="--force"):
        env.engine().restore("data/a.log")
    assert target.read_bytes() == b"someone made a new file"
    env.engine().restore("data/a.log", force=True)
    assert target.read_bytes().startswith(b"archive me")


def test_restore_of_identical_existing_file_is_a_noop(env):
    archived(env, run=False)
    before = env.manifest.read_bytes()
    result = env.engine().restore("data/a.log")
    assert result.already_present and env.manifest.read_bytes() == before


def test_restore_picks_the_requested_version(env):
    f = env.file("a.log", b"version one")
    env.engine().run()
    make_file(f, b"version two!", age_days=20)
    env.engine().run()
    versions = env.events("archived")
    first_hash = versions[0]["sha256"]
    out = env.tmp / "out.log"
    env.engine().restore("data/a.log", to=out, sha256=first_hash[:10])
    assert out.read_bytes() == b"version one"
    latest = env.tmp / "latest.log"
    env.engine().restore("data/a.log", to=latest)
    assert latest.read_bytes() == b"version two!"


def test_restore_unknown_target(env):
    with pytest.raises(RestoreError, match="nothing in the manifest"):
        env.engine().restore("data/missing.log")


def test_restore_of_a_corrupted_copy_writes_nothing(env):
    archived(env)
    data = bytearray(copy_of(env).read_bytes())
    data[2] ^= 0xFF
    copy_of(env).write_bytes(bytes(data))
    with pytest.raises(VerificationError):
        env.engine().restore("data/a.log")
    assert not (env.root / "a.log").exists()
    assert [p for p in os.listdir(env.root) if "restore" in p] == []  # no half-written temp file left


def test_restore_can_preserve_the_archived_mtime(env):
    archived(env)
    env.engine().restore("data/a.log", preserve_mtime=True)
    mtime = (env.root / "a.log").stat().st_mtime
    assert abs(mtime - (NOW - 30 * 86400)) < 2


def test_restored_file_is_eligible_for_trim_again(env):
    archived(env)
    env.engine().restore("data/a.log")
    plan = env.engine().plan(mode="trim")
    assert [(i.action, i.rel) for i in plan.items] == [("trim", "a.log")]


def test_restore_refuses_a_non_regular_target(env, tmp_path):
    archived(env)
    (env.root / "a.log").mkdir()
    with pytest.raises(RestoreError, match="not a regular file"):
        env.engine().restore("data/a.log")


def test_restore_in_place_needs_the_root_in_policy(env):
    archived(env)
    manifest_rec = env.records()[0]
    assert manifest_rec["root"] == "data"
    from helpers import make_env

    other = make_env(env.tmp, root={"name": "elsewhere", "path": str(env.tmp / "elsewhere")})
    with pytest.raises(RestoreError, match="--to"):
        other.engine().restore("data/a.log")


def test_corrupt_manifest_stops_a_restore(env):
    archived(env)
    env.manifest.write_bytes(env.manifest.read_bytes().replace(b'"size":88', b'"size":1'))
    with pytest.raises(ManifestError):
        env.engine().restore("data/a.log")
