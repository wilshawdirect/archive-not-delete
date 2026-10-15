"""Two runs must not race."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from archive_not_delete import LockHeldError, ManifestError, RestoreError, RunLock, run_lock
from archive_not_delete.cli import main

ROOT = Path(__file__).resolve().parent.parent


def test_second_holder_is_refused_then_allowed_after_release(tmp_path):
    path = tmp_path / "run.lock"
    with RunLock(path):
        with pytest.raises(LockHeldError):
            RunLock(path).acquire()
    again = RunLock(path)
    again.acquire()
    again.release()


def test_release_is_idempotent_and_reacquire_on_same_object_is_refused(tmp_path):
    lock = RunLock(tmp_path / "x.lock")
    lock.acquire()
    with pytest.raises(LockHeldError):
        lock.acquire()
    lock.release()
    lock.release()


def test_lock_creates_its_directory_and_leaves_the_file(tmp_path):
    path = tmp_path / "deep" / "er" / "run.lock"
    with run_lock(path):
        assert path.exists()
    assert path.exists()  # never deleted: nothing to go stale


def test_run_is_blocked_while_the_lock_is_held(env):
    f = env.file("a.log", b"data")
    with RunLock(env.policy.lock):
        for call in (env.engine().run, env.engine().archive, env.engine().trim):
            with pytest.raises(LockHeldError):
                call()
        with pytest.raises(LockHeldError):
            env.engine().restore("data/a.log")
    assert f.exists()
    assert env.engine().run().exit_code == 0  # free again afterwards


def test_plan_and_verify_do_not_need_the_lock(env):
    env.file("a.log", b"data")
    with RunLock(env.policy.lock):
        assert len(env.engine().plan().items) == 1
        assert env.engine().verify_manifest().exit_code == 0


def test_cli_exit_code_4_when_locked(env, capsys):
    env.file("a.log", b"data")
    policy_file = env.tmp / "policy.json"
    import json

    policy_file.write_text(
        json.dumps(
            {
                "manifest": str(env.manifest),
                "destination": {"type": "local", "path": str(env.archive)},
                "root": [{"name": "data", "path": str(env.root)}],
            }
        )
    )
    with RunLock(env.policy.lock):
        assert main(["run", "--policy", str(policy_file)]) == 4
    assert "lock" in capsys.readouterr().err


def test_lock_is_released_when_a_run_fails(env):
    env.file("a.log")
    env.manifest.parent.mkdir(parents=True)
    env.manifest.write_text("garbage\n")
    with pytest.raises(ManifestError):
        env.engine().run()
    lock = RunLock(env.policy.lock)
    lock.acquire()
    lock.release()


def test_lock_is_released_when_restore_fails(env):
    with pytest.raises(RestoreError):
        env.engine().restore("nothing/here")
    lock = RunLock(env.policy.lock)
    lock.acquire()
    lock.release()


def test_another_process_holding_the_lock_blocks_us(tmp_path):
    path = tmp_path / "shared.lock"
    code = (
        "import sys; from archive_not_delete import RunLock\n"
        f"lock = RunLock({str(path)!r}); lock.acquire()\n"
        "print('locked', flush=True)\n"
        "sys.stdin.read()\n"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(LockHeldError):
            RunLock(path).acquire()
    finally:
        child.stdin.close()
        child.wait(timeout=30)
        child.stdout.close()
    again = RunLock(path)
    again.acquire()  # the child exited, so the OS released its lock: no stale lock to clean up
    again.release()
