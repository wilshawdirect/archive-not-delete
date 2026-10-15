"""Disk-floor awareness and exit codes 0 / 1 / 3."""

from __future__ import annotations

from helpers import FlipDestination, make_env, tree_usage

from archive_not_delete.cli import main

CAPACITY = 10_000
FLOOR_GB = 0.000002  # 2,000 bytes (the floor is in decimal GB)


def setup(tmp_path, files=5, size=1900):
    env = make_env(tmp_path)
    for i in range(files):
        env.file(f"f{i}.log", bytes([65 + i]) * size, age_days=10 + i)
    return env, env.engine(disk_usage=tree_usage(env.root, CAPACITY))


def test_floor_met_after_a_full_run(tmp_path):
    env, engine = setup(tmp_path)  # 9,500 bytes used, 500 free
    result = engine.run(floor_gb=FLOOR_GB)
    (report,) = result.floor
    assert (report.free_before, report.free_after) == (500, 10_000)
    assert report.met and not report.projected and report.floor_bytes == 2000
    assert result.exit_code == 0


def test_floor_still_breached_exits_1(tmp_path):
    env, engine = setup(tmp_path)
    result = engine.run(floor_gb=FLOOR_GB, byte_cap=1900)  # frees only one file: 2,400 free... then 2 files
    assert result.floor[0].free_after == 2400
    assert result.exit_code == 0  # 2,400 >= 2,000
    env2, engine2 = setup(tmp_path / "second", files=5, size=1900)
    breached = engine2.run(floor_gb=0.000003, byte_cap=1900)  # floor 3,000, only 2,400 free after
    assert breached.floor[0].free_after == 2400 and not breached.floor[0].met
    assert breached.exit_code == 1


def test_archive_mode_frees_nothing_so_the_floor_stays_breached(tmp_path):
    env, engine = setup(tmp_path)
    result = engine.archive(floor_gb=FLOOR_GB)
    assert result.floor[0].free_after == result.floor[0].free_before == 500
    assert result.exit_code == 1


def test_verification_failure_wins_over_floor(tmp_path):
    env, _ = setup(tmp_path)
    engine = env.engine(destination=FlipDestination(env.archive), disk_usage=tree_usage(env.root, CAPACITY))
    result = engine.run(floor_gb=FLOOR_GB)
    assert not result.floor[0].met
    assert result.exit_code == 3


def test_no_floor_means_always_met(tmp_path):
    env, engine = setup(tmp_path)
    result = engine.run()
    assert result.floor[0].floor_bytes is None and result.floor[0].met
    assert result.exit_code == 0


def test_free_space_is_reported_before_and_after_even_without_a_floor(tmp_path):
    env, engine = setup(tmp_path, files=1)
    (report,) = engine.run().floor
    assert report.free_after - report.free_before == 1900


def test_floor_is_reported_per_root(tmp_path):
    from helpers import NOW, make_file

    from archive_not_delete import Engine, policy_from_dict

    data = {
        "manifest": str(tmp_path / "m.jsonl"),
        "destination": {"type": "local", "path": str(tmp_path / "archive")},
        "root": [{"name": "one", "path": str(tmp_path / "one")}, {"name": "two", "path": str(tmp_path / "two")}],
    }
    make_file(tmp_path / "one" / "a.log", b"1" * 100)
    make_file(tmp_path / "two" / "b.log", b"2" * 200)
    engine = Engine(policy_from_dict(data, tmp_path), now=lambda: NOW)
    reports = engine.plan(floor_gb=0.0).floor
    assert [r.root for r in reports] == ["one", "two"]


def write_policy(env):
    import json

    path = env.tmp / "policy.json"
    path.write_text(
        json.dumps(
            {
                "manifest": str(env.manifest),
                "destination": {"type": "local", "path": str(env.archive)},
                "root": [{"name": "data", "path": str(env.root)}],
            }
        )
    )
    return str(path)


def test_cli_exit_1_when_the_floor_is_impossible(env, capsys):
    env.file("a.log", b"data")
    assert main(["run", "--policy", write_policy(env), "--floor-gb", "1e12"]) == 1
    assert "BREACHED" in capsys.readouterr().out


def test_cli_exit_0_when_the_floor_is_trivially_met(env):
    env.file("a.log", b"data")
    assert main(["run", "--policy", write_policy(env), "--floor-gb", "0"]) == 0


def test_cli_plan_exits_1_when_even_the_projection_breaches(env):
    env.file("a.log", b"data")
    assert main(["plan", "--policy", write_policy(env), "--floor-gb", "1e12"]) == 1
