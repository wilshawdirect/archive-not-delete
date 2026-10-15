"""The command line: every subcommand, the JSON output, and the exit codes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import make_file

from archive_not_delete import __version__
from archive_not_delete.cli import main

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def cli(env):
    """Run the CLI against the env's policy with files old enough for the real clock."""
    policy = env.tmp / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "manifest": str(env.manifest),
                "destination": {"type": "local", "path": str(env.archive)},
                "root": [{"name": "data", "path": str(env.root), "min_age": "1d"}],
                "measure_csv": str(env.tmp / "growth.csv"),
            }
        )
    )

    def run(*args):
        return main([args[0], "--policy", str(policy), *args[1:]])

    run.env = env
    run.policy = policy
    return run


def old_file(env, rel, data=b"payload"):
    path = make_file(env.root / rel, data)
    # make_file ages relative to a fixed 2027 clock; the CLI uses the real clock, so push the mtime far into the past
    import os

    os.utime(path, (1_000_000_000, 1_000_000_000))
    return path


def test_plan_text_output(cli, capsys):
    old_file(cli.env, "a.log", b"x" * 2000)
    assert cli("plan") == 0
    out = capsys.readouterr().out
    assert "plan: 1 to archive (2.0 KB)" in out and "ARCHIVE" in out and "data/a.log" in out and "why:" in out


def test_plan_json_is_parseable_and_complete(cli, capsys):
    old_file(cli.env, "a.log")
    assert cli("plan", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "plan" and data["items"][0]["action"] == "archive" and data["exit_code"] == 0


def test_plan_changes_nothing(cli):
    f = old_file(cli.env, "a.log")
    cli("plan")
    assert f.exists() and not cli.env.archive.exists() and not cli.env.manifest.exists()


def test_archive_then_trim(cli, capsys):
    f = old_file(cli.env, "a.log", b"keep going")
    assert cli("archive") == 0 and f.exists()
    assert (cli.env.archive / "data" / "a.log").read_bytes() == b"keep going"
    assert cli("trim") == 0 and not f.exists()
    assert "trimmed 1" in capsys.readouterr().out


def test_run_end_to_end_and_text_summary(cli, capsys):
    f = old_file(cli.env, "a.log", b"y" * 1500)
    assert cli("run") == 0
    assert not f.exists()
    out = capsys.readouterr().out
    assert "run: archived 1 (1.5 KB), trimmed 1 (1.5 KB)" in out and "free space [data]" in out


def test_run_json(cli, capsys):
    old_file(cli.env, "a.log")
    assert cli("run", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["archived"]) == 1 and len(data["trimmed"]) == 1 and data["floor"][0]["met"] is True


def test_run_with_byte_cap_argument(cli):
    for i in range(3):
        old_file(cli.env, f"f{i}.log", b"z" * 100)
    assert cli("run", "--byte-cap", "250B") == 0
    assert len(list(cli.env.root.glob("*.log"))) == 1


def test_run_only_named_root(cli):
    f = old_file(cli.env, "a.log")
    assert cli("run", "--root", "data") == 0 and not f.exists()


def test_unknown_root_exits_2(cli, capsys):
    assert cli("run", "--root", "nope") == 2
    assert "no root named" in capsys.readouterr().err


def test_unwritable_destination_exits_3(cli, capsys):
    f = old_file(cli.env, "a.log")
    cli.env.archive.write_text("blocker")
    assert cli("run") == 3
    assert f.exists()
    assert "FAILED" in capsys.readouterr().err


def test_verify_manifest_ok_and_failure(cli, capsys):
    old_file(cli.env, "a.log", b"verify me")
    cli("run")
    assert cli("verify-manifest") == 0
    assert "checked 1, ok 1" in capsys.readouterr().out
    (cli.env.archive / "data" / "a.log").unlink()
    assert cli("verify-manifest") == 3
    assert "SOURCE TRIMMED" in capsys.readouterr().err


def test_verify_manifest_quick_and_json(cli, capsys):
    old_file(cli.env, "a.log")
    cli("run")
    capsys.readouterr()
    assert cli("verify-manifest", "--quick", "--json") == 0
    assert json.loads(capsys.readouterr().out)["quick"] is True


def test_restore_command(cli, capsys):
    f = old_file(cli.env, "a.log", b"restore me")
    cli("run")
    assert cli("restore", "data/a.log") == 0
    assert f.read_bytes() == b"restore me"
    assert "restored" in capsys.readouterr().out
    assert cli("restore", "data/a.log") == 0  # identical file already there
    assert "already present" in capsys.readouterr().out


def test_restore_errors_exit_2(cli, capsys):
    assert cli("restore", "data/never-archived.log") == 2
    assert "nothing in the manifest" in capsys.readouterr().err


def test_restore_to_and_json(cli, capsys, tmp_path):
    old_file(cli.env, "a.log", b"elsewhere")
    cli("run")
    capsys.readouterr()
    target = tmp_path / "out.log"
    assert cli("restore", "data/a.log", "--to", str(target), "--json") == 0
    assert json.loads(capsys.readouterr().out)["restored_to"] == str(target) and target.read_bytes() == b"elsewhere"


def test_measure_command(cli, capsys):
    old_file(cli.env, "sub/a.bin", b"m" * 300)
    assert cli("measure") == 0
    out = capsys.readouterr().out
    assert "measure: 2 folders recorded" in out and "first measurement" in out
    assert (cli.env.tmp / "growth.csv").exists()
    old_file(cli.env, "sub/b.bin", b"m" * 200)
    assert cli("measure", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["folder"]: r["delta_bytes"] for r in rows}["sub"] == 200


def test_measure_text_shows_growth(cli, capsys):
    old_file(cli.env, "sub/a.bin", b"m" * 300)
    cli("measure")
    old_file(cli.env, "sub/b.bin", b"m" * 200)
    capsys.readouterr()
    cli("measure", "--depth", "1", "--top", "5")
    assert "+200 B since last" in capsys.readouterr().out


def test_missing_policy_exits_2(tmp_path, capsys):
    assert main(["plan", "--policy", str(tmp_path / "nope.toml")]) == 2
    assert "cannot read policy" in capsys.readouterr().err


def test_bad_policy_exits_2(tmp_path, capsys):
    (tmp_path / "p.json").write_text(json.dumps({"root": []}))
    assert main(["plan", "--policy", str(tmp_path / "p.json")]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["plan"],
        ["run", "--policy"],
        ["plan", "--policy", "x", "--mode", "everything"],
        ["run", "--byte-cap", "x"],
    ],
)
def test_usage_errors_exit_2(argv):
    assert main(argv) == 2


def test_help_and_version_exit_0(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert "exit codes" in capsys.readouterr().out


def test_plan_no_purge_and_rows_options(cli, capsys):
    for i in range(5):
        old_file(cli.env, f"f{i}.log")
    assert cli("plan", "--purge", "--rows", "2") == 0
    assert "... 3 more" in capsys.readouterr().out


def test_trust_manifest_flag_no_longer_exists(cli, capsys):
    f = old_file(cli.env, "a.log")
    cli("archive")
    (cli.env.archive / "data" / "a.log").unlink()
    assert cli("trim", "--trust-manifest") == 2  # unknown option: usage error
    assert "unrecognized arguments" in capsys.readouterr().err
    assert cli("trim") == 3 and f.exists()  # and a plain trim refuses without the archive copy


def test_python_dash_m_entry_point(tmp_path):
    done = subprocess.run(
        [sys.executable, "-m", "archive_not_delete", "--version"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0 and __version__ in done.stdout
    missing = subprocess.run(
        [sys.executable, "-m", "archive_not_delete", "plan", "--policy", str(tmp_path / "nope.toml")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode == 2
