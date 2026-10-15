"""The sample policies and the README example must stay loadable."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from archive_not_delete import load_policy

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("name", ["policy.toml", "policy-sftp.toml", "policy.json"])
def test_example_policies_load(name):
    policy = load_policy(ROOT / "examples" / name)
    assert policy.roots and policy.destination.type in ("local", "sftp")


def test_example_policy_shows_every_purge_kind():
    policy = load_policy(ROOT / "examples" / "policy.toml")
    kinds = {pc.kind for root in policy.roots for pc in root.purge}
    assert kinds == {"temp", "cache", "duplicate"}
    assert policy.byte_cap == 50_000_000_000 and policy.roots[0].byte_cap == 20_000_000_000


def test_sftp_example_keeps_secrets_out_of_the_file():
    text = (ROOT / "examples" / "policy-sftp.toml").read_text(encoding="utf-8")
    assert "password =" not in text and "ARCHIVE_SFTP_PASSWORD" in text


def test_readme_policy_is_about_fifteen_lines_and_loads(tmp_path):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```toml\n(.*?)```", readme, re.S)
    assert block, "README must contain a toml example"
    lines = block.group(1).rstrip("\n").splitlines()
    assert len(lines) <= 15
    (tmp_path / "policy.toml").write_text(block.group(1), encoding="utf-8")
    assert load_policy(tmp_path / "policy.toml").roots


def test_readme_documents_every_exit_code_and_command():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for command in ("plan", "archive", "trim", "run", "verify-manifest", "restore", "measure"):
        assert f"`{command}`" in readme
    for code in ("| 0 |", "| 1 |", "| 2 |", "| 3 |", "| 4 |"):
        assert code in readme


def test_package_metadata_matches_the_version():
    import tomllib

    from archive_not_delete import __version__

    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == __version__ == "0.1.0"
    assert meta["project"]["dependencies"] == []  # the core is standard library only
    assert meta["project"]["optional-dependencies"]["sftp"] == ["paramiko>=3.4"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [0.1.0]" in changelog


def test_readme_documents_the_sftp_fsync_limit_and_the_purge_opt_in():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    limits = readme.split("### Limits")[1].split("## Destinations")[0]
    assert "no remote fsync" in limits.lower() and "SFTP" in limits
    assert "--purge" in readme and "--trust-manifest" not in readme and "--no-purge" not in readme
