"""Policy files: TOML and JSON, strict keys, relative paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from archive_not_delete import PolicyError, load_policy, policy_from_dict

TOML = """
manifest = "state/manifest.jsonl"
byte_cap = "20GB"
purge_byte_cap = "1GB"
max_failures = 5
measure_csv = "state/growth.csv"

[destination]
type = "local"
path = "../archive"

[[root]]
name = "logs"
path = "logs"
include = ["*.log", "*.gz"]
exclude = ["current/**"]
min_age = "14d"
min_size = "1MB"
max_size = "50GiB"
byte_cap = "5GB"
order = "largest"

[[root.purge]]
name = "scratch"
kind = "temp"
globs = ["*.tmp"]
min_age = "2d"
"""


def test_load_toml(tmp_path):
    (tmp_path / "policy.toml").write_text(TOML, encoding="utf-8")
    policy = load_policy(tmp_path / "policy.toml")
    (root,) = policy.roots
    assert root.name == "logs" and root.path == tmp_path / "logs"  # relative to the policy file
    assert root.include == ("*.log", "*.gz") and root.exclude == ("current/**",)
    assert root.min_age_s == 14 * 86400 and root.min_size == 1_000_000 and root.max_size == 50 * 1024**3
    assert root.byte_cap == 5_000_000_000 and root.order == "largest"
    assert root.purge[0].kind == "temp" and root.purge[0].min_age_s == 2 * 86400
    assert policy.byte_cap == 20_000_000_000 and policy.purge_byte_cap == 1_000_000_000 and policy.max_failures == 5
    assert policy.destination.type == "local"
    assert policy.destination.options["path"] == (tmp_path.parent / "archive")
    assert policy.manifest == tmp_path / "state" / "manifest.jsonl"
    assert policy.lock == tmp_path / "state" / "manifest.jsonl.lock"
    assert policy.measure_csv == tmp_path / "state" / "growth.csv"


def test_json_and_toml_are_equivalent(tmp_path):
    data = {
        "manifest": "m.jsonl",
        "destination": {"type": "local", "path": "arch"},
        "root": [{"name": "d", "path": "d", "min_age": "1d"}],
    }
    (tmp_path / "p.json").write_text(json.dumps(data))
    lines = [
        'manifest = "m.jsonl"',
        "[destination]",
        'type = "local"',
        'path = "arch"',
        "[[root]]",
        'name = "d"',
        'path = "d"',
        'min_age = "1d"',
    ]
    (tmp_path / "p.toml").write_text("\n".join(lines) + "\n")
    assert load_policy(tmp_path / "p.json") == load_policy(tmp_path / "p.toml")


def test_defaults(tmp_path):
    policy = policy_from_dict(
        {"destination": {"type": "local", "path": "a"}, "root": [{"name": "d", "path": "d"}]}, tmp_path
    )
    (root,) = policy.roots
    assert root.include == ("*",) and root.exclude == () and root.min_age_s == 0 and root.min_size == 0
    assert root.max_size is None and root.byte_cap is None and root.order == "oldest"
    assert policy.byte_cap is None and policy.max_failures == 3
    assert policy.manifest == tmp_path / "archive-manifest.jsonl"


def test_absolute_paths_are_kept(tmp_path):
    target = tmp_path / "somewhere"
    policy = policy_from_dict(
        {"destination": {"type": "local", "path": str(target)}, "root": [{"name": "d", "path": str(target / "d")}]},
        Path("unrelated"),
    )
    assert policy.roots[0].path == target / "d"


def test_sftp_destination_options(tmp_path):
    policy = policy_from_dict(
        {
            "destination": {
                "type": "sftp",
                "host": "storage.invalid",
                "username": "svc",
                "path": "/srv/a",
                "key_file": "id_key",
                "password_env": "SECRET_VAR",
            },
            "root": [{"name": "d", "path": "d"}],
        },
        tmp_path,
    )
    options = policy.destination.options
    assert policy.destination.type == "sftp" and options["port"] == 22 and options["path"] == "/srv/a"
    assert options["key_file"] == tmp_path / "id_key" and options["password_env"] == "SECRET_VAR"
    assert "password" not in options  # secrets never live in the policy


BASE = {"destination": {"type": "local", "path": "a"}, "root": [{"name": "d", "path": "d"}]}


def mutate(**changes):
    data = json.loads(json.dumps(BASE))
    for key, value in changes.items():
        if key == "root0":
            data["root"][0].update(value)
        elif key == "dest":
            data["destination"].update(value)
        else:
            data[key] = value
    return data


@pytest.mark.parametrize(
    "data",
    [
        {"root": [{"name": "d", "path": "d"}]},  # no destination
        {"destination": {"type": "local", "path": "a"}},  # no roots
        {"destination": {"type": "local", "path": "a"}, "root": []},
        mutate(surprise=1),  # unknown top-level key
        mutate(root0={"min_agee": "1d"}),  # typo'd key must not be silently ignored
        mutate(root0={"name": "bad name!"}),
        mutate(root0={"name": ""}),
        mutate(root0={"order": "random"}),
        mutate(root0={"min_age": "soon"}),
        mutate(root0={"min_size": "-5"}),
        mutate(root0={"min_size": True}),
        {"destination": {"type": "local", "path": "a"}, "root": [{"name": "d", "path": "d", "include": [1]}]},
        mutate(root0={"include": [""]}),
        mutate(root0={"exclude": ["/"]}),
        mutate(root0={"purge": "nope"}),
        mutate(dest={"type": "ftp"}),
        mutate(dest={"type": "local", "extra": 1}),
        mutate(dest={"type": "sftp"}),
        mutate(max_failures=0),
        mutate(max_failures="three"),
        mutate(byte_cap="a lot"),
        {
            "destination": {"type": "local", "path": "a"},
            "root": [{"name": "d", "path": "d"}, {"name": "d", "path": "e"}],
        },
        {"destination": {"type": "local", "path": "a"}, "root": [{"name": "d"}]},
        [],
    ],
)
def test_invalid_policies_are_rejected(tmp_path, data):
    with pytest.raises(PolicyError):
        policy_from_dict(data, tmp_path)


def test_duplicate_purge_class_names_are_rejected(tmp_path):
    purge = {"name": "x", "kind": "cache", "globs": ["*.pyc"]}
    with pytest.raises(PolicyError, match="unique"):
        policy_from_dict(mutate(root0={"purge": [purge, purge]}), tmp_path)


def test_a_purge_class_without_globs_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match="globs"):
        policy_from_dict(mutate(root0={"purge": [{"name": "x", "kind": "cache"}]}), tmp_path)


def test_unreadable_and_malformed_files(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.toml")
    (tmp_path / "bad.toml").write_text("this = = broken")
    with pytest.raises(PolicyError, match="cannot parse"):
        load_policy(tmp_path / "bad.toml")
    (tmp_path / "bad.json").write_text("{nope")
    with pytest.raises(PolicyError, match="cannot parse"):
        load_policy(tmp_path / "bad.json")
    (tmp_path / "binary.toml").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "binary.toml")


def test_policy_root_lookup(tmp_path):
    policy = policy_from_dict(BASE, tmp_path)
    assert policy.root("d").name == "d"
    with pytest.raises(PolicyError, match="no root named"):
        policy.root("zzz")
