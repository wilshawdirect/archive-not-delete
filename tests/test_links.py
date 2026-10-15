"""Links never lead out of a root: not while scanning, not while trimming, not through a forged manifest line."""

from __future__ import annotations

import os

import pytest
from helpers import make_dir_link, make_file

from archive_not_delete import LocalDestination, Manifest, SourceStream
from archive_not_delete.scan import ScanStats, walk_files
from archive_not_delete.util import Matcher


def walk(root):
    stats = ScanStats()
    return [f.rel for f in walk_files(root, Matcher([]), stats=stats)], stats


def test_walk_skips_a_directory_link_that_points_outside(tmp_path):
    outside = tmp_path / "outside"
    make_file(outside / "secret.txt", b"secret")
    root = tmp_path / "data"
    make_file(root / "real.txt", b"real")
    make_dir_link(root / "link", outside)
    found, stats = walk(root)
    assert found == ["real.txt"]
    assert stats.counts["link_skipped"] == 1


def test_walk_skips_a_file_symlink(tmp_path):
    target = make_file(tmp_path / "outside.txt", b"outside")
    root = tmp_path / "data"
    make_file(root / "real.txt", b"real")
    try:
        os.symlink(target, root / "alias.txt")
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are not available on this machine")
    found, stats = walk(root)
    assert found == ["real.txt"] and stats.counts["link_skipped"] == 1


def test_run_never_touches_files_behind_a_link(env, tmp_path):
    outside = tmp_path / "outside"
    secret = make_file(outside / "secret.txt", b"do not touch", age_days=400)
    env.file("real.log", b"real data")
    make_dir_link(env.root / "link", outside)
    result = env.engine().run()
    assert secret.read_bytes() == b"do not touch"
    assert [m.rel for m in result.archived] == ["real.log"]
    assert not any("secret" in key for key in os.listdir(env.archive / "data"))
    assert (env.root / "link").exists()  # the link itself is left alone too


def test_root_given_as_a_link_is_still_swept(tmp_path):
    from helpers import make_env

    real = tmp_path / "real_data"
    make_file(real / "a.log", b"through the root link")
    env = make_env(tmp_path, root={"path": str(tmp_path / "rootlink")})
    make_dir_link(tmp_path / "rootlink", real)
    result = env.engine().run()
    assert not (real / "a.log").exists() and len(result.trimmed) == 1


def forge_entry(env, rel, source, sha, size, dest_key):
    manifest = Manifest(env.manifest)
    manifest.read()
    manifest.append(
        "archived",
        id="f0f0f0f0f0f0f0f0",
        root="data",
        rel=rel,
        source=str(source),
        size=size,
        sha256=sha,
        mtime_ns=0,
        dest_uri="file:///x",
        dest_key=dest_key,
        verified_at="2027-01-01T00:00:00Z",
    )


def test_trim_refuses_a_manifest_entry_that_reaches_through_a_link(env, tmp_path):
    outside = tmp_path / "outside"
    secret = make_file(outside / "secret.txt", b"top secret", age_days=30)
    make_dir_link(env.root / "link", outside)
    dest = LocalDestination(env.archive)
    with open(secret, "rb") as handle:
        sent = dest.put(SourceStream(handle), "data/link/secret.txt")  # a real, valid archive copy exists
    forge_entry(
        env, "link/secret.txt", env.root / "link" / "secret.txt", sent.sha256, sent.size, "data/link/secret.txt"
    )
    result = env.engine().trim()
    assert secret.read_bytes() == b"top secret"
    assert result.skipped.get("escapes_root") == 1 and not result.trimmed


def test_manifest_entry_with_dot_dot_is_ignored(env, tmp_path):
    victim = make_file(tmp_path / "victim.txt", b"victim")
    forge_entry(env, "../victim.txt", victim, "0" * 64, 6, "data/x")
    result = env.engine().trim()
    assert victim.exists()
    assert result.skipped.get("invalid_manifest_entry") == 1


def test_confined_helper_rejects_a_path_that_resolves_elsewhere(env, tmp_path):
    from archive_not_delete.engine import Engine

    outside = tmp_path / "outside"
    make_file(outside / "f.txt", b"f")
    make_dir_link(env.root / "link", outside)
    root = env.policy.roots[0]
    assert Engine._confined(env.root / "link" / "f.txt", root, "link/f.txt") is False
    real = make_file(env.root / "ok" / "f.txt", b"f")
    assert Engine._confined(real, root, "ok/f.txt") is True
