"""Regression tests for the ways the tool could be made to delete a source that has no copy anywhere.

Each group names the attack it closes: storage reached under two names, over-broad purge globs, a
trust-the-ledger flag, filesystem roots, non-atomic publishing, and I/O errors that escaped as tracebacks.
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys

import pytest
from helpers import (
    NOW,
    AliasDestination,
    LoopbackDestination,
    make_env,
    make_file,
)

from archive_not_delete import (
    ArchiveError,
    DestinationError,
    LocalDestination,
    Manifest,
    PolicyError,
    RunLock,
    SourceStream,
    StateError,
    policy_from_dict,
)
from archive_not_delete.cli import main
from archive_not_delete.destinations import _fsync_dir
from archive_not_delete.errors import AliasError, from_os_error
from archive_not_delete.policy import PurgeClass, RootConfig, check_purge_glob
from archive_not_delete.util import is_filesystem_root, normalize_policy_path


def no_probes(*dirs):
    return [p for d in dirs for p in d.rglob("*") if ".probe-" in p.name]


def hard_link_or_skip(source, link):
    try:
        os.link(source, link)
    except (OSError, NotImplementedError):
        pytest.skip("hard links are not available here")


# ======================================================================== 1. archive and source on the same storage


def test_alias_destination_is_refused_by_the_layout_probe_and_the_source_survives(env):
    f = env.file("precious.txt", b"the only copy " * 50)
    alias = AliasDestination(env.tmp / "harmless", into=env.root.parent)  # keys land inside the source root
    result = env.engine(destination=alias).run()
    assert f.read_bytes() == b"the only copy " * 50
    assert result.exit_code == 3 and [x.kind for x in result.failures] == ["destination_aliases_source"]
    assert env.events("archived") == [] and env.events("trimmed") == [] and not result.trimmed
    assert no_probes(env.root, env.tmp / "harmless") == []  # the probe is cleaned up either way


def test_layout_probe_also_covers_destinations_with_no_local_path(env):
    f = env.file("precious.txt", b"remote but really local " * 20)
    result = env.engine(destination=LoopbackDestination(env.root.parent)).run()
    assert f.exists() and result.exit_code == 3
    assert result.failures[0].kind == "destination_aliases_source"
    assert no_probes(env.root) == []


def test_probe_is_removed_after_a_normal_run_too(env):
    env.file("a.log", b"data")
    result = env.engine().run()
    assert result.exit_code == 0
    assert no_probes(env.root, env.archive) == []


def test_probe_that_cannot_be_written_stops_the_root(env):
    f = env.file("a.log", b"data")
    env.archive.write_text("a file, not a directory")
    result = env.engine().run()
    assert f.exists() and result.exit_code == 3 and result.failures[0].kind == "destination_error"
    assert result.skipped.get("root_refused", 0) >= 1


def test_reused_identical_object_that_is_the_source_itself_is_refused(env):
    f = env.file("a.log", b"identical because it is the same file")
    engine = env.engine()
    alias = AliasDestination(env.tmp / "harmless", into=env.root.parent)
    with pytest.raises(AliasError, match="same file"):
        engine._store(alias, f, "data/a.log")  # "identical object already there" must not mean "same file"


def test_trim_refuses_when_the_archive_object_is_a_hard_link_of_the_source(env):
    f = env.file("a.log", b"hard linked, so no second copy")
    env.engine().archive()
    stored = env.archive / "data" / "a.log"
    stored.unlink()
    hard_link_or_skip(f, stored)
    result = env.engine().trim()
    assert f.exists() and not result.trimmed
    assert result.exit_code == 3 and result.failures[0].kind == "destination_aliases_source"


def test_trim_refuses_when_the_archive_object_is_a_symlink(env):
    f = env.file("a.log", b"symlinked archive object")
    env.engine().archive()
    stored = env.archive / "data" / "a.log"
    stored.unlink()
    try:
        os.symlink(f, stored)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are not available on this machine")
    result = env.engine().trim()
    assert f.exists() and result.exit_code == 3 and result.failures[0].kind == "destination_aliases_source"


def test_same_file_check_is_conservative(monkeypatch, tmp_path):
    from archive_not_delete.engine import Engine

    a = make_file(tmp_path / "a", b"x")
    b = make_file(tmp_path / "b", b"x")
    assert Engine._same_file(a, b) is False
    assert Engine._same_file(a, tmp_path / "missing") is False

    def denied(*_args):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(os.path, "samefile", denied)
    assert Engine._same_file(a, b) is True  # cannot prove they differ: refuse


def test_duplicate_that_is_a_hard_link_of_its_keeper_is_not_purged(tmp_path):
    cls = {"name": "dupes", "kind": "duplicate", "globs": ["copies/**"]}
    env = make_env(tmp_path, root={"purge": [cls]})
    keeper = env.file("copies/a.bin", b"one inode", age_days=40)
    twin = env.root / "copies" / "b.bin"
    hard_link_or_skip(keeper, twin)  # two names, one inode: not an independent duplicate
    result = env.engine().trim(purge=True)  # trim mode: only the purge step runs, the keeper is not archived
    assert keeper.exists() and twin.exists() and not result.purged
    assert result.skipped.get("duplicate_is_same_file") == 1


@pytest.mark.skipif(os.name != "nt", reason="administrative network-share aliases are a Windows feature")
def test_unc_alias_of_the_archive_folder_cannot_delete_the_only_copy(tmp_path):
    alias = tmp_path / "alias"
    docs = alias / "docs"
    docs.mkdir(parents=True)
    precious = make_file(docs / "precious.txt", b"only copy of the thesis\n" * 100, age_days=90)
    drive, rest = os.path.splitdrive(str(alias))
    unc = "\\\\localhost\\" + drive[0].lower() + "$" + rest
    if not os.path.isdir(unc):
        pytest.skip("the administrative share is not reachable on this machine")
    policy = policy_from_dict(
        {
            "manifest": str(tmp_path / "m.jsonl"),
            "destination": {"type": "local", "path": unc},
            "root": [{"name": "docs", "path": str(docs), "min_age": "1d"}],
        },
        tmp_path,
    )
    from archive_not_delete import Engine

    result = Engine(policy, now=lambda: NOW).run()
    assert precious.read_bytes() == b"only copy of the thesis\n" * 100
    assert result.exit_code == 3 and not result.trimmed


# ============================================================================== 2. purge globs and the default


@pytest.mark.parametrize(
    "glob",
    [
        "*",
        "**",
        "*.*",
        "**/*",
        "?*",
        "*/*",
        "**/**",
        ".*",
        "[a-z]*",
        "*?",
        "**/*.*",
        "a*",
        "*.t*",
        "/",
        "",
        "*e*/**",
        "**/?*a*/**",
        "cache*/**",  # one literal character is not an anchor
        "Thumbs.db",
        "core",
        "*~",
        "*.t?p",
        "**/*.log*",
    ],
)
def test_wildcard_only_purge_globs_are_refused(tmp_path, glob):
    with pytest.raises(PolicyError):
        make_env(tmp_path, root={"purge": [{"name": "c", "kind": "cache", "globs": [glob]}]})


@pytest.mark.parametrize(
    "glob",
    [
        "*.tmp",
        "*.pyc",
        "*.tar.gz",
        "cache/**",
        "**/__pycache__/**",
        "**/.cache/**",
        "tmp/*.log",
        "**/old/*.bin",
    ],
)
def test_specific_purge_globs_are_accepted(glob):
    check_purge_glob(glob, "test")


def test_the_broad_glob_attack_no_longer_gets_as_far_as_a_policy(tmp_path):
    docs = tmp_path / "docs"
    make_file(docs / "thesis.docx", b"irreplaceable", age_days=400)
    with pytest.raises(PolicyError, match="too broad"):
        policy_from_dict(
            {
                "destination": {"type": "local", "path": str(tmp_path / "arch")},
                "root": [{"name": "d", "path": str(docs), "purge": [{"name": "c", "kind": "cache", "globs": ["*"]}]}],
            },
            tmp_path,
        )
    assert (docs / "thesis.docx").exists()


def test_cli_purge_is_opt_in(env, capsys):
    import json

    policy = env.tmp / "p.json"
    policy.write_text(
        json.dumps(
            {
                "manifest": str(env.manifest),
                "destination": {"type": "local", "path": str(env.archive)},
                "root": [
                    {
                        "name": "data",
                        "path": str(env.root),
                        "include": ["*.log"],
                        "purge": [{"name": "c", "kind": "cache", "globs": ["*.pyc"]}],
                    }
                ],
            }
        )
    )
    f = make_file(env.root / "x.pyc", b"b", age_days=400)
    os.utime(f, (1_000_000_000, 1_000_000_000))
    assert main(["run", "--policy", str(policy)]) == 0 and f.exists()
    assert main(["trim", "--policy", str(policy)]) == 0 and f.exists()
    assert main(["run", "--policy", str(policy), "--purge"]) == 0 and not f.exists()
    assert "purged without a copy" in capsys.readouterr().out


# ======================================================================== 4. filesystem and drive roots refused


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C:\\", True),
        ("C:/", True),
        ("c:", True),
        ("\\", True),
        ("\\\\?\\C:\\", True),
        ("\\\\?\\UNC\\server\\share", True),
        ("\\\\server\\share\\", True),
        ("\\\\server\\share\\folder", False),
        ("C:\\data", False),
        ("\\\\?\\C:\\data\\logs", False),
        ("relative\\path", False),
    ],
)
def test_windows_filesystem_roots(text, expected):
    assert is_filesystem_root(text, windows=True) is expected


@pytest.mark.parametrize(
    ("text", "expected"), [("/", True), ("//", True), ("/home", False), ("/a/..", True), ("data", False)]
)
def test_posix_filesystem_roots(text, expected):
    assert is_filesystem_root(text, windows=False) is expected


def test_policy_refuses_a_root_that_is_a_filesystem_root(tmp_path):
    for bad in ("/", os.path.abspath(os.sep)):
        with pytest.raises(PolicyError, match="root of a filesystem"):
            policy_from_dict(
                {"destination": {"type": "local", "path": str(tmp_path / "a")}, "root": [{"name": "all", "path": bad}]},
                tmp_path,
            )


def test_a_root_config_cannot_be_built_directly_on_a_filesystem_root(tmp_path):
    with pytest.raises(PolicyError):
        RootConfig(name="all", path=type(tmp_path)(os.path.abspath(os.sep)))
    assert RootConfig(name="ok", path=tmp_path).name == "ok"


@pytest.mark.skipif(os.name != "nt", reason="drive letters and extended paths are Windows-only")
@pytest.mark.parametrize("bad", ["C:\\", "\\\\?\\C:\\", "//?/C:/", "\\\\?\\UNC\\localhost\\c$"])
def test_windows_policy_refuses_drive_and_share_roots(tmp_path, bad):
    with pytest.raises(PolicyError, match="root of a filesystem"):
        policy_from_dict(
            {"destination": {"type": "local", "path": str(tmp_path / "a")}, "root": [{"name": "all", "path": bad}]},
            tmp_path,
        )


# ============================================================================ 5. atomic no-overwrite publishing


def stream(data):
    import io

    return SourceStream(io.BytesIO(data))


def test_put_cannot_overwrite_even_when_the_target_appears_between_check_and_publish(tmp_path, monkeypatch):
    dest = LocalDestination(tmp_path / "arch")
    real_link = os.link

    def racing_link(src, dst, *args, **kwargs):
        with open(dst, "wb") as handle:  # another writer wins the race
            handle.write(b"the other writer's object")
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(DestinationError, match="overwrite"):
        dest.put(stream(b"mine"), "k")
    assert (tmp_path / "arch" / "k").read_bytes() == b"the other writer's object"
    assert [p for p in (tmp_path / "arch").rglob("*") if ".part-" in p.name] == []


def test_publish_leaves_no_temp_file_behind(tmp_path):
    dest = LocalDestination(tmp_path / "arch")
    dest.put(stream(b"data"), "a/b")
    assert [p.name for p in (tmp_path / "arch").rglob("*") if p.is_file()] == ["b"]


def test_put_flushes_the_parent_directory(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("archive_not_delete.destinations._fsync_dir", lambda path: seen.append(path))
    LocalDestination(tmp_path / "arch").put(stream(b"data"), "deep/er/k")
    assert seen == [tmp_path / "arch" / "deep" / "er"]


@pytest.mark.skipif(os.name == "nt", reason="directory fsync is a POSIX operation")
def test_fsync_dir_works_on_a_real_directory(tmp_path):
    _fsync_dir(tmp_path)
    _fsync_dir(tmp_path / "missing")  # best effort, never raises


def test_filesystem_without_hard_links(tmp_path, monkeypatch):
    def no_links(*_args, **_kwargs):
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    dest = LocalDestination(tmp_path / "arch")
    if os.name == "nt":  # Windows rename never replaces, so it stands in for the link
        assert dest.put(stream(b"data"), "k").size == 4
        assert (tmp_path / "arch" / "k").read_bytes() == b"data"
        with pytest.raises(DestinationError, match="overwrite"):
            dest.put(stream(b"second"), "k")
    else:  # elsewhere there is no atomic no-overwrite, so fail closed
        with pytest.raises(DestinationError, match="no-overwrite"):
            dest.put(stream(b"data"), "k")
        assert not (tmp_path / "arch" / "k").exists()


# ==================================================================== 7. I/O errors never escape as tracebacks


def policy_json(env, **override):
    import json

    data = {
        "manifest": str(env.manifest),
        "destination": {"type": "local", "path": str(env.archive)},
        "root": [{"name": "data", "path": str(env.root)}],
    }
    data.update(override)
    path = env.tmp / "p.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_manifest_location_under_a_file_is_a_bad_path_exit_2(env, capsys):
    blocker = env.tmp / "nofile.txt"
    blocker.write_text("x")
    env.file("a.log", b"data")
    policy = policy_json(env, manifest=str(blocker / "m.jsonl"))
    assert main(["run", "--policy", policy]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_the_engine_raises_a_typed_error_not_a_raw_oserror(env):
    blocker = env.tmp / "nofile.txt"
    blocker.write_text("x")
    bad = make_env(env.tmp, manifest=str(blocker / "m.jsonl"))
    with pytest.raises(PolicyError):
        bad.engine().run()


def test_lock_permission_error_is_exit_3(env, monkeypatch, capsys):
    env.file("a.log", b"data")
    real_open = os.open

    def deny_lock(path, *args, **kwargs):
        if str(path).endswith(".lock"):
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_lock)
    assert main(["run", "--policy", policy_json(env)]) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_lock_setup_errors_are_typed(env, monkeypatch):
    def full_disk(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(os, "open", full_disk)
    with pytest.raises(StateError):
        RunLock(env.tmp / "x.lock").acquire()


def test_manifest_append_failure_is_a_typed_error(tmp_path, monkeypatch):
    manifest = Manifest(tmp_path / "m.jsonl")
    manifest.read()

    def full_disk(_fd):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)
    with pytest.raises(StateError):
        manifest.append("purged", root="r", rel="x", source="s", size=1, kind="temp", purged_at="t")


def test_measure_csv_failure_is_typed(env):
    blocker = env.tmp / "blocker"
    blocker.write_text("x")
    with pytest.raises(PolicyError):
        env.engine().measure(csv_path=blocker / "growth.csv")


@pytest.mark.parametrize(
    ("raised", "code"),
    [
        (PermissionError(errno.EACCES, "denied"), 3),
        (OSError(errno.EIO, "input/output error"), 3),
        (FileNotFoundError(errno.ENOENT, "gone"), 2),
        (NotADirectoryError(errno.ENOTDIR, "not a directory"), 2),
    ],
)
def test_cli_never_shows_a_traceback_for_an_oserror(env, monkeypatch, capsys, raised, code):
    from archive_not_delete import Engine

    def boom(self, **_kwargs):
        raise raised

    monkeypatch.setattr(Engine, "verify_manifest", boom)
    assert main(["verify-manifest", "--policy", policy_json(env)]) == code
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_from_os_error_classification():
    assert isinstance(from_os_error(FileExistsError(errno.EEXIST, "x"), "w"), PolicyError)
    assert isinstance(from_os_error(OSError(errno.ENAMETOOLONG, "x"), "w"), PolicyError)
    assert isinstance(from_os_error(OSError(errno.ENOSPC, "x"), "w"), StateError)
    assert isinstance(from_os_error(OSError(errno.ENOSPC, "x"), "w"), ArchiveError)


def test_attack_script_style_run_exits_cleanly_in_a_subprocess(env):
    blocker = env.tmp / "nofile.txt"
    blocker.write_text("x")
    env.file("a.log", b"data")
    policy = policy_json(env, manifest=str(blocker / "m.jsonl"))
    done = subprocess.run(
        [sys.executable, "-m", "archive_not_delete", "run", "--policy", policy],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2 and "Traceback" not in done.stderr


# ======================================================================== 8. extended-length paths are absolute


def test_extended_paths_are_normalised_to_ordinary_absolute_paths():
    assert normalize_policy_path("\\\\?\\C:\\data\\logs", windows=True) == "C:\\data\\logs"
    assert normalize_policy_path("//?/C:/data/logs", windows=True) == "C:\\data\\logs"
    assert normalize_policy_path("\\\\?\\UNC\\srv\\share\\x", windows=True) == "\\\\srv\\share\\x"
    assert normalize_policy_path("C:\\plain", windows=True) == "C:\\plain"
    assert normalize_policy_path("\\\\?\\C:\\data", windows=False) == "\\\\?\\C:\\data"  # only meaningful on Windows


@pytest.mark.skipif(os.name != "nt", reason="extended-length paths are Windows-only")
def test_extended_root_path_is_absolute_not_joined_to_the_policy_folder(tmp_path):
    policy = policy_from_dict(
        {
            "destination": {"type": "local", "path": str(tmp_path / "arch")},
            "root": [{"name": "d", "path": "\\\\?\\" + str(tmp_path / "data")}],
        },
        tmp_path / "somewhere" / "else",
    )
    assert policy.roots[0].path == tmp_path / "data"


def test_a_linked_archive_object_is_refused_even_where_symlinks_cannot_be_created(env, monkeypatch):
    f = env.file("a.log", b"archive object that turns out to be a link")
    env.engine().archive()
    stored = env.archive / "data" / "a.log"
    real_islink = os.path.islink
    monkeypatch.setattr(
        os.path,
        "islink",
        lambda p: (
            True
            if os.path.normcase(str(p)).endswith("a.log")
            and os.path.normcase(str(env.archive)) in os.path.normcase(str(p))
            else real_islink(p)
        ),
    )
    result = env.engine().trim()
    assert stored.exists() and f.exists() and not result.trimmed
    assert result.exit_code == 3 and result.failures[0].kind == "destination_aliases_source"
    assert "link" in result.failures[0].detail


def test_the_one_letter_anchor_attack_no_longer_gets_as_far_as_a_policy(tmp_path):
    root = tmp_path / "home"
    keep = [
        make_file(root / "clients" / "contract.pdf", b"c", age_days=400),
        make_file(root / "personal" / "will.docx", b"w", age_days=400),
    ]
    with pytest.raises(PolicyError, match="too broad"):
        policy_from_dict(
            {
                "destination": {"type": "local", "path": str(tmp_path / "arch")},
                "root": [
                    {"name": "h", "path": str(root), "purge": [{"name": "c", "kind": "cache", "globs": ["*e*/**"]}]}
                ],
            },
            tmp_path,
        )
    assert all(p.exists() for p in keep)


def test_a_purge_class_built_directly_cannot_skip_the_glob_check():
    for bad in ("*", "*e*/**", "cache*/**", "**/*"):
        with pytest.raises(PolicyError, match="too broad"):
            PurgeClass(name="x", kind="cache", globs=(bad,))
    assert PurgeClass(name="x", kind="cache", globs=("*.tmp", "cache/**")).globs == ("*.tmp", "cache/**")
