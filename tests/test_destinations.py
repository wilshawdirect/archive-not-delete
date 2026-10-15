"""Local and SFTP destinations. SFTP is exercised through an in-memory fake client: no network."""

from __future__ import annotations

import hashlib
import io
import sys
import types

import pytest
from fake_sftp import FakeSftp
from helpers import make_env

from archive_not_delete import (
    DestinationError,
    LocalDestination,
    SftpDestination,
    SourceError,
    SourceStream,
)
from archive_not_delete.destinations import build_destination
from archive_not_delete.policy import DestinationSpec


def stream(data: bytes) -> SourceStream:
    return SourceStream(io.BytesIO(data))


# ------------------------------------------------------------------------------------------------- local


def test_local_put_and_digest_round_trip(tmp_path):
    dest = LocalDestination(tmp_path / "arch")
    sent = dest.put(stream(b"hello archive"), "data/sub/a.txt")
    assert sent.sha256 == hashlib.sha256(b"hello archive").hexdigest() and sent.size == 13
    assert dest.exists("data/sub/a.txt") and dest.digest("data/sub/a.txt") == sent
    with dest.open_read("data/sub/a.txt") as handle:
        assert handle.read() == b"hello archive"


def test_local_put_handles_empty_and_multi_chunk_files(tmp_path):
    dest = LocalDestination(tmp_path / "arch")
    assert dest.put(stream(b""), "e").size == 0
    big = b"0123456789" * 300_000  # 3 MB: more than one read chunk
    assert dest.put(stream(big), "big").size == len(big)
    assert dest.digest("big").sha256 == hashlib.sha256(big).hexdigest()


def test_local_refuses_to_overwrite(tmp_path):
    dest = LocalDestination(tmp_path / "arch")
    dest.put(stream(b"first"), "k")
    with pytest.raises(DestinationError, match="overwrite"):
        dest.put(stream(b"second"), "k")
    assert dest.digest("k").size == 5


@pytest.mark.parametrize("key", ["../escape", "/absolute", "a/../../b", "", "a//b", "a/./b", "nul\x00byte"])
def test_local_rejects_unsafe_keys(tmp_path, key):
    dest = LocalDestination(tmp_path / "arch")
    with pytest.raises(DestinationError, match="unsafe"):
        dest.exists(key)


def test_local_put_cleans_up_its_temp_file_when_the_source_fails(tmp_path):
    class Broken:
        def read(self, size=-1):
            raise SourceError("disk gone")

    dest = LocalDestination(tmp_path / "arch")
    with pytest.raises(SourceError):
        dest.put(Broken(), "d/k")
    assert not dest.exists("d/k")
    assert [p for p in (tmp_path / "arch").rglob("*") if p.is_file()] == []  # no .part file left


def test_local_unwritable_destination_raises_destination_error(tmp_path):
    blocker = tmp_path / "arch"
    blocker.write_text("a file, not a directory")
    with pytest.raises(DestinationError, match="cannot write"):
        LocalDestination(blocker).put(stream(b"x"), "k")


def test_local_digest_of_missing_key_is_a_destination_error(tmp_path):
    with pytest.raises(DestinationError):
        LocalDestination(tmp_path).digest("nope")


def test_local_uri_is_a_file_uri(tmp_path):
    assert LocalDestination(tmp_path / "arch").uri("a/b.txt").startswith("file:///")


def test_build_destination_local(tmp_path):
    spec = DestinationSpec("local", {"path": tmp_path})
    assert isinstance(build_destination(spec), LocalDestination)


# -------------------------------------------------------------------------------------------------- sftp


def sftp(base="/srv/archive", **kwargs):
    fake = FakeSftp()
    return fake, SftpDestination(fake, base, label="storage.invalid", **kwargs)


def test_sftp_put_creates_parent_directories_and_verifies(tmp_path):
    fake, dest = sftp()
    sent = dest.put(stream(b"remote bytes"), "data/deep/a.bin")
    assert bytes(fake.files["/srv/archive/data/deep/a.bin"]) == b"remote bytes"
    assert {"/srv", "/srv/archive", "/srv/archive/data", "/srv/archive/data/deep"} <= fake.dirs
    assert dest.digest("data/deep/a.bin") == sent and dest.exists("data/deep/a.bin")


def test_sftp_leaves_no_temp_file_behind(tmp_path):
    fake, dest = sftp()
    dest.put(stream(b"x"), "k")
    assert [p for p in fake.files if ".part-" in p] == []


def test_sftp_uri_format():
    _, dest = sftp()
    assert dest.uri("data/a.bin") == "sftp://storage.invalid/srv/archive/data/a.bin"
    _, custom = sftp(port=2222)
    assert custom.uri("k") == "sftp://storage.invalid:2222/srv/archive/k"


def test_sftp_refuses_to_overwrite():
    fake, dest = sftp()
    dest.put(stream(b"first"), "k")
    with pytest.raises(DestinationError, match="overwrite"):
        dest.put(stream(b"second"), "k")
    assert bytes(fake.files["/srv/archive/k"]) == b"first"


def test_sftp_write_failure_removes_the_temp_file_and_raises():
    fake, dest = sftp()
    fake.fail_after = 5
    with pytest.raises(DestinationError, match="cannot write"):
        dest.put(stream(b"0123456789"), "k")
    assert not dest.exists("k") and [p for p in fake.files if ".part-" in p] == []
    assert any(".part-" in removed for removed in fake.removed)


def test_sftp_source_failure_removes_the_temp_file():
    class Broken:
        def read(self, size=-1):
            raise SourceError("unreadable")

    fake, dest = sftp()
    with pytest.raises(SourceError):
        dest.put(Broken(), "k")
    assert fake.files == {}


@pytest.mark.parametrize("key", ["../x", "/abs", "a/../b"])
def test_sftp_rejects_unsafe_keys(key):
    _, dest = sftp()
    with pytest.raises(DestinationError, match="unsafe"):
        dest.exists(key)


def test_sftp_digest_of_missing_object():
    _, dest = sftp()
    with pytest.raises(DestinationError):
        dest.digest("missing")


def test_sftp_close_closes_the_client_and_the_connection():
    fake = FakeSftp()
    ssh = types.SimpleNamespace(closed=False, close=lambda: setattr(ssh, "closed", True))
    SftpDestination(fake, "/b", closers=(ssh,)).close()
    assert fake.closed and ssh.closed


def test_full_run_through_sftp(env):
    fake = FakeSftp()
    dest = SftpDestination(fake, "/srv/archive", label="storage.invalid")
    f = env.file("logs/a.log", b"remote " * 40)
    result = env.engine(destination=dest).run()
    assert result.exit_code == 0 and not f.exists()
    assert bytes(fake.files["/srv/archive/data/logs/a.log"]) == b"remote " * 40
    assert env.events("archived")[0]["dest_uri"] == "sftp://storage.invalid/srv/archive/data/logs/a.log"
    assert env.engine(destination=dest).verify_manifest().exit_code == 0


def test_sftp_corrupted_copy_is_caught_and_source_kept(env):
    class FlippingSftp(FakeSftp):
        def rename(self, oldpath, newpath):
            super().rename(oldpath, newpath)
            self.files[newpath][3] ^= 0xFF

    fake = FlippingSftp()
    f = env.file("a.log", b"remote data " * 10)
    result = env.engine(destination=SftpDestination(fake, "/arch")).run()
    assert result.exit_code == 3 and f.exists()
    assert result.failures[0].kind == "verification_failed"


def test_sftp_full_disk_means_nothing_is_trimmed(env):
    fake = FakeSftp()
    fake.fail_after = 3
    f = env.file("a.log", b"does not fit " * 5)
    result = env.engine(destination=SftpDestination(fake, "/arch")).run()
    assert result.exit_code == 3 and f.exists() and result.failures[0].kind == "destination_error"


def test_sftp_verify_manifest_catches_a_vanished_object(env):
    fake = FakeSftp()
    dest = SftpDestination(fake, "/arch")
    env.file("a.log", b"will vanish")
    env.engine(destination=dest).run()
    fake.files.clear()
    result = env.engine(destination=dest).verify_manifest()
    assert result.exit_code == 3 and result.problems[0].status == "missing" and result.lost


def test_sftp_restore_round_trip(env):
    fake = FakeSftp()
    dest = SftpDestination(fake, "/arch")
    env.file("a.log", b"bring me back")
    env.engine(destination=dest).run()
    env.engine(destination=dest).restore("data/a.log")
    assert (env.root / "a.log").read_bytes() == b"bring me back"


# ------------------------------------------------------------------------- sftp from policy options


class FakeSSH:
    instances: list[FakeSSH] = []
    fail = False

    def __init__(self):
        self.calls = []
        self.closed = False
        self.policy = None
        FakeSSH.instances.append(self)

    def load_system_host_keys(self):
        self.calls.append("system")

    def load_host_keys(self, path):
        self.calls.append(("known_hosts", path))

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, host, **kwargs):
        self.connect_args = (host, kwargs)
        if FakeSSH.fail:
            raise OSError("connection refused")

    def open_sftp(self):
        return FakeSftp()

    def close(self):
        self.closed = True


class RejectPolicy:
    pass


class AutoAddPolicy:
    pass


@pytest.fixture
def fake_paramiko(monkeypatch):
    module = types.ModuleType("paramiko")
    module.SSHClient = FakeSSH
    module.RejectPolicy = RejectPolicy
    module.AutoAddPolicy = AutoAddPolicy
    monkeypatch.setitem(sys.modules, "paramiko", module)
    FakeSSH.instances = []
    FakeSSH.fail = False
    return module


OPTIONS = {"host": "storage.invalid", "port": 2200, "username": "svc", "path": "/srv/a", "connect_timeout": 7.0}


def test_from_options_rejects_unknown_host_keys(fake_paramiko):
    dest = SftpDestination.from_options({**OPTIONS, "key_file": "/keys/id", "known_hosts": "/keys/kh"})
    (ssh,) = FakeSSH.instances
    assert isinstance(ssh.policy, RejectPolicy) and not isinstance(ssh.policy, AutoAddPolicy)
    assert ("known_hosts", "/keys/kh") in ssh.calls
    host, kwargs = ssh.connect_args
    assert host == "storage.invalid" and kwargs["port"] == 2200 and kwargs["username"] == "svc"
    assert kwargs["key_filename"] == "/keys/id" and kwargs["timeout"] == 7.0 and kwargs["password"] is None
    assert dest.uri("k") == "sftp://storage.invalid:2200/srv/a/k"


def test_from_options_reads_the_password_from_the_environment(fake_paramiko, monkeypatch):
    monkeypatch.setenv("ARCHIVE_TEST_SECRET", "s3cret")
    SftpDestination.from_options({**OPTIONS, "password_env": "ARCHIVE_TEST_SECRET"})
    _, kwargs = FakeSSH.instances[0].connect_args
    assert kwargs["password"] == "s3cret" and kwargs["allow_agent"] is False


def test_from_options_missing_password_variable(fake_paramiko, monkeypatch):
    monkeypatch.delenv("ARCHIVE_TEST_SECRET", raising=False)
    with pytest.raises(DestinationError, match="ARCHIVE_TEST_SECRET"):
        SftpDestination.from_options({**OPTIONS, "password_env": "ARCHIVE_TEST_SECRET"})


def test_from_options_connection_failure_closes_and_raises(fake_paramiko):
    FakeSSH.fail = True
    with pytest.raises(DestinationError, match="cannot connect"):
        SftpDestination.from_options(OPTIONS)
    assert FakeSSH.instances[0].closed


def test_missing_paramiko_gives_a_clear_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", None)  # makes `import paramiko` raise ImportError
    with pytest.raises(DestinationError, match=r"archive-not-delete\[sftp\]"):
        SftpDestination.from_options(OPTIONS)


def test_policy_with_sftp_builds_through_paramiko(fake_paramiko, tmp_path):
    env = make_env(
        tmp_path,
        destination={"type": "sftp", "host": "storage.invalid", "username": "svc", "path": "/srv/a"},
    )
    env.file("a.log", b"x")
    result = env.engine().plan()
    assert len(result.items) == 1 and FakeSSH.instances == []  # plan never connects
    env.engine().archive()
    assert len(FakeSSH.instances) == 1 and FakeSSH.instances[0].closed  # built once, closed after the run
