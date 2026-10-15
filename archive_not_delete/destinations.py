"""Archive destinations. A destination stores bytes under a key and can read them back; it never overwrites.

The core is standard library only. SFTP needs the optional ``paramiko`` extra, imported lazily, and the SFTP class
talks to a tiny client protocol (the subset of ``paramiko.SFTPClient`` it uses) so it can be tested without a network.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from .errors import DestinationError, PolicyError, SourceError
from .policy import DestinationSpec
from .util import CHUNK, Digest, fs, is_inside, real_norm, validate_rel


class SourceStream:
    """Wraps an open source file so a read failure is reported as ``SourceError``, not as a destination fault."""

    def __init__(self, handle: BinaryIO, name: str = "source") -> None:
        self._handle = handle
        self._name = name

    def read(self, size: int = CHUNK) -> bytes:
        try:
            return self._handle.read(size)
        except OSError as exc:
            raise SourceError(f"cannot read {self._name}: {exc}") from exc


class Destination(ABC):
    """Contract every destination follows."""

    @abstractmethod
    def uri(self, key: str) -> str:
        """Human-readable location of ``key`` (recorded in the manifest)."""

    @abstractmethod
    def exists(self, key: str) -> bool:
        """True when an object is stored at ``key``."""

    @abstractmethod
    def put(self, stream: SourceStream, key: str) -> Digest:
        """Store the stream under ``key`` (refusing to overwrite) and return the digest of the bytes it sent."""

    @abstractmethod
    def open_read(self, key: str) -> BinaryIO:
        """Open the stored object for reading. Callers use it as a context manager."""

    def digest(self, key: str) -> Digest:
        """Re-read the stored object and hash it. This is the verification read; it never trusts a cached value."""
        sha = hashlib.sha256()
        size = 0
        try:
            with self.open_read(key) as handle:
                while chunk := handle.read(CHUNK):
                    sha.update(chunk)
                    size += len(chunk)
        except (OSError, EOFError) as exc:
            raise DestinationError(f"cannot read back {self.uri(key)}: {exc}") from exc
        return Digest(sha.hexdigest(), size)

    @abstractmethod
    def remove(self, key: str) -> None:
        """Remove an object THIS TOOL just created (the layout probe). The engine never removes archived data."""

    def local_path(self, key: str) -> Path | None:
        """Where the object lives on the local filesystem, or None for a remote destination."""
        return None

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release connections. Default: nothing to release."""


# ------------------------------------------------------------------------------------------------------ local


def _fsync_dir(path: Path) -> None:
    """Flush a directory entry to disk (POSIX). Windows cannot open a directory this way; best effort elsewhere."""
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class LocalDestination(Destination):
    """A directory on another disk (or any mounted path)."""

    def __init__(self, base: str | os.PathLike[str]) -> None:
        self.base = Path(os.path.abspath(base))

    def _path(self, key: str) -> Path:
        try:
            validate_rel(key)
        except PolicyError as exc:
            raise DestinationError(f"unsafe archive key {key!r}") from exc
        path = self.base.joinpath(*key.split("/"))
        if not is_inside(real_norm(path), real_norm(self.base)):
            raise DestinationError(f"archive key {key!r} resolves outside the destination")
        return path

    def uri(self, key: str) -> str:
        return self.base.joinpath(*key.split("/")).as_uri()

    def local_path(self, key: str) -> Path | None:
        return self._path(key)

    def remove(self, key: str) -> None:
        try:
            os.unlink(fs(self._path(key)))
        except OSError as exc:
            raise DestinationError(f"cannot remove {self.uri(key)}: {exc}") from exc

    def _publish(self, tmp: Path, target: Path, key: str) -> None:
        """Move the finished temp file to its final name without ever replacing an existing object.

        A hard link fails if the target exists, which makes "create only if absent" atomic. Where hard links are
        unsupported, Windows' rename (which never replaces) is used; elsewhere we fail closed.
        """
        try:
            os.link(fs(tmp), fs(target))
        except FileExistsError as exc:
            raise DestinationError(f"refusing to overwrite existing archive object {self.uri(key)}") from exc
        except OSError as exc:
            if os.name != "nt":
                raise DestinationError(
                    f"cannot publish {self.uri(key)}: the filesystem has no hard links, so no-overwrite "
                    f"cannot be guaranteed ({exc})"
                ) from exc
            try:
                os.rename(fs(tmp), fs(target))
            except FileExistsError as exists:
                raise DestinationError(f"refusing to overwrite existing archive object {self.uri(key)}") from exists

    def exists(self, key: str) -> bool:
        return os.path.lexists(fs(self._path(key)))

    def put(self, stream: SourceStream, key: str) -> Digest:
        target = self._path(key)
        if os.path.lexists(fs(target)):
            raise DestinationError(f"refusing to overwrite existing archive object {self.uri(key)}")
        tmp = target.with_name(f"{target.name}.part-{uuid.uuid4().hex[:8]}")
        sha = hashlib.sha256()
        size = 0
        try:
            os.makedirs(fs(target.parent), exist_ok=True)
            with open(fs(tmp), "xb") as out:
                while chunk := stream.read(CHUNK):
                    sha.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            self._publish(tmp, target, key)
            _fsync_dir(target.parent)
        except OSError as exc:
            raise DestinationError(f"cannot write {self.uri(key)}: {exc}") from exc
        finally:
            if os.path.lexists(fs(tmp)):
                try:
                    os.unlink(fs(tmp))
                except OSError:
                    pass
        return Digest(sha.hexdigest(), size)

    def open_read(self, key: str) -> BinaryIO:
        try:
            return open(fs(self._path(key)), "rb")
        except OSError as exc:
            raise DestinationError(f"cannot open {self.uri(key)}: {exc}") from exc


# ------------------------------------------------------------------------------------------------------ SFTP


class SftpClient(Protocol):
    """The subset of ``paramiko.SFTPClient`` the destination uses. A fake with these methods works too."""

    def open(self, filename: str, mode: str = "r", bufsize: int = -1) -> Any: ...

    def stat(self, path: str) -> Any: ...

    def mkdir(self, path: str, mode: int = 0o777) -> None: ...

    def rename(self, oldpath: str, newpath: str) -> None: ...

    def remove(self, path: str) -> None: ...

    def close(self) -> None: ...


class SftpDestination(Destination):
    """Remote storage over SFTP. ``client`` is a connected ``paramiko.SFTPClient`` (or a compatible fake)."""

    def __init__(
        self,
        client: SftpClient,
        base: str,
        *,
        label: str = "remote",
        port: int = 22,
        closers: tuple[Any, ...] = (),
    ) -> None:
        self._client = client
        self.base = base.rstrip("/") or "/"
        self.label = label
        self.port = port
        self._closers = closers

    # -- construction from a policy ----------------------------------------------------------------------------

    @classmethod
    def from_options(cls, options: dict[str, Any]) -> SftpDestination:
        """Connect using policy options. Host keys are verified (unknown hosts are rejected, never auto-accepted)."""
        try:
            import paramiko
        except ImportError as exc:
            raise DestinationError(
                "the sftp destination needs paramiko: pip install 'archive-not-delete[sftp]'"
            ) from exc
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        if options.get("known_hosts"):
            ssh.load_host_keys(os.fspath(options["known_hosts"]))
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        password = None
        if options.get("password_env"):
            password = os.environ.get(options["password_env"])
            if password is None:
                raise DestinationError(f"environment variable {options['password_env']} is not set")
        try:
            ssh.connect(
                options["host"],
                port=int(options.get("port", 22)),
                username=options["username"],
                password=password,
                key_filename=os.fspath(options["key_file"]) if options.get("key_file") else None,
                timeout=float(options.get("connect_timeout", 15)),
                allow_agent=not password,
                look_for_keys=not password and not options.get("key_file"),
            )
            client = ssh.open_sftp()
        except Exception as exc:
            ssh.close()
            raise DestinationError(f"cannot connect to {options['host']}: {exc}") from exc
        return cls(client, options["path"], label=options["host"], port=int(options.get("port", 22)), closers=(ssh,))

    # -- helpers -----------------------------------------------------------------------------------------------

    def _remote(self, key: str) -> str:
        try:
            validate_rel(key)
        except PolicyError as exc:
            raise DestinationError(f"unsafe archive key {key!r}") from exc
        return posixpath.join(self.base, key)

    def _makedirs(self, remote_dir: str) -> None:
        missing: list[str] = []
        current = remote_dir
        while current not in ("", "/", "."):
            try:
                self._client.stat(current)
                break
            except FileNotFoundError:
                missing.append(current)
                current = posixpath.dirname(current)
        for path in reversed(missing):
            self._client.mkdir(path)

    def uri(self, key: str) -> str:
        host = self.label if self.port == 22 else f"{self.label}:{self.port}"
        return f"sftp://{host}/{self._remote(key).lstrip('/')}"

    def exists(self, key: str) -> bool:
        try:
            self._client.stat(self._remote(key))
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise DestinationError(f"cannot stat {self.uri(key)}: {exc}") from exc

    def put(self, stream: SourceStream, key: str) -> Digest:
        final = self._remote(key)
        if self.exists(key):
            raise DestinationError(f"refusing to overwrite existing archive object {self.uri(key)}")
        tmp = f"{final}.part-{uuid.uuid4().hex[:8]}"
        sha = hashlib.sha256()
        size = 0
        try:
            self._makedirs(posixpath.dirname(final))
            with self._client.open(tmp, "wb") as out:
                while chunk := stream.read(CHUNK):
                    sha.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
            self._client.rename(tmp, final)
        except OSError as exc:
            self._discard(tmp)
            raise DestinationError(f"cannot write {self.uri(key)}: {exc}") from exc
        except BaseException:
            self._discard(tmp)
            raise
        return Digest(sha.hexdigest(), size)

    def _discard(self, remote_tmp: str) -> None:
        """Remove our own half-written temp file (never an archived object)."""
        try:
            self._client.remove(remote_tmp)
        except OSError:
            pass

    def open_read(self, key: str) -> BinaryIO:
        try:
            return self._client.open(self._remote(key), "rb")
        except OSError as exc:
            raise DestinationError(f"cannot open {self.uri(key)}: {exc}") from exc

    def remove(self, key: str) -> None:
        try:
            self._client.remove(self._remote(key))
        except OSError as exc:
            raise DestinationError(f"cannot remove {self.uri(key)}: {exc}") from exc

    def close(self) -> None:
        for closer in (self._client, *self._closers):
            try:
                closer.close()
            except Exception:  # best effort on shutdown
                pass


def build_destination(spec: DestinationSpec) -> Destination:
    """Create the destination a policy describes."""
    if spec.type == "local":
        return LocalDestination(spec.options["path"])
    if spec.type == "sftp":
        return SftpDestination.from_options(spec.options)
    raise PolicyError(f"unknown destination type {spec.type!r}")
