"""Exception hierarchy. Each class carries the CLI exit code it maps to."""

from __future__ import annotations

import errno


class ArchiveError(Exception):
    """Base class for every error this library raises on purpose."""

    exit_code = 2


class PolicyError(ArchiveError):
    """The policy file is missing, malformed, or asks for something unsafe."""

    exit_code = 2


class RestoreError(ArchiveError):
    """A restore request cannot be honoured (unknown file, target exists)."""

    exit_code = 2


class ManifestError(ArchiveError):
    """The manifest is unreadable, damaged, or its hash chain is broken."""

    exit_code = 3


class DestinationError(ArchiveError):
    """The archive destination is unreachable, unwritable, or refused an operation."""

    exit_code = 3


class SourceError(ArchiveError):
    """A source file could not be read."""

    exit_code = 3


class VerificationError(ArchiveError):
    """A copy did not match what was sent (or what the manifest recorded)."""

    exit_code = 3


class AliasError(ArchiveError):
    """The archive object is the source file itself (or a link to it): there is no independent copy."""

    exit_code = 3


class StateError(ArchiveError):
    """The manifest or lock location cannot be used (permissions, full disk, I/O error)."""

    exit_code = 3


class LockHeldError(ArchiveError):
    """Another run holds the run lock."""

    exit_code = 4


_BAD_PATH_ERRNOS = {errno.ENOENT, errno.ENOTDIR, errno.EEXIST, errno.EINVAL, errno.ENAMETOOLONG, errno.EISDIR}


def from_os_error(exc: OSError, what: str) -> ArchiveError:
    """Turn an OSError from lock/manifest/state handling into a typed error: a bad path is exit 2, anything else 3."""
    message = f"{what}: {exc}"
    bad_path = isinstance(exc, FileNotFoundError | NotADirectoryError | FileExistsError | IsADirectoryError)
    if bad_path or exc.errno in _BAD_PATH_ERRNOS:
        return PolicyError(message)
    return StateError(message)
