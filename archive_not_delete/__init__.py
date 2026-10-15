"""archive-not-delete: free disk space safely. Nothing is deleted unless a verified copy exists elsewhere."""

from __future__ import annotations

__version__ = "0.1.0"

from .destinations import Destination, LocalDestination, SftpDestination, SourceStream
from .engine import Engine
from .errors import (
    AliasError,
    ArchiveError,
    DestinationError,
    LockHeldError,
    ManifestError,
    PolicyError,
    RestoreError,
    SourceError,
    StateError,
    VerificationError,
)
from .lock import RunLock, run_lock
from .manifest import Manifest
from .policy import DestinationSpec, Policy, PurgeClass, RootConfig, load_policy, policy_from_dict
from .results import RestoreResult, RunResult, VerifyResult

__all__ = [
    "AliasError",
    "ArchiveError",
    "Destination",
    "DestinationError",
    "DestinationSpec",
    "Engine",
    "LocalDestination",
    "LockHeldError",
    "Manifest",
    "ManifestError",
    "Policy",
    "PolicyError",
    "PurgeClass",
    "RestoreError",
    "RestoreResult",
    "RootConfig",
    "RunLock",
    "RunResult",
    "SftpDestination",
    "SourceError",
    "SourceStream",
    "StateError",
    "VerificationError",
    "VerifyResult",
    "__version__",
    "load_policy",
    "policy_from_dict",
    "run_lock",
]
