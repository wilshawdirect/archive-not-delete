# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: the API may still change).

## [0.1.0] - 2026-10-15

First release.

### Safety (changed after an adversarial review, before the first release)

- A trim re-reads the archive copy every time; the `--trust-manifest` flag is gone.
- Before every removal the source and the stored object must not be the same file (device and inode), and the stored
  object must not be a link. A layout probe, written through the destination, refuses a root whose archive turns out to
  be inside the source tree (aliases, loopback mounts, an SFTP server on the same host).
- Purge classes run only with `--purge`, and a purge glob must name a literal extension, directory or file;
  wildcard-only globs are refused.
- A sweep root cannot be a filesystem, drive or share root; extended-length paths count as absolute.
- Publishing to a local archive is an atomic hard-link (no overwrite even under a race); the directory is fsynced.
- I/O errors in lock and manifest handling are typed: a bad path exits 2, anything else 3; no tracebacks.

### Added

- Policy files (TOML or JSON): roots with include/exclude globs, minimum age, minimum and maximum size, an order
  (`oldest` or `largest`), a per-root and a global per-run byte cap, and the archive destination. Unknown keys are
  rejected.
- Destinations: a local directory, and SFTP (optional extra `sftp`, `paramiko` imported lazily; host keys are verified
  and unknown hosts rejected). Destinations never overwrite an existing object.
- Verification: every copy is re-read from the destination and compared by sha256 and size before the source is
  trimmed. A failed or unverified copy never trims.
- Commands: `plan`, `archive`, `trim`, `run`, `verify-manifest`, `restore`, `measure`
  (`python -m archive_not_delete`).
- Purge-allowed classes (`cache`, `temp`, `duplicate`) that the policy must declare explicitly; deleted without a copy
  and reported separately. Duplicates are purged only after both files are re-hashed.
- Append-only, hash-chained JSONL manifest (source, size, sha256, destination URI, `verified_at`, `trimmed_at`).
  `verify-manifest` separates a lost copy (source already trimmed) from an at-risk one.
- Disk floor: `--floor-gb`, free space reported before and after. Exit codes 0 ok / 1 floor still breached / 2 usage /
  3 a copy failed verification / 4 another run holds the lock.
- Growth measurement: per-folder sizes appended to a CSV with growth since the last measurement.
- Safety: links and Windows junctions are never followed, a trim re-checks that the path really lies inside its root,
  a run lock (an OS lock, so no stale lock files), long-path support on Windows.
