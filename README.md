# archive-not-delete

A janitor for disks that fill up, built on one rule:

> **Nothing is deleted unless a verified copy exists elsewhere first.**

"Verified" is specific: the copy was **read back from the archive destination** and its sha256 and size matched what
was sent, and the file on disk **still matches that copy** at the moment it is removed. A copy that fails the check is
never recorded as good and never causes a delete.

Python 3.11+, standard library only. SFTP is an optional extra (`paramiko`), imported lazily.

```
        policy file                         archive destination
   (roots, ages, sizes, caps)         (a directory on another disk, or SFTP)
            |                                         ^
            v                                         | 1. copy
   plan -> candidates --------------------------------+
                                                      | 2. re-read, compare sha256 + size
                                                      | 3. append to the manifest
   source file  <--- 4. re-hash source, re-check copy, then remove ---+
```

Existing tools tend to be either "delete old files" (`find -mtime +30 -delete`) or "back everything up" (a different
job). This is the step in between: move the old, big, rarely-touched files somewhere else, prove the move worked, and
only then free the space.

## Install

Not on PyPI yet. From a checkout:

```bash
pip install .                 # the core: no dependencies
pip install ".[sftp]"         # adds paramiko for SFTP destinations
pip install -e ".[dev]"       # tests and the linter
```

You can also run it in place with `python -m archive_not_delete` from the repository root.

## A policy in 15 lines

```toml
byte_cap = "20GB"                      # most bytes one run will handle
[destination]
type = "local"
path = "/mnt/archive"                  # another disk; must be outside every root
[[root]]
name = "logs"
path = "/var/log/myapp"
include = ["*.log", "*.gz"]
exclude = ["current/**"]
min_age = "14d"
min_size = "1MB"
[[root.purge]]                         # deletable WITHOUT a copy, because the policy says so
name = "scratch"
kind = "temp"
globs = ["*.tmp"]
```

Paths in a policy are relative to the policy file. TOML or JSON (`.json`) both work, with the same keys. Unknown keys are
an error, so a typo such as `min_agee` cannot silently widen a sweep. See [`examples/`](examples) for a fuller policy, an
SFTP policy, and a JSON one.

## Commands

```bash
python -m archive_not_delete plan   --policy policy.toml      # read this first; it changes nothing
python -m archive_not_delete run    --policy policy.toml --floor-gb 50
```

| Command | What it does |
|---|---|
| `plan` | Dry run. Lists every file it would archive, trim or purge, with sizes, ages and the reasons, what the byte cap defers, and projected free space. Writes nothing and never connects to the destination. |
| `archive` | Copies eligible files to the destination and verifies each copy. **Keeps the sources.** Never deletes. |
| `trim` | Removes only sources whose verified copy is recorded in the manifest, re-reading that copy first, every time. |
| `run` | `archive`, verify, then `trim`, file by file, within the byte cap. |
| `verify-manifest` | Re-reads every archived object from the destination and compares sha256 and size. `--quick` checks existence only. |
| `restore` | Copies an archived file back, checking its hash on the way. Never overwrites without `--force`. |
| `measure` | Records per-folder sizes to a CSV so you can see what is growing. |

Useful options: `--root NAME` (repeatable), `--byte-cap 20GB`, `--floor-gb 50`, `--json`, and `--purge`.
`plan --mode archive|trim|run` previews a specific command.

**Purge is off unless you ask.** The `[[root.purge]]` classes in a policy say what *may* be deleted without a copy;
`trim --purge` / `run --purge` (and `plan --purge`, to preview) are what actually do it. Without `--purge` those
files are left alone, and not archived either.

### Disk floor and exit codes

`--floor-gb N` (decimal gigabytes, 10^9 bytes) makes the run report free space before and after for each root and
whether the floor is met.

| Code | Meaning |
|---|---|
| 0 | OK. |
| 1 | The run finished but the floor is still breached, or an operation errored (a source could not be removed, a root was missing). Nothing unsafe happened. |
| 2 | Usage or policy error, or a restore that cannot be honoured. |
| 3 | A copy failed verification, a destination was unwritable, the archive turned out to be the source itself, or the manifest/archive does not match. **Nothing was trimmed on the strength of it.** |
| 4 | Another run holds the lock. |

Code 3 wins over 1. `plan` exits 1 if even the projected result would leave the floor breached.

## The guarantees

A source file is removed only when **all** of these hold at that moment:

1. **A verified copy is recorded.** The manifest has an `archived` record whose sha256 and size came from re-reading
   the destination.
2. **The source still equals that copy.** The file is re-hashed (and its size checked) right before removal; if it
   changed after archiving, it is left alone and reported as `changed_since_archive`.
3. **The copy is still there and still good.** Before every removal the archive object is read back again and must
   exist at the recorded size and hash. There is no flag to skip this, and `run` does it too, even for a copy it
   verified a moment earlier.
4. **The path is genuinely inside a policy root.** No link anywhere along the way; the real path must equal
   `<root>/<relative path>`. A manifest line that points through a link or contains `..` is refused.
5. **The archive copy is genuinely a second copy.** The source and the stored object must not be the same file
   (same device and inode, whatever they are called: a network-share alias, a bind mount, a hard link), and the stored
   object must not be a link. A layout probe backs this up: before touching a root, the tool writes a small file
   through the destination and refuses the root if that file shows up inside the source tree. This works for SFTP too.
6. **Nothing in the policy excludes it.**

And, always:

- A failed or unverified copy is **never** recorded as good and never trims. A source that changed while it was being
  copied is recorded but not trimmed.
- The archive is **never overwritten**. Same name with different content goes to a hash-suffixed name; both are kept.
  Publishing is atomic: the finished temp file is hard-linked into place, which fails if the name exists (Windows
  filesystems without hard links use rename, which never replaces; other filesystems without them are refused).
- A **sweep root can never be a filesystem root**: `/`, a drive such as `C:\`, an extended-length `\\?\C:\`, or a
  network share root are refused when the policy loads. Extended-length paths are treated as absolute paths.
- **Links are never followed**: symbolic links, and on Windows junctions and mount points, are skipped, not entered.
- **Only classes you declare** (`cache`, `temp`, `duplicate`) can be deleted without a copy, and only with `--purge`.
  A purge glob must name something: a literal extension (`*.tmp`), a literal directory (`cache/**`,
  `**/__pycache__/**`) or an exact file name. Wildcard-only patterns such as `*`, `**`, `*.*` or `**/*` are refused
  when the policy loads. Purged files are reported
  separately (`purged`, never `trimmed`), recorded in the manifest, and still respect `exclude`. A duplicate is purged
  only after both files are re-hashed and found identical, and the kept file still exists.
- The **manifest is append-only** JSONL, opened only for append and fsynced per line. Lines are chained
  (`seq` plus the sha256 of the previous line), so an edited, removed or reordered line is detected.
- A **damaged manifest stops the run** (fail closed) rather than guessing.
- **One run at a time**: an operating-system lock that disappears if the process dies, so there is no stale lock file
  to clean up.
- The **byte cap** bounds how much one run handles. A file larger than the cap is reported and never moves.

### Limits - read these

- **A writer racing the final check can lose data.** If another process writes to a file in the microseconds between
  the last check and the removal, those bytes are not in the copy. Sweep files nothing is writing to; that is what
  `min_age` is for.
- **Verification is only as honest as the read-back.** A destination that serves a cached or fabricated read defeats it.
  Bit rot *after* verification is not caught until you run `verify-manifest`; schedule that.
- **Content only.** sha256 and size are verified. Permissions, ownership, ACLs, extended attributes and (by default)
  modification times are not preserved. `restore --preserve-mtime` restores the time.
- **Hard links** are not detected. Trimming one name frees nothing while another name still points at the data.
- **SFTP has no remote fsync.** The protocol gives the client no way to force the server to flush to disk. A copy
  is verified by reading it back, but that read can be served from the server's cache, so a power loss on the server
  just after a run can lose a copy that verified. Run `verify-manifest` again later (for example nightly) to catch
  that. Local destinations do flush the file and, on POSIX, its directory.
- It copies whole files. There is no resume, compression or encryption.

## Destinations

**Local directory** - another disk or a mounted share. It must lie outside every root (the tool refuses overlap, in
either direction, and the layout probe catches the case where two different spellings reach the same storage). Each
copy is written to a temporary name, fsynced, hard-linked into place without replacing anything, and the directory
is flushed on POSIX.

**SFTP** - `pip install ".[sftp]"`. Host keys are verified: an unknown host is **rejected**, never auto-accepted, so add
it to `known_hosts` first. Authenticate with `key_file`, or with `password_env` naming an environment variable; the
password never goes in the policy. The class talks to a small client protocol (the subset of `paramiko.SFTPClient` it
uses), which is how the tests run it against an in-memory fake with no network.

Archive keys are `<root name>/<path relative to the root>`, so the archive mirrors the source layout.

## The manifest

One JSON object per line. `archived` carries what was proven:

```json
{"seq":1,"prev":"0000...","event":"archived","id":"9f2c...","root":"logs","rel":"2026/app.log","source":"/var/log/myapp/2026/app.log","size":1048576,"sha256":"...","mtime_ns":1790000000000000000,"dest_uri":"file:///mnt/archive/logs/2026/app.log","dest_key":"logs/2026/app.log","verified_at":"2026-10-15T08:00:00Z"}
```

`trimmed` (with `trimmed_at`), `purged` (with `kind`, and for duplicates the `sha256` and the `kept` path) and
`restored` events follow. Current state is the fold of the events in order. `verify-manifest` re-checks every object, and
reports a **lost** copy (destination bad *and* source already trimmed) separately from an **at-risk** one (destination
bad, source still on disk).

## Growth measurement

`measure` appends one row per folder to a CSV (`timestamp,root,folder,bytes,files`), for each root and for subfolders
down to `--depth`. It prints the biggest growers since the previous measurement. It counts everything on disk, including
files your `exclude` protects, because a full disk does not care. Run it from cron or Task Scheduler.

## Library use

```python
from archive_not_delete import Engine, load_policy

engine = Engine(load_policy("policy.toml"))
plan = engine.plan()                       # RunResult; nothing written
result = engine.run(floor_gb=50)           # raises LockHeldError if another run is active
print(result.exit_code, result.bytes_trimmed, [m.rel for m in result.purged])
```

## Non-goals

- **Not a backup system.** After a trim, the archive holds the only copy. Keep your own redundancy for the destination.
- **Not deduplicating storage.** `duplicate` purging removes exact copies inside a root; it is not a content store.
- Not a scheduler (use cron, systemd timers or Task Scheduler), not a file synchroniser, no compression or encryption,
  and it never deletes anything from the archive. Empty directories are left behind.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
python -W error -m pytest -q
```

Tests are deterministic (a fixed clock, `tmp_path`, an in-memory SFTP fake). Link tests skip where the platform will not
create links.

## License

MIT. See [LICENSE](LICENSE).
