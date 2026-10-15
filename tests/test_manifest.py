"""The manifest is append-only, chained, and fails closed."""

from __future__ import annotations

import pytest

from archive_not_delete import Manifest, ManifestError

ARCHIVED = {
    "id": "aaaaaaaaaaaaaaaa",
    "root": "data",
    "rel": "a.log",
    "source": "/data/a.log",
    "size": 5,
    "sha256": "ab" * 32,
    "mtime_ns": 1,
    "dest_uri": "file:///arch/data/a.log",
    "dest_key": "data/a.log",
    "verified_at": "2027-01-01T00:00:00Z",
}


def fresh(tmp_path, name="m.jsonl"):
    manifest = Manifest(tmp_path / name)
    manifest.read()
    return manifest


def test_missing_file_reads_as_empty(tmp_path):
    state = Manifest(tmp_path / "nope.jsonl").read()
    assert state.entries == {} and state.lines == 0


def test_append_and_read_round_trip(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    manifest.append("trimmed", id=ARCHIVED["id"], trimmed_at="2027-01-02T00:00:00Z")
    state = Manifest(tmp_path / "m.jsonl").read()
    entry = state.entries[ARCHIVED["id"]]
    assert entry.sha256 == ARCHIVED["sha256"] and entry.trimmed and entry.trimmed_at == "2027-01-02T00:00:00Z"
    assert state.lines == 2


def test_lines_are_chained_with_seq_and_prev(tmp_path):
    manifest = fresh(tmp_path)
    first = manifest.append("archived", **ARCHIVED)
    second = manifest.append("trimmed", id=ARCHIVED["id"], trimmed_at="t")
    assert (first["seq"], second["seq"]) == (1, 2)
    assert first["prev"] == "0" * 64 and second["prev"] != first["prev"]


def test_file_only_ever_grows_and_earlier_bytes_never_change(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    snapshot = (tmp_path / "m.jsonl").read_bytes()
    manifest.append("trimmed", id=ARCHIVED["id"], trimmed_at="t")
    grown = (tmp_path / "m.jsonl").read_bytes()
    assert grown.startswith(snapshot) and len(grown) > len(snapshot)


def test_a_new_manifest_object_continues_the_chain(tmp_path):
    fresh(tmp_path).append("archived", **ARCHIVED)
    second = Manifest(tmp_path / "m.jsonl")
    second.read()
    second.append("trimmed", id=ARCHIVED["id"], trimmed_at="t")
    assert Manifest(tmp_path / "m.jsonl").read().lines == 2  # strict read: chain intact


def test_editing_a_line_breaks_the_chain(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    manifest.append("trimmed", id=ARCHIVED["id"], trimmed_at="t")
    path = tmp_path / "m.jsonl"
    path.write_bytes(path.read_bytes().replace(b'"size":5', b'"size":6'))
    with pytest.raises(ManifestError, match="chain"):
        Manifest(path).read()


def test_removing_a_line_is_detected(tmp_path):
    manifest = fresh(tmp_path)
    for n in range(3):
        manifest.append("purged", root="data", rel=f"{n}", source="s", size=1, kind="cache", purged_at="t")
    path = tmp_path / "m.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0] + lines[2])
    with pytest.raises(ManifestError, match="seq"):
        Manifest(path).read()


def test_reordering_lines_is_detected(tmp_path):
    manifest = fresh(tmp_path)
    for n in range(3):
        manifest.append("purged", root="data", rel=f"{n}", source="s", size=1, kind="cache", purged_at="t")
    path = tmp_path / "m.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[1] + lines[0] + lines[2])
    with pytest.raises(ManifestError):
        Manifest(path).read()


def test_invalid_json_line_fails_closed(tmp_path):
    path = tmp_path / "m.jsonl"
    path.write_text("{not json}\n")
    with pytest.raises(ManifestError, match="not valid JSON"):
        Manifest(path).read()


def test_torn_final_line_fails_closed(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    path = tmp_path / "m.jsonl"
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with pytest.raises(ManifestError, match="newline-terminated"):
        Manifest(path).read()


def test_lenient_read_collects_problems_and_still_folds(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    path = tmp_path / "m.jsonl"
    with open(path, "ab") as handle:
        handle.write(b"junk line\n")
    state = Manifest(path).read(strict=False)
    assert ARCHIVED["id"] in state.entries and state.problems


def test_append_refuses_a_record_missing_fields(tmp_path):
    manifest = fresh(tmp_path)
    with pytest.raises(ManifestError, match="missing"):
        manifest.append("archived", id="x")  # no root/rel/...
    assert not (tmp_path / "m.jsonl").exists()


def test_record_with_missing_fields_in_the_file_is_a_problem(tmp_path):
    import json

    path = tmp_path / "m.jsonl"
    rec = {"seq": 1, "prev": "0" * 64, "event": "archived", "id": "x"}
    path.write_bytes(json.dumps(rec).encode() + b"\n")
    with pytest.raises(ManifestError, match="missing fields"):
        Manifest(path).read()


def test_restore_event_resets_trimmed(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    manifest.append("trimmed", id=ARCHIVED["id"], trimmed_at="t1")
    manifest.append("restored", id=ARCHIVED["id"], restored_at="t2")
    entry = Manifest(tmp_path / "m.jsonl").read().entries[ARCHIVED["id"]]
    assert not entry.trimmed and entry.restored_at == "t2"


def test_purged_events_are_listed_separately_from_entries(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("purged", root="data", rel="x.pyc", source="s", size=1, kind="cache", purged_at="t")
    state = Manifest(tmp_path / "m.jsonl").read()
    assert state.entries == {} and len(state.purged) == 1


def test_find_by_id_key_and_source(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    state = Manifest(tmp_path / "m.jsonl").read()
    for needle in (ARCHIVED["id"], "data/a.log", "/data/a.log"):
        assert [e.id for e in state.find(needle)] == [ARCHIVED["id"]]
    assert state.find("data/other.log") == []


def test_unknown_event_cannot_be_appended(tmp_path):
    with pytest.raises(ManifestError):
        fresh(tmp_path).append("deleted", id="x")


def test_unknown_event_in_the_file_is_a_problem(tmp_path):
    manifest = fresh(tmp_path)
    manifest.append("archived", **ARCHIVED)
    path = tmp_path / "m.jsonl"
    # Hand-write a chained line with an event name this version does not know.
    import hashlib
    import json

    last = path.read_bytes().splitlines()[-1]
    rec = {"seq": 2, "prev": hashlib.sha256(last).hexdigest(), "event": "vanished"}
    with open(path, "ab") as handle:
        handle.write(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    with pytest.raises(ManifestError, match="unknown event"):
        Manifest(path).read()


def test_append_creates_parent_directories_and_keeps_unicode(tmp_path):
    manifest = Manifest(tmp_path / "a" / "b" / "m.jsonl")
    manifest.read()
    manifest.append("purged", root="data", rel="café/日本.tmp", source="s", size=1, kind="temp", purged_at="t")
    assert "café" in (tmp_path / "a" / "b" / "m.jsonl").read_text(encoding="utf-8")
    assert Manifest(tmp_path / "a" / "b" / "m.jsonl").read().purged[0]["rel"] == "café/日本.tmp"
