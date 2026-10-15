"""Parsing, globbing, hashing and Windows path helpers."""

from __future__ import annotations

import hashlib
import os
import stat
from types import SimpleNamespace

import pytest

from archive_not_delete import PolicyError, SourceError
from archive_not_delete.util import (
    Matcher,
    compile_glob,
    extended,
    fmt_age,
    fmt_bytes,
    is_inside,
    is_link_like,
    iso_utc,
    parse_duration,
    parse_size,
    sha256_file,
    strip_extended,
    validate_rel,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0),
        (1024, 1024),
        ("10", 10),
        ("500MB", 500_000_000),
        ("2GiB", 2 * 1024**3),
        ("1.5KB", 1500),
        (" 3 tb ", 3 * 1000**4),
    ],
)
def test_parse_size(value, expected):
    assert parse_size(value) == expected


@pytest.mark.parametrize("value", ["abc", "-1", "5 parsecs", True, -5, None, [], "MB"])
def test_parse_size_rejects(value):
    with pytest.raises(PolicyError):
        parse_size(value)


@pytest.mark.parametrize(
    ("value", "seconds"),
    [(90, 90), ("90", 90), ("15m", 900), ("12h", 43200), ("14d", 14 * 86400), ("2w", 14 * 86400), ("0.5d", 43200)],
)
def test_parse_duration(value, seconds):
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("value", ["soon", "5y", -1, False, None])
def test_parse_duration_rejects(value):
    with pytest.raises(PolicyError):
        parse_duration(value)


def test_formatting():
    assert fmt_bytes(0) == "0 B" and fmt_bytes(1500) == "1.5 KB" and fmt_bytes(2_500_000) == "2.5 MB"
    assert fmt_bytes(3 * 10**12) == "3.0 TB" and fmt_bytes(12 * 10**15).endswith("TB")
    assert fmt_age(30) == "30s" and fmt_age(300) == "5m" and fmt_age(7200) == "2h" and fmt_age(3 * 86400) == "3d"
    assert iso_utc(0) == "1970-01-01T00:00:00Z"


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.log", "a.log", True),
        ("*.log", "deep/er/a.log", True),  # no slash: matches the name at any depth
        ("*.log", "a.logx", False),
        ("a?.txt", "ab.txt", True),
        ("a?.txt", "abc.txt", False),
        ("[ab].txt", "a.txt", True),
        ("[!ab].txt", "a.txt", False),
        ("[!ab].txt", "c.txt", True),
        ("cache/*", "cache/x", True),
        ("cache/*", "cache/x/y", False),  # * does not cross a slash
        ("cache/**", "cache/x/y/z", True),
        ("cache/**", "other/cache/x", False),  # anchored at the root
        ("**/old/*.bin", "old/a.bin", True),
        ("**/old/*.bin", "x/y/old/a.bin", True),
        ("**/old/*.bin", "x/older/a.bin", False),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("/top.txt", "top.txt", True),
        ("/top.txt", "sub/top.txt", False),
        ("**", "anything/at/all", True),
        ("[abc", "[abc", True),  # an unterminated class is just text
        ("a.b", "aXb", False),  # dots are literal
    ],
)
def test_glob_matching(pattern, path, expected):
    assert Matcher([pattern], case_sensitive=True).matches(path) is expected


def test_matcher_reports_the_matching_pattern():
    matcher = Matcher(["*.tmp", "*.log"], case_sensitive=True)
    assert matcher.which("x/a.log") == "*.log" and matcher.which("a.txt") is None


def test_case_sensitivity_is_configurable():
    assert Matcher(["*.LOG"], case_sensitive=True).matches("a.log") is False
    assert Matcher(["*.LOG"], case_sensitive=False).matches("a.log") is True


def test_directory_matching_and_ancestor_exclusion():
    matcher = Matcher(["cache/**", "node_modules", "*.bak"], case_sensitive=True)
    assert matcher.matches_dir("cache") and matcher.matches_dir("pkg/node_modules") and matcher.matches_dir("x.bak")
    assert not matcher.matches_dir("src")
    assert matcher.excludes("pkg/node_modules/lib/x.js")  # an excluded ancestor excludes the file
    assert matcher.excludes("cache/a/b.txt") and not matcher.excludes("src/a.txt")


def test_empty_matcher_matches_nothing():
    matcher = Matcher([])
    assert not matcher and not matcher.matches("a") and not matcher.excludes("a/b")


@pytest.mark.parametrize("pattern", ["", "/", 5])
def test_bad_patterns_are_rejected(pattern):
    with pytest.raises(PolicyError):
        Matcher([pattern])


def test_compile_glob_is_anchored():
    assert compile_glob("a*").fullmatch("abc") and not compile_glob("a*").fullmatch("xabc")


@pytest.mark.parametrize("rel", ["a", "a/b.txt", "deep/er/x.y", "caf\u00e9/\u65e5.txt"])
def test_validate_rel_accepts(rel):
    assert validate_rel(rel) == rel


@pytest.mark.parametrize("rel", ["", "/abs", "../x", "a/../b", "a//b", "a/./b", "a/", "nul\x00", None])
def test_validate_rel_rejects(rel):
    with pytest.raises(PolicyError):
        validate_rel(rel)


def test_sha256_file(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"abc" * 1000)
    digest = sha256_file(path)
    assert digest.sha256 == hashlib.sha256(b"abc" * 1000).hexdigest() and digest.size == 3000


def test_sha256_file_missing_is_a_source_error(tmp_path):
    with pytest.raises(SourceError):
        sha256_file(tmp_path / "missing")


def test_extended_adds_the_prefix_only_for_long_windows_paths():
    long_path = "C:\\" + "\\".join(["folder"] * 60) + "\\file.txt"
    assert extended(long_path, windows=True) == "\\\\?\\" + long_path
    assert extended("C:\\short\\file.txt", windows=True) == "C:\\short\\file.txt"
    assert extended(long_path, windows=False) == long_path
    assert extended("\\\\?\\" + long_path, windows=True) == "\\\\?\\" + long_path  # already extended


def test_extended_handles_network_shares():
    unc = "\\\\server\\share\\" + "\\".join(["dir"] * 80) + "\\f.txt"
    assert extended(unc, windows=True) == "\\\\?\\UNC\\server\\share\\" + "\\".join(["dir"] * 80) + "\\f.txt"


def test_strip_extended_round_trips():
    assert strip_extended("\\\\?\\C:\\a\\b") == "C:\\a\\b"
    assert strip_extended("\\\\?\\UNC\\srv\\share\\x") == "\\\\srv\\share\\x"
    assert strip_extended("C:\\plain") == "C:\\plain"


def test_is_inside():
    sep = os.sep
    a, ab, a_b = sep + "a", sep + "ab", sep.join(["", "a", "b"])
    assert is_inside(a_b, a) and is_inside(a, a) and not is_inside(ab, a)


def test_is_link_like_recognises_symlinks_and_junctions():
    plain = SimpleNamespace(st_mode=stat.S_IFREG | 0o644)
    symlink = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
    junction = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_reparse_tag=0xA0000003)
    cloud = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_reparse_tag=0x9000001A)  # a sync placeholder is not a link
    assert is_link_like(symlink) and is_link_like(junction)
    assert not is_link_like(plain) and not is_link_like(cloud)
