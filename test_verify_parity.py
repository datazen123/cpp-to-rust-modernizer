"""Offline unit tests for verify_parity.py's deterministic functions.

Compilation/execution tests need clang and rustc on PATH (both are cheap,
local, no network) but never call the Anthropic API - safe for CI on every
push alongside test_modernize.py.
"""
from pathlib import Path

import pytest

import verify_parity as vp

FIXTURES = Path(__file__).parent / "test_fixtures"


def test_parse_output_parses_valid_lines():
    rows = vp.parse_output("A-1|5|1|high\nA-2|2|0|low\n")
    assert rows == [
        {"id": "A-1", "days_since_check": 5, "is_overdue": True, "risk": "high"},
        {"id": "A-2", "days_since_check": 2, "is_overdue": False, "risk": "low"},
    ]


def test_parse_output_ignores_blank_lines():
    assert vp.parse_output("A-1|5|1|high\n\n") == [
        {"id": "A-1", "days_since_check": 5, "is_overdue": True, "risk": "high"},
    ]


def test_parse_output_returns_none_on_malformed_line():
    assert vp.parse_output("not the right format at all") is None


def test_parse_output_returns_none_on_non_numeric_field():
    assert vp.parse_output("A-1|not-a-number|1|high") is None


def test_check_no_unsafe_blocks_passes_clean_source():
    result = vp.check_no_unsafe_blocks("fn main() { println!(\"hi\"); }")
    assert result == {"ok": True, "unsafe_keyword_count": 0}


def test_check_no_unsafe_blocks_flags_unsafe_keyword():
    result = vp.check_no_unsafe_blocks("fn main() { unsafe { do_thing(); } }")
    assert result["ok"] is False
    assert result["unsafe_keyword_count"] == 1


def test_check_no_unsafe_blocks_counts_multiple_occurrences():
    result = vp.check_no_unsafe_blocks("unsafe { a(); } unsafe { b(); }")
    assert result["unsafe_keyword_count"] == 2


def test_check_no_unsafe_blocks_does_not_false_positive_on_substring():
    """'unsafe' as part of another identifier (e.g. a comment mentioning
    'this is not unsafeish') shouldn't false-positive - word boundary
    matters. This checks the inverse: a real substring match that ISN'T a
    standalone word should not be flagged."""
    result = vp.check_no_unsafe_blocks("// thread_unsafe_counter is a bad name for a variable")
    assert result["ok"] is True


# --- check_clippy: real clippy-driver run, requires clippy on PATH ---

def test_check_clippy_reports_zero_warnings_on_clean_code(tmp_path):
    rust_file = tmp_path / "clean.rs"
    rust_file.write_text("fn main() { println!(\"hello\"); }\n")
    result = vp.check_clippy(rust_file)
    assert result["ran"] is True
    assert result["warning_count"] == 0


def test_check_clippy_detects_a_real_lint_warning(tmp_path):
    """A well-known clippy lint (manual_unwrap_or) - the exact pattern
    Claude's own generated code triggered on the live run documented in
    the README."""
    rust_file = tmp_path / "lint_me.rs"
    rust_file.write_text(
        "fn main() {\n"
        "    let x: Result<i32, ()> = Ok(1);\n"
        "    let _y = match x { Ok(n) => n, Err(_) => 0 };\n"
        "}\n"
    )
    result = vp.check_clippy(rust_file)
    assert result["ran"] is True
    assert result["warning_count"] >= 1


def test_check_clippy_excludes_the_summary_line_from_the_count(tmp_path):
    """clippy's own 'N warnings emitted' trailing summary line also starts
    with 'warning:' - it must not be double-counted as an extra finding."""
    rust_file = tmp_path / "lint_me.rs"
    rust_file.write_text(
        "fn main() {\n"
        "    let x: Result<i32, ()> = Ok(1);\n"
        "    let _y = match x { Ok(n) => n, Err(_) => 0 };\n"
        "}\n"
    )
    result = vp.check_clippy(rust_file)
    assert "warning emitted" in result["output"] or "warnings emitted" in result["output"]
    assert result["warning_count"] == 1
