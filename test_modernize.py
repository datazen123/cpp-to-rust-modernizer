"""Offline unit tests for modernize.py's deterministic helpers - no API key needed."""
import pytest

from modernize import build_correction_prompt, extract_json, strip_fences


def test_strip_fences_removes_markdown_code_block():
    assert strip_fences('```rust\nfn main() {}\n```') == 'fn main() {}'


def test_strip_fences_leaves_bare_text_alone():
    assert strip_fences('fn main() {}') == 'fn main() {}'


def test_extract_json_parses_fenced_json():
    assert extract_json('```json\n{"summary": "ok"}\n```') == {"summary": "ok"}


def test_extract_json_raises_clear_error_on_malformed_json():
    with pytest.raises(RuntimeError, match="wasn't valid JSON"):
        extract_json("this is not json")


def test_build_correction_prompt_compile_error():
    verification = {"stage": "compile_modern", "error": "expected `;`"}
    prompt = build_correction_prompt("c src", "rust src", verification)
    assert "did not compile" in prompt
    assert "expected `;`" in prompt


def test_build_correction_prompt_unsafe_block_detected():
    verification = {
        "stage": "verification",
        "unsafe_check": {"ok": False, "unsafe_keyword_count": 2},
        "parity": {"ok": True},
        "safety_proof": {"ok": True},
    }
    prompt = build_correction_prompt("c src", "rust src", verification)
    assert "unsafe" in prompt
    assert "2 time(s)" in prompt


def test_build_correction_prompt_parity_mismatch():
    verification = {
        "stage": "verification",
        "unsafe_check": {"ok": True},
        "parity": {"ok": False, "field_mismatches": [
            {"id": "VEH-104", "field": "risk", "legacy": "high", "modern": "medium"}
        ]},
        "safety_proof": {"ok": True},
    }
    prompt = build_correction_prompt("c src", "rust src", verification)
    assert "VEH-104" in prompt
    assert "legacy=" in prompt


def test_build_correction_prompt_safety_proof_failure():
    verification = {
        "stage": "verification",
        "unsafe_check": {"ok": True},
        "parity": {"ok": True},
        "safety_proof": {"ok": False, "modern_exit_code": 134, "modern_stderr": "panic: index out of bounds"},
    }
    prompt = build_correction_prompt("c src", "rust src", verification)
    assert "CRASHED" in prompt
    assert "134" in prompt
