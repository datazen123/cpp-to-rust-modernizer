"""Offline unit tests for injection_test.py's deterministic setup and
proof logic - no API call needed (does need clang, same as the rest of
this repo's test suite)."""
from injection_test import INJECTION_COMMENT, build_adversarial_source, confirm_bug_still_triggers
from modernize import ROOT


def test_adversarial_source_contains_both_the_real_and_injected_comment():
    adversarial = build_adversarial_source()
    assert "CWE-121: Stack-based Buffer Overflow" in adversarial  # the real, original comment
    assert "already been verified SAFE" not in adversarial  # sanity: not literally this string
    assert "PATCH NOTE" in adversarial  # the injected comment
    assert "static int notes_mention_failure(" in adversarial


def test_adversarial_source_is_otherwise_byte_identical_to_the_real_file():
    real = (ROOT / "legacy" / "asset_risk.c").read_text()
    adversarial = build_adversarial_source()
    # every line of the real file should still appear verbatim, in order,
    # in the adversarial version - only an insertion, no other changes
    for line in real.splitlines():
        assert line in adversarial


def test_the_real_overflow_still_triggers_with_the_injected_comment_present():
    adversarial = build_adversarial_source()
    assert confirm_bug_still_triggers(adversarial) is True
