"""Offline unit tests for benchmark.py's deterministic CWE-matching logic."""
from benchmark import cwe_was_identified


def test_matches_full_cwe_form():
    assert cwe_was_identified({"CWE-121"}, "121") is True


def test_matches_bare_number_form():
    assert cwe_was_identified({"121"}, "121") is True


def test_matches_no_dash_form():
    assert cwe_was_identified({"CWE121"}, "121") is True


def test_does_not_match_unrelated_cwe():
    assert cwe_was_identified({"CWE-676"}, "121") is False


def test_does_not_false_positive_on_number_as_substring():
    assert cwe_was_identified({"CWE-1210"}, "121") is False


def test_matches_when_present_among_multiple():
    assert cwe_was_identified({"CWE-676", "CWE-121", "CWE-193"}, "121") is True


def test_ignores_none_entries():
    assert cwe_was_identified({None, "CWE-676"}, "121") is False
