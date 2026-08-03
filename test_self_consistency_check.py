"""Offline unit tests for self_consistency_check.py's deterministic
agreement logic - no API call needed."""
from self_consistency_check import all_agree


def test_all_agree_when_unanimous_true():
    assert all_agree([True, True, True]) is True


def test_all_agree_when_unanimous_false():
    assert all_agree([False, False, False]) is True


def test_all_agree_false_on_split():
    assert all_agree([True, False, True]) is False


def test_all_agree_trivially_true_for_single_sample():
    assert all_agree([True]) is True
