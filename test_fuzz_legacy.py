"""Offline unit tests for fuzz_legacy.py's deterministic generation logic -
no compile or subprocess needed for these."""
import random

from fuzz_legacy import PRINTABLE, random_record


def test_printable_excludes_the_field_delimiter():
    assert "|" not in PRINTABLE


def test_random_record_always_has_exactly_three_delimiters_from_the_fixed_fields():
    """id|days|interval|notes - always at least 3 pipes, regardless of what
    random content lands in each field (delimiter itself is excluded from
    the alphabet, so this can't be perturbed by chance)."""
    rng = random.Random(1)
    for _ in range(50):
        record = random_record(rng)
        assert record.count("|") == 3


def test_random_record_is_deterministic_given_the_same_rng_state():
    record_a = random_record(random.Random(7))
    record_b = random_record(random.Random(7))
    assert record_a == record_b
