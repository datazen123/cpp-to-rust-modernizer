"""Property-based tests (Hypothesis) for verify_parity.py's deterministic
functions - invariants checked across hundreds of generated inputs, not
just hand-picked examples. No clang/rustc/API key needed for these."""
from hypothesis import given, settings
from hypothesis import strategies as st

import verify_parity as vp

SAFE_ID = st.text(alphabet=st.characters(whitelist_categories=("L", "N"), min_codepoint=32), min_size=1, max_size=10)
PRIORITY = st.sampled_from(["low", "medium", "high", "urgent"])


@given(
    ticket_id=SAFE_ID,
    days=st.integers(min_value=0, max_value=100000),
    overdue=st.integers(min_value=0, max_value=1),
    priority=PRIORITY,
)
@settings(max_examples=200)
def test_parse_output_round_trips_any_well_formed_line(ticket_id, days, overdue, priority):
    """Any well-formed pipe-delimited line should parse back to exactly
    the fields that were put in - a round-trip property, not just a fixed
    example."""
    line = f"{ticket_id}|{days}|{overdue}|{priority}"
    rows = vp.parse_output(line)

    assert rows is not None
    assert rows[0]["id"] == ticket_id
    assert rows[0]["days_since_check"] == days
    assert rows[0]["is_overdue"] == bool(overdue)
    assert rows[0]["risk"] == priority


@given(text=st.text(min_size=1, max_size=50))
@settings(max_examples=200)
def test_parse_output_never_crashes_on_arbitrary_text(text):
    """Malformed input must return None (a value the caller checks), never
    raise an unhandled exception - this is the actual safety property that
    matters for a function parsing untrusted subprocess output."""
    try:
        vp.parse_output(text)
    except Exception as exc:  # noqa: BLE001 - the property IS "never raises"
        raise AssertionError(f"parse_output raised on input {text!r}: {exc}") from exc


@given(
    prefix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_{}();\n ", max_size=30),
    suffix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_{}();\n ", max_size=30),
)
@settings(max_examples=200)
def test_check_no_unsafe_blocks_flags_standalone_unsafe_keyword(prefix, suffix):
    """Whenever the standalone word 'unsafe' appears (surrounded by
    non-word characters or string boundaries), it must be counted -
    across many generated surrounding contexts, not just one hand-picked
    example."""
    source = f"{prefix} unsafe {suffix}"
    result = vp.check_no_unsafe_blocks(source)
    assert result["unsafe_keyword_count"] >= 1
    assert result["ok"] is False


@given(word_chars=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_0123456789", min_size=1, max_size=15))
@settings(max_examples=200)
def test_check_no_unsafe_blocks_does_not_flag_unsafe_as_substring_of_identifier(word_chars):
    """'unsafe' glued directly onto other word characters (part of a
    longer identifier) must NOT be flagged as a real unsafe block - only
    the standalone keyword counts."""
    identifier = f"unsafe{word_chars}"  # e.g. "unsafely", "unsafe_flag"
    source = f"let {identifier} = true;"
    result = vp.check_no_unsafe_blocks(source)
    assert result["unsafe_keyword_count"] == 0
    assert result["ok"] is True
