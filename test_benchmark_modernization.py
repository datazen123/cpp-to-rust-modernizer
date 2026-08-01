"""Offline unit tests for benchmark_modernization.py's deterministic,
network-independent pieces."""
from benchmark_modernization import JULIET_TESTCASE_BASE, VARIANTS, RUST_REQUIREMENTS


def test_variants_has_six_distinct_flow_shapes():
    assert len(VARIANTS) == 6
    assert len(set(VARIANTS.values())) == 6


def test_testcase_url_formats_with_the_real_juliet_filename_pattern():
    url = JULIET_TESTCASE_BASE.format(variant="01")
    assert url.endswith("CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c")
    assert url.startswith("https://raw.githubusercontent.com/")


def test_every_variant_key_produces_a_fetchable_looking_url():
    for variant in VARIANTS:
        url = JULIET_TESTCASE_BASE.format(variant=variant)
        assert url.endswith(f"cpy_{variant}.c")


def test_rust_requirements_bans_unsafe_and_fixed_buffers():
    assert "unsafe" in RUST_REQUIREMENTS
    assert "fixed-size buffer" in RUST_REQUIREMENTS
