"""Offline unit tests for benchmark_second_cwe.py's deterministic,
network-independent pieces."""
from benchmark_second_cwe import EXPECTED_CWE_NUMBER, JULIET_TESTCASE_BASE, RUST_REQUIREMENTS, VARIANTS


def test_variants_has_six_distinct_flow_shapes():
    assert len(VARIANTS) == 6
    assert len(set(VARIANTS.values())) == 6


def test_variants_are_different_from_the_cwe121_benchmarks_variant_set():
    """Confirms this is testing a genuinely different corner of Juliet's
    flow-variant catalog, not accidentally re-running the same IDs."""
    from benchmark_modernization import VARIANTS as CWE121_VARIANTS
    assert set(VARIANTS) != set(CWE121_VARIANTS)


def test_expected_cwe_is_416_not_121():
    assert EXPECTED_CWE_NUMBER == "416"


def test_testcase_url_formats_with_the_real_juliet_filename_pattern():
    url = JULIET_TESTCASE_BASE.format(variant="01")
    assert url.endswith("CWE416_Use_After_Free__malloc_free_char_01.c")
    assert url.startswith("https://raw.githubusercontent.com/")


def test_every_variant_key_produces_a_fetchable_looking_url():
    for variant in VARIANTS:
        url = JULIET_TESTCASE_BASE.format(variant=variant)
        assert url.endswith(f"char_{variant}.c")


def test_rust_requirements_bans_unsafe_and_explains_this_is_an_ownership_bug():
    assert "unsafe" in RUST_REQUIREMENTS
    assert "ownership" in RUST_REQUIREMENTS
