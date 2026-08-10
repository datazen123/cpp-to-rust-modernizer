"""Offline unit tests for semantic_entropy.py's deterministic math and
response-parsing logic - no API call needed (cluster_by_meaning() itself
calls the live API and is only exercised via VERIFIED-RUN.md, matching
this repo's convention of not mocking Claude in pytest)."""
import math

from semantic_entropy import discrete_semantic_entropy, max_entropy, parse_cluster_response


def test_single_cluster_is_zero_entropy():
    assert discrete_semantic_entropy([5]) == 0.0


def test_all_singletons_hits_the_max_entropy_ceiling():
    entropy = discrete_semantic_entropy([1, 1, 1, 1])
    assert math.isclose(entropy, max_entropy(4))


def test_even_split_is_higher_entropy_than_uneven_split():
    even = discrete_semantic_entropy([2, 2])
    uneven = discrete_semantic_entropy([3, 1])
    assert even > uneven > 0.0


def test_empty_input_is_zero_not_an_error():
    assert discrete_semantic_entropy([]) == 0.0


def test_max_entropy_of_one_sample_is_zero():
    assert max_entropy(1) == 0.0


def test_max_entropy_of_two_samples_is_one_bit():
    assert max_entropy(2) == 1.0


def test_parse_cluster_response_accepts_a_valid_partition():
    clusters = parse_cluster_response('{"clusters": [[0, 2], [1]]}', n=3)
    assert clusters == [[0, 2], [1]]


def test_parse_cluster_response_falls_back_to_singletons_on_malformed_json():
    clusters = parse_cluster_response("not json at all", n=3)
    assert clusters == [[0], [1], [2]]


def test_parse_cluster_response_falls_back_when_partition_is_incomplete():
    # index 2 is missing entirely - must not be silently trusted
    clusters = parse_cluster_response('{"clusters": [[0, 1]]}', n=3)
    assert clusters == [[0], [1], [2]]


def test_parse_cluster_response_falls_back_when_an_index_repeats():
    # index 1 appears in two clusters - not a valid partition
    clusters = parse_cluster_response('{"clusters": [[0, 1], [1, 2]]}', n=3)
    assert clusters == [[0], [1], [2]]


def test_parse_cluster_response_fallback_is_the_maximum_entropy_outcome():
    """A malformed judge response must fail toward more reported
    uncertainty, never toward false consistency."""
    clusters = parse_cluster_response("garbage", n=3)
    entropy = discrete_semantic_entropy([len(c) for c in clusters])
    assert entropy == max_entropy(3)
