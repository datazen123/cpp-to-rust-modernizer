"""Property-based tests (Hypothesis) for semantic_entropy.py's discrete
entropy math - these check invariants across generated cluster-size
distributions, not just the hand-picked examples in
test_semantic_entropy.py. No API key or network needed."""
import math

from hypothesis import given, settings
from hypothesis import strategies as st

from semantic_entropy import discrete_semantic_entropy, max_entropy

cluster_sizes = st.lists(st.integers(min_value=1, max_value=20), min_size=1, max_size=10)


@given(sizes=cluster_sizes)
@settings(max_examples=200)
def test_entropy_never_negative(sizes):
    assert discrete_semantic_entropy(sizes) >= 0.0


@given(sizes=cluster_sizes)
@settings(max_examples=200)
def test_entropy_never_exceeds_the_all_singletons_ceiling(sizes):
    n = sum(sizes)
    assert discrete_semantic_entropy(sizes) <= max_entropy(n) + 1e-9


@given(sizes=cluster_sizes)
@settings(max_examples=200)
def test_entropy_is_invariant_to_cluster_order(sizes):
    """The entropy of a distribution doesn't depend on which cluster is
    listed first - it's a property of the size multiset, not the order
    Claude happened to list the clusters in."""
    assert math.isclose(discrete_semantic_entropy(sizes), discrete_semantic_entropy(list(reversed(sizes))))


@given(n=st.integers(min_value=1, max_value=20))
@settings(max_examples=50)
def test_single_cluster_containing_everything_is_always_zero_entropy(n):
    assert discrete_semantic_entropy([n]) == 0.0


@given(n=st.integers(min_value=2, max_value=15))
@settings(max_examples=50)
def test_all_singletons_always_hits_the_ceiling_exactly(n):
    assert math.isclose(discrete_semantic_entropy([1] * n), max_entropy(n))
