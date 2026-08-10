"""
Discrete semantic entropy over analyze()'s free-text "summary" field, as a
companion uncertainty signal to self_consistency_check.py's categorical
CWE-121-identified vote.

Applies Farquhar, Kossen, Kuhn, Gal, "Detecting hallucinations in large
language models using semantic entropy" (Nature 630, 625-630, 2024,
https://www.nature.com/articles/s41586-024-07421-0). Unlike this
portfolio's other 3 self-consistency checks, `analyze()`'s one categorical
judgment (does it name CWE-121?) is already checked by
`all_agree()`/`cwe_was_identified()` - there's no severity enum here to
majority-vote. What every sample *does* always produce, independent of
whether it happens to name CWE-121, is a one-paragraph plain-English
`summary` of what the program does. Two samples can describe the same
program in different words, or describe it in ways that actually diverge
on substance - semantic entropy over `summary` measures which, as a
signal that's complementary to (not a replacement for) the CWE-121 flag.

Two adaptations from the paper's exact procedure, made explicit rather
than silently assumed:

1. **Discrete variant, not the full log-prob-weighted one.** The paper
   shows a "discrete semantic entropy" variant - cluster sizes only, no
   token log-probabilities - performs comparably to the full version and
   is the right choice for black-box models. That's this repo's
   situation exactly: the Anthropic Messages API this portfolio's
   llm_client.py wraps doesn't expose token log-probabilities.

2. **One joint clustering call, not pairwise incremental.** The paper's
   real algorithm compares each new sample one at a time against a
   representative of each existing meaning-cluster (using either a
   trained NLI model or, as the authors also validate, "a general-purpose
   LLM" asked whether two texts mean the same thing). This module uses
   the latter (Claude, temperature=0 for a consistent judge) but sends
   all samples in a single clustering call rather than doing it pairwise
   - a cost/latency simplification, not a reproduction of the paper's
   exact incremental procedure. The entropy formula itself (Shannon
   entropy over cluster-size fractions) is applied exactly as described.
"""
from __future__ import annotations

import json
import math

from llm_client import AnthropicClient

CLUSTER_SYSTEM_PROMPT = """You are grading semantic equivalence between short
plain-English summaries of what the identical C program does. You will be
given several numbered texts. Group them into meaning-clusters: texts belong
in the same cluster only if they describe the same program behavior/purpose
- same core function, same key risk or role it plays. Texts belong in
different clusters if a reader would come away with a materially different
understanding of what the program does or is for, even if only in
emphasis - not just because the wording differs.

Reply with ONLY JSON, no markdown fences:
{"clusters": [[0, 2], [1]]}
- a list of clusters, each a list of the given zero-based indices.
- every index from the input must appear in exactly one cluster."""


def parse_cluster_response(text: str, n: int) -> list[list[int]]:
    """Pure parsing/validation, split out from the API call so it's
    unit-testable without a live client. A response that doesn't
    partition every index exactly once is treated as a verification
    failure, not silently trusted - the fallback (one singleton cluster
    per text) is deliberately the *maximum*-entropy outcome, so a
    malformed judge response shows up as high uncertainty rather than
    being smoothed into false consistency."""
    try:
        clusters = json.loads(text)["clusters"]
        seen = sorted(i for cluster in clusters for i in cluster)
        if seen != list(range(n)):
            raise ValueError("clustering response didn't partition every index exactly once")
        return clusters
    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
        return [[i] for i in range(n)]


def cluster_by_meaning(client: AnthropicClient, texts: list[str]) -> list[list[int]]:
    """One joint clustering call across all sampled summaries. len(texts)
    <= 1 is trivially one cluster - no judge call needed or possible."""
    if len(texts) <= 1:
        return [[i] for i in range(len(texts))]

    numbered = "\n".join(f"{i}: {t}" for i, t in enumerate(texts))
    response = client.create(
        system=CLUSTER_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": numbered}, {"role": "assistant", "content": "{"}],
        max_tokens=500,
        temperature=0.0,
    )
    text = "{" + "".join(b.text for b in response.content if b.type == "text")
    return parse_cluster_response(text, len(texts))


def discrete_semantic_entropy(cluster_sizes: list[int]) -> float:
    """Shannon entropy, in bits, over the meaning-cluster distribution -
    Farquhar et al.'s discrete semantic entropy: p_c = |cluster c| /
    total samples, entropy = -sum(p_c * log2(p_c)). 0.0 means every
    sample landed in one meaning-cluster (fully consistent); higher means
    samples split across more, or more evenly-sized, meaning-clusters."""
    n = sum(cluster_sizes)
    if n == 0:
        return 0.0
    entropy = 0.0
    for size in cluster_sizes:
        if size <= 0:
            continue
        p = size / n
        entropy -= p * math.log2(p)
    return entropy


def max_entropy(k: int) -> float:
    """Entropy if all k samples landed in their own singleton cluster -
    used to normalize a reported entropy value onto a 0-1 scale."""
    return math.log2(k) if k > 1 else 0.0
