"""
Self-consistency check: does Claude consistently identify the planted
CWE-121 bug across multiple independent samples of the same analyze()
call - and does its plain-English summary of the program mean the same
thing each time, independent of whether it names the bug?

Applies Wang, Wei, Schuurmans, Le, Chi, Narang, Chowdhery, Zhou,
"Self-Consistency Improves Chain of Thought Reasoning in Language Models"
(https://arxiv.org/abs/2203.11171, ICLR 2023) to `analyze()`: instead of
trusting one sample, this calls it `--samples` times (default 5 - see
semantic_entropy.py's docstring for why) against the identical
`legacy/asset_risk.c` source, then deterministically checks whether every
sample agrees on the one categorical judgment this step makes.

Unlike this portfolio's other self-consistency checks, `analyze()` doesn't
assign a severity field to majority-vote - its one categorical judgment is
CWE identification itself: does Claude name CWE-121, the real planted bug,
every time it's asked? This reuses `cwe_was_identified()` from
`benchmark.py` (already tested there) rather than reimplementing the
matching logic.

Complementary to that categorical flag: `analyze()` always returns a
`summary` field regardless of what it found, so this also runs
semantic_entropy.py's discrete semantic entropy (Farquhar et al., Nature
2024) over the sampled summaries - a finding-independent uncertainty
signal about whether Claude's overall read of the program is stable.

This is additive - it doesn't change modernize.py's default single-call
behavior, and it costs extra API calls beyond the one `modernize.py`
already makes for its own live run: one per sample, plus one to cluster
the summaries.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python self_consistency_check.py [--samples N]
"""
from __future__ import annotations

import argparse
import json

from benchmark import EXPECTED_CWE_NUMBER, cwe_was_identified
from llm_client import AnthropicClient
from modernize import ROOT, analyze
from semantic_entropy import cluster_by_meaning, discrete_semantic_entropy, max_entropy

DEFAULT_SAMPLES = 5


def all_agree(flags: list[bool]) -> bool:
    """Deterministic aggregation - no LLM judgment. True only if every
    sample reached the same identified/not-identified call."""
    return len(set(flags)) == 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    args = parser.parse_args()

    client = AnthropicClient()
    legacy_src = (ROOT / "legacy" / "asset_risk.c").read_text()

    print(f"Sampling analyze() {args.samples} independent times against the identical source...\n")

    results = []
    for i in range(args.samples):
        analysis = analyze(client, legacy_src)
        risks = analysis.get("memory_safety_risks", [])
        cwes_found = sorted({r.get("cwe") for r in risks if r.get("cwe")})
        identified = cwe_was_identified(set(cwes_found), EXPECTED_CWE_NUMBER)
        results.append({
            "sample": i, "identified_cwe_121": identified,
            "cwes_found": cwes_found, "total_risks_noted": len(risks),
            "summary": analysis.get("summary", ""),
        })
        print(f"Sample {i}: CWE-121 identified={identified}, "
              f"all CWEs found={cwes_found}, total risks noted={len(risks)}")

    flags = [r["identified_cwe_121"] for r in results]
    identified_count = sum(flags)
    risk_counts = [r["total_risks_noted"] for r in results]

    print(f"\nCWE-121 identified in {identified_count}/{args.samples} samples "
          f"({'UNANIMOUS' if all_agree(flags) else 'SPLIT'}).")
    print(f"Total risks noted per sample: {risk_counts} "
          f"(a real, expected source of run-to-run variation - analyze() "
          f"has no fixed list of secondary observations to be consistent about).")

    print(f"\n=== Semantic entropy over the program summary (Farquhar et al., Nature 2024) ===\n")
    print("Clustering the sampled summaries by meaning (Claude as the entailment "
          "judge, temperature=0)...\n")

    summaries = [r["summary"] for r in results if r["summary"]]
    entropy_report = {}
    if len(summaries) >= 2:
        clusters = cluster_by_meaning(client, summaries)
        entropy = discrete_semantic_entropy([len(c) for c in clusters])
        ceiling = max_entropy(len(summaries))
        entropy_report = {
            "semantic_entropy_bits": round(entropy, 3),
            "semantic_entropy_normalized": round(entropy / ceiling, 3) if ceiling else 0.0,
            "meaning_cluster_count": len(clusters),
            "samples_clustered": len(summaries),
        }
        tag = "CONSISTENT" if entropy == 0.0 else "MIXED"
        print(f"[{tag}] {len(clusters)} meaning-cluster(s) across {len(summaries)} "
              f"summaries -> {entropy:.3f} bits")
    else:
        entropy_report = {"note": f"only {len(summaries)} non-empty summary(s) - nothing to cluster"}
        print(entropy_report["note"])

    (ROOT / "self_consistency_result.json").write_text(
        json.dumps({"samples": results, "summary_semantic_entropy": entropy_report}, indent=2) + "\n"
    )
    print("\nWrote self_consistency_result.json")


if __name__ == "__main__":
    main()
