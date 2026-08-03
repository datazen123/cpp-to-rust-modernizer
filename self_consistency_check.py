"""
Self-consistency check: does Claude consistently identify the planted
CWE-121 bug across multiple independent samples of the same analyze()
call?

Applies Wang, Wei, Schuurmans, Le, Chi, Narang, Chowdhery, Zhou,
"Self-Consistency Improves Chain of Thought Reasoning in Language Models"
(https://arxiv.org/abs/2203.11171, ICLR 2023) to `analyze()`: instead of
trusting one sample, this calls it `--samples` times (default 3) against
the identical `legacy/asset_risk.c` source, then deterministically checks
whether every sample agrees on the one categorical judgment this step
makes.

Unlike this portfolio's other self-consistency checks, `analyze()` doesn't
assign a severity field to majority-vote - its one categorical judgment is
CWE identification itself: does Claude name CWE-121, the real planted bug,
every time it's asked? This reuses `cwe_was_identified()` from
`benchmark.py` (already tested there) rather than reimplementing the
matching logic.

This is additive - it doesn't change modernize.py's default single-call
behavior, and it costs one extra API call per sample beyond the one
`modernize.py` already makes for its own live run.

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

DEFAULT_SAMPLES = 3


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

    (ROOT / "self_consistency_result.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Wrote self_consistency_result.json")


if __name__ == "__main__":
    main()
