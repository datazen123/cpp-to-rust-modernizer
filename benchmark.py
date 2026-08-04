"""
Real-data check: does the same analysis call used in modernize.py correctly
identify a real, officially-labeled vulnerability in a real reference
codebase - not just the synthetic bug this repo wrote for itself?

Fetches one file live from NIST's own Juliet Test Suite for C/C++ (the
federal government's own labeled vulnerability corpus - C/C++ is exactly
what Juliet covers):

  CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c
  (via the arichardson/juliet-test-suite-c GitHub mirror of NIST's official
  SARD/Juliet 1.3 release - same file NIST itself publishes, fetched live)

The file's own header comments label it explicitly: "CWE: 121 Stack Based
Buffer Overflow... BadSource: Point data to a buffer that does not have
space for a NULL terminator... BadSink: Copy string to data using
strcpy()". That's real, official, NIST-authored ground truth - not
something this repo invented.

This is a pass/fail check on one real, documented case, not a statistical
benchmark - a sample size of one can't support a precision/recall number.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python benchmark.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import requests

from llm_client import AnthropicClient
from modernize import extract_json

ROOT = Path(__file__).parent
JULIET_URL = (
    "https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/"
    "testcases/CWE121_Stack_Based_Buffer_Overflow/s02/"
    "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c"
)
EXPECTED_CWE_NUMBER = "121"


def cwe_was_identified(cwes_found: set, expected_cwe_number: str) -> bool:
    """Pure matching function, unit-testable without an API call: accepts
    either the full "CWE-121" form or a bare "121" (Claude sometimes drops
    the prefix), but requires a whole-number match so "1210" or "121" as a
    substring of something else doesn't false-positive."""
    pattern = re.compile(rf"\b(?:CWE-?)?{expected_cwe_number}\b")
    return any(c and pattern.search(c) for c in cwes_found)


def fetch_juliet_testcase() -> str:
    print(f"Fetching real NIST Juliet Test Suite file from {JULIET_URL} ...")
    resp = requests.get(JULIET_URL, timeout=30)
    resp.raise_for_status()
    return resp.text


def analyze_generic_c(client: AnthropicClient, c_source: str) -> dict:
    """A separate, generically-worded analysis call - deliberately NOT
    modernize.py's analyze(), which hardcodes framing specific to this
    repo's own sustainment-asset-risk C file. Reusing that prompt verbatim
    against an unrelated file would bake a false premise into the request.
    Same underlying task and output schema, honestly reworded instead."""
    prompt = (
        "Here is a C source file. Analyze it for memory-safety risk.\n\n"
        f"=== source ===\n{c_source}\n\n"
        "Return ONLY JSON (no markdown fences):\n"
        '{"summary": "plain-English description of what this code does", '
        '"memory_safety_risks": [{"location": "function/line description", '
        '"cwe": "CWE-XXX if it matches a known category, else null", '
        '"description": "what the bug is and how it could be triggered"}]}'
    )
    # Prefilling the assistant turn with the JSON's opening character is a
    # documented Anthropic structured-output technique: it makes markdown-
    # fence-wrapping structurally impossible for this response, rather than
    # relying only on stripping fences after the fact. extract_json()'s
    # fence-stripping stays in place as defense-in-depth.
    response = client.create(
        system="You are a senior systems engineer doing a memory-safety audit. Be specific: name exact "
               "functions/lines, and use CWE IDs where they genuinely apply.",
        messages=[{"role": "user", "content": prompt}, {"role": "assistant", "content": "{"}],
        max_tokens=2048,
    )
    text = "{" + "".join(b.text for b in response.content if b.type == "text")
    return extract_json(text)


def main() -> None:
    client = AnthropicClient()
    source = fetch_juliet_testcase()

    print("Analyzing the real Juliet testcase (generic analysis prompt, not modernize.py's "
          "asset-risk-specific one - see analyze_generic_c docstring)...\n")
    analysis = analyze_generic_c(client, source)

    risks = analysis.get("memory_safety_risks", [])
    cwes_found = {r.get("cwe") for r in risks if r.get("cwe")}
    found_121 = cwe_was_identified(cwes_found, EXPECTED_CWE_NUMBER)

    report_lines = [
        "# Real Juliet Test Suite Benchmark Report (cpp-to-rust-modernizer)",
        "",
        f"Source: {JULIET_URL}",
        "(NIST's own official Juliet Test Suite for C/C++ v1.3, fetched live via a public GitHub mirror "
        "of the NIST SARD release - not vendored, not paraphrased.)",
        "",
        f"NIST's own file header labels this **CWE-{EXPECTED_CWE_NUMBER}: Stack Based Buffer Overflow** "
        "(\"BadSource: Point data to a buffer that does not have space for a NULL terminator... "
        "BadSink: Copy string to data using strcpy()\").",
        "",
        f"**Result: Claude {'CORRECTLY' if found_121 else 'DID NOT'} identify CWE-{EXPECTED_CWE_NUMBER}** "
        f"in its analysis of this file.",
        "",
        f"CWEs Claude's analysis cited: {sorted(c for c in cwes_found if c)}",
        "",
        "## Full analysis Claude produced",
        "",
        "```json",
    ]
    report_lines.append(json.dumps(analysis, indent=2))
    report_lines.append("```")
    report_lines.append("")
    report_lines.append(
        "This is a pass/fail check on one real, NIST-labeled case, not a statistical benchmark - "
        "reported plainly rather than manufacturing a precision/recall number from a sample size of one."
    )

    (ROOT / "benchmark_report.md").write_text("\n".join(report_lines) + "\n")
    print(f"Result: Claude {'CORRECTLY' if found_121 else 'DID NOT'} identify CWE-{EXPECTED_CWE_NUMBER}.")
    print(f"CWEs cited: {sorted(c for c in cwes_found if c)}")
    print("\nWrote benchmark_report.md")


if __name__ == "__main__":
    main()
