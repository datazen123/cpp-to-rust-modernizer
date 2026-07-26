"""
Claude-driven legacy-to-modern migration: C to Rust, the same underlying
category DARPA's TRACTOR program is funding GrammaTech to build
(HR001123C0079, "C++ TO RUST (PROGRAMMING LANGUAGE) ASSISTED MIGRATION",
$1.5M, active through Sept 2026 - see README). Reads real (synthetic)
legacy C with a genuine CWE-121 stack-based buffer overflow, produces a
structured memory-safety analysis, then generates an idiomatic, safe
(no `unsafe`) Rust replacement.

The generated Rust is then run through verify_parity.py automatically -
not a manual follow-up step - which is the actual source of truth on
whether the migration is correct AND actually memory-safe, not something
this script (or Claude) gets to assert. On failure (compile error, unsafe
block detected, behavioral parity mismatch, or the Rust binary crashing on
the same input that's supposed to prove it's safe), Claude gets the exact
failure back for one bounded corrective rewrite before this script gives up
and says so plainly.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python modernize.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from llm_client import AnthropicClient
from verify_parity import run_full_verification

ROOT = Path(__file__).parent
CODE_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)
MAX_CORRECTION_RETRIES = 1

RUST_HARD_REQUIREMENTS = """Hard requirements for the Rust replacement:
- Single self-contained file, Rust standard library ONLY (no external
  crates - this is compiled directly with `rustc`, no Cargo/crates.io).
- Read records from stdin, one per line, pipe-delimited:
  id|days_since_check|check_interval_days|condition_notes
  (condition_notes may be empty, and may be arbitrarily long - it MUST be
  handled safely no matter how long it is, unlike the legacy C version).
- For each record, compute the exact same business rules as the legacy C:
  is_overdue = days_since_check > check_interval_days; ratio =
  days_since_check / check_interval_days; risk = "high" if ratio >= 2.0,
  "medium" if ratio >= 1.0, else "low"; then risk becomes "high" if
  condition_notes case-insensitively contains "fail", regardless of the
  ratio-based tier.
- Sort output rows by risk (high, then medium, then low).
- Print one line per record to stdout, pipe-delimited:
  id|days_since_check|is_overdue(0 or 1)|risk
- Absolutely NO `unsafe` blocks, and no fixed-size buffers copied into via
  something like a manual byte-array with an unchecked length - use safe
  String/Vec/str methods (e.g. to_lowercase().contains(...)) which have no
  fixed capacity and cannot overflow. This is the entire point of the
  migration - re-implementing the C bug in an `unsafe` block would defeat
  it completely."""


def strip_fences(text: str) -> str:
    return CODE_FENCE_RE.sub("", text.strip()).strip()


def extract_json(text: str) -> dict:
    try:
        return json.loads(strip_fences(text))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Claude's response wasn't valid JSON: {exc}\nRaw response:\n{text}") from exc


def call(client: AnthropicClient, system: str, user: str, max_tokens: int = 4096) -> str:
    response = client.create(system=system, messages=[{"role": "user", "content": user}], max_tokens=max_tokens)
    return "".join(b.text for b in response.content if b.type == "text")


def analyze(client: AnthropicClient, legacy_src: str) -> dict:
    prompt = (
        "Here is a legacy C module for sustainment-asset risk scoring, still "
        "in production use. Analyze it for memory-safety risk.\n\n"
        f"=== legacy/asset_risk.c ===\n{legacy_src}\n\n"
        "Return ONLY JSON (no markdown fences):\n"
        '{"summary": "plain-English description of what this program does", '
        '"memory_safety_risks": [{"location": "function/line description", '
        '"cwe": "CWE-XXX if it matches a known category, else null", '
        '"description": "what the bug is and how it could be triggered"}], '
        '"rust_migration_plan": ["ordered steps for the Rust rewrite"]}'
    )
    return extract_json(
        call(client, "You are a senior systems engineer doing a memory-safety audit before a Rust migration. "
                      "Be specific: name exact functions/lines, and use CWE IDs where they genuinely apply.",
             prompt)
    )


def generate_modern_rust(client: AnthropicClient, legacy_src: str, analysis: dict) -> str:
    prompt = (
        "Rewrite this legacy C program as safe, idiomatic Rust, fixing the "
        "memory-safety issues you identified below.\n\n"
        f"{RUST_HARD_REQUIREMENTS}\n\n"
        "Return ONLY the Rust source, no markdown fences, no commentary.\n\n"
        f"=== legacy/asset_risk.c ===\n{legacy_src}\n\n"
        f"=== your analysis ===\n{json.dumps(analysis, indent=2)}"
    )
    return strip_fences(
        call(client, "You are a senior Rust engineer performing a careful, behavior-preserving, "
                      "memory-safe rewrite of legacy C.", prompt)
    )


def build_correction_prompt(legacy_src: str, previous_rust: str, verification: dict) -> str:
    stage = verification["stage"]
    if stage == "compile_modern":
        problem = f"Your Rust did not compile:\n{verification['error']}"
    elif not verification["unsafe_check"]["ok"]:
        problem = (
            f"Your Rust uses `unsafe` {verification['unsafe_check']['unsafe_keyword_count']} time(s), "
            "which is not allowed - it defeats the point of this migration. Remove all `unsafe` blocks "
            "and rewrite using safe String/Vec/str methods with no fixed-size buffers."
        )
    elif not verification["parity"].get("ok", False):
        mismatches = verification["parity"].get("field_mismatches", [])
        if mismatches:
            detail = "\n".join(
                f"- id {m['id']}, field '{m['field']}': legacy={m['legacy']!r}, your version={m['modern']!r}"
                for m in mismatches
            )
        else:
            detail = verification["parity"].get("error", "unknown parity failure")
        problem = f"Your Rust's output didn't match the legacy C's behavior on valid input:\n{detail}"
    else:
        safety = verification["safety_proof"]
        problem = (
            "Your Rust CRASHED when given a long condition_notes value (the exact input that proves "
            f"the C version is vulnerable): exit code {safety['modern_exit_code']}, "
            f"stderr: {safety['modern_stderr']}. condition_notes must be handled safely at ANY length - "
            "do not use a fixed-size buffer or array for it."
        )

    return (
        f"Your previous Rust rewrite FAILED automated verification. {problem}\n\n"
        f"{RUST_HARD_REQUIREMENTS}\n\n"
        f"=== legacy/asset_risk.c (source of truth for behavior) ===\n{legacy_src}\n\n"
        f"=== your previous modernized/asset_risk.rs (has the bug above) ===\n{previous_rust}\n\n"
        "Return ONLY the corrected Rust source, no markdown fences, no commentary."
    )


def main() -> None:
    client = AnthropicClient()
    legacy_src = (ROOT / "legacy" / "asset_risk.c").read_text()

    print("Analyzing legacy C for memory-safety risk...")
    analysis = analyze(client, legacy_src)
    (ROOT / "modernized" / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
    print(json.dumps(analysis, indent=2))

    print("\nGenerating modernized/asset_risk.rs...")
    modern_rust = generate_modern_rust(client, legacy_src, analysis)
    (ROOT / "modernized" / "asset_risk.rs").write_text(modern_rust + "\n")

    print("Running full verification (compile, unsafe-block check, parity, live ASan-vs-Rust safety proof)...")
    verification = run_full_verification()
    verified = verification["ok"]

    for attempt in range(MAX_CORRECTION_RETRIES):
        if verified:
            break
        print(f"  VERIFICATION FAILED at stage '{verification['stage']}' - requesting one corrective rewrite...")
        correction_prompt = build_correction_prompt(legacy_src, modern_rust, verification)
        modern_rust = strip_fences(call(
            client, "You are a senior Rust engineer performing a careful, behavior-preserving, "
                    "memory-safe rewrite of legacy C.", correction_prompt,
        ))
        (ROOT / "modernized" / "asset_risk.rs").write_text(modern_rust + "\n")
        verification = run_full_verification()
        verified = verification["ok"]

    (ROOT / "modernized" / "verification_result.json").write_text(json.dumps(verification, indent=2) + "\n")

    if verified:
        print("  VERIFIED: no unsafe blocks, behavioral parity holds, and the Rust binary handles the exact "
              "input that crashes the C binary under AddressSanitizer.")
    else:
        print(f"  STILL FAILING after {MAX_CORRECTION_RETRIES} correction attempt(s) at stage "
              f"'{verification['stage']}'. modernized/asset_risk.rs is NOT verified - do not ship it "
              f"without human review. Full detail in modernized/verification_result.json.")

    clippy = verification.get("clippy", {})
    if clippy.get("ran"):
        print(f"  clippy (non-blocking): {clippy['warning_count']} warning(s) - see modernized/verification_result.json")

    print(f"\nWrote modernized/analysis.json, modernized/asset_risk.rs, modernized/verification_result.json")
    print(f"Verification status: {'VERIFIED' if verified else 'NOT VERIFIED - needs human review'}")


if __name__ == "__main__":
    main()
