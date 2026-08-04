"""
Second-CWE-family modernization benchmark: does this repo's
analyze-then-generate approach generalize beyond the one bug class
(CWE-121, stack-based buffer overflow) it was built around, to a
genuinely different memory-safety bug class?

`benchmark_modernization.py` already proves the pipeline generalizes
across six different C control-flow *shapes* wrapping the identical
CWE-121 bug. This script asks a different, harder question: does it also
generalize to a different bug *class* - **CWE-416, Use-After-Free** -
where the underlying mistake (using memory after `free()`), the detection
mechanism (ASan's heap-poisoning check, not a stack-buffer-overflow
check), and the Rust fix (Rust's ownership/borrow-checker rules, not
`String`'s dynamic sizing) are all different from CWE-121's.

This is also a stronger test of the "Rust makes this bug class
impossible" claim than CWE-121 is: a `String` avoiding a fixed buffer
sidesteps CWE-121 by construction, but a *correct* Rust translation of a
use-after-free bug has to actually respect Rust's ownership rules - there
is no equivalent of "just use a bigger container" that sidesteps this bug
class without engaging with move semantics at all.

Same six real, NIST-labeled flow variants as `benchmark_modernization.py`
uses for CWE-121 (same public GitHub mirror), applied to CWE-416 instead:

  01  Baseline
  02  Control flow: if(1) / if(0)
  11  Control flow: via function calls returning true/false
  15  Control flow: switch statements
  16  Control flow: while(1)
  18  Control flow: goto statements

For each variant: compile the real `_bad()` function with AddressSanitizer
and run it (confirms the use-after-free is genuinely triggerable in that
variant's own source); have Claude analyze it (the same generic prompt
`benchmark.py` uses - no CWE-121-specific framing); have Claude generate a
safe Rust replacement; compile that Rust and run it.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python benchmark_second_cwe.py
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from benchmark import analyze_generic_c, cwe_was_identified
from benchmark_modernization import compile_and_run_rust, fetch, fetch_support_files
from llm_client import AnthropicClient
from modernize import strip_fences

ROOT = Path(__file__).parent

EXPECTED_CWE_NUMBER = "416"

JULIET_TESTCASE_BASE = (
    "https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/"
    "testcases/CWE416_Use_After_Free/"
    "CWE416_Use_After_Free__malloc_free_char_{variant}.c"
)

VARIANTS = {
    "01": "Baseline",
    "02": "Control flow: if(1) / if(0)",
    "11": "Control flow: via function calls returning true/false",
    "15": "Control flow: switch statements",
    "16": "Control flow: while(1)",
    "18": "Control flow: goto statements",
}

RUST_REQUIREMENTS = """Hard requirements for the Rust replacement:
- Single self-contained file, Rust standard library ONLY (no external
  crates - this is compiled directly with `rustc`, no Cargo/crates.io).
- Reproduce the same intended behavior as the C function: build a string
  and print it.
- Absolutely NO `unsafe` blocks. The fix for this specific bug class
  (use-after-free) is NOT "use a bigger/dynamic container" the way a
  buffer-overflow fix is - it's respecting Rust's ownership rules. Do
  not manually free/drop a value and then use it afterward; let Rust's
  own ownership and borrow-checking rules make that structurally
  impossible rather than working around them.
- Include a `fn main()` so the file is directly runnable."""


def compile_and_run_bad_c(c_source: str, variant: str, tmpdir: Path) -> dict:
    """Compiles the real `_bad()` function (with AddressSanitizer) and
    runs it - deterministic, not an LLM claim. Confirms the use-after-free
    is genuinely triggerable in THIS variant's exact source."""
    src_path = tmpdir / f"variant_{variant}.c"
    src_path.write_text(c_source)
    bin_path = tmpdir / f"bad_bin_{variant}"
    compile_result = subprocess.run(  # nosec B603 B607 - shell=False, static argv, no untrusted input
        ["clang", "-fsanitize=address", "-g", "-O0", "-DINCLUDEMAIN", "-DOMITGOOD",
         "-I", str(tmpdir), "-o", str(bin_path), str(src_path), str(tmpdir / "io.c")],
        capture_output=True, text=True, timeout=60,
    )
    if compile_result.returncode != 0:
        return {"compiled": False, "crashed": False, "error": compile_result.stderr}

    run_result = subprocess.run([str(bin_path)], capture_output=True, text=True, timeout=10)  # nosec B603
    crashed = "AddressSanitizer" in run_result.stderr and run_result.returncode != 0
    is_uaf = "use-after-free" in run_result.stderr.lower()
    summary = next((l for l in run_result.stderr.splitlines() if "SUMMARY" in l), None)
    return {"compiled": True, "crashed": crashed, "confirmed_use_after_free": is_uaf, "asan_summary": summary}


def generate_safe_rust(client: AnthropicClient, c_source: str, analysis: dict) -> str:
    prompt = (
        "Here is a real C function with a known, labeled memory-safety bug "
        "(see the vulnerability analysis below). Write a safe, idiomatic "
        "Rust replacement.\n\n"
        f"{RUST_REQUIREMENTS}\n\n"
        "Return ONLY the Rust source, no markdown fences, no commentary.\n\n"
        f"=== vulnerable C function ===\n{c_source}\n\n"
        f"=== your vulnerability analysis ===\n{json.dumps(analysis, indent=2)}"
    )
    # No prefill here, unlike the JSON-returning calls elsewhere in this
    # repo - a raw Rust source file has no fixed guaranteed starting
    # character the way JSON does (some valid files start with `use`,
    # others go straight to `fn main()`), so forcing one would risk
    # constraining a valid response rather than just hardening extraction.
    response = client.create(
        system="You are a senior Rust engineer performing a careful, memory-safe rewrite of legacy C.",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2048,
    )
    text = "".join(b.text for b in response.content if b.type == "text")
    return strip_fences(text)


def main() -> None:
    client = AnthropicClient()
    results = {}

    with tempfile.TemporaryDirectory(prefix="cpp_to_rust_second_cwe_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        print("Fetching Juliet support files (std_testcase.h, std_testcase_io.h, io.c)...")
        fetch_support_files(tmpdir)

        for variant, description in VARIANTS.items():
            print(f"\n=== Variant {variant}: {description} ===")
            url = JULIET_TESTCASE_BASE.format(variant=variant)
            c_source = fetch(url)

            print("  Compiling + running the real _bad() function under AddressSanitizer...")
            bad_result = compile_and_run_bad_c(c_source, variant, tmpdir)
            print(f"  Use-after-free confirmed real in this variant: "
                  f"{bad_result.get('confirmed_use_after_free', False)}")

            print("  Claude analyzing for memory-safety risk (generic prompt, no CWE-416-specific framing)...")
            analysis = analyze_generic_c(client, c_source)
            risks = analysis.get("memory_safety_risks", [])
            cwes_found = {r.get("cwe") for r in risks if r.get("cwe")}
            identified = cwe_was_identified(cwes_found, EXPECTED_CWE_NUMBER)
            print(f"  CWE-{EXPECTED_CWE_NUMBER} identified: {identified}")

            print("  Claude generating safe Rust replacement...")
            rust_source = generate_safe_rust(client, c_source, analysis)
            rust_result = compile_and_run_rust(rust_source, variant, tmpdir)
            print(f"  Rust: compiled={rust_result['compiled']} "
                  f"unsafe_blocks={rust_result['unsafe_check']['unsafe_keyword_count']} "
                  f"ran_clean={rust_result['ran']}")

            results[variant] = {
                "description": description,
                "bad_c": bad_result,
                "cwe_identified": identified,
                "cwes_found": sorted(c for c in cwes_found if c),
                "rust": rust_result,
            }

    total = len(results)
    bug_confirmed = sum(1 for r in results.values() if r["bad_c"].get("confirmed_use_after_free"))
    cwe_identified = sum(1 for r in results.values() if r["cwe_identified"])
    rust_fully_safe = sum(
        1 for r in results.values()
        if r["rust"]["compiled"] and r["rust"]["unsafe_check"]["ok"] and r["rust"]["ran"]
    )

    print("\n=== Summary ===")
    print(f"Variants tested: {total}")
    print(f"Real use-after-free confirmed under ASan: {bug_confirmed}/{total}")
    print(f"CWE-{EXPECTED_CWE_NUMBER} correctly identified: {cwe_identified}/{total}")
    print(f"Rust compiled + zero unsafe + ran clean: {rust_fully_safe}/{total}")

    (ROOT / "benchmark_second_cwe_result.json").write_text(json.dumps(results, indent=2) + "\n")
    print("\nWrote benchmark_second_cwe_result.json")


if __name__ == "__main__":
    main()
