"""
Multi-case modernization benchmark: does the same analyze-then-generate
approach `modernize.py` uses hold up against real, NIST-authored C beyond
the one synthetic file this repo wrote for itself - across DIFFERENT
control/data-flow shapes wrapping the identical underlying bug?

Six real files from NIST's Juliet Test Suite for C/C++ v1.3 (the same
public GitHub mirror `benchmark.py` uses), same base vulnerability
(CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy - a fixed
10-byte stack buffer with no room for the NUL terminator on a
10-character `strcpy`), six different NIST-labeled "Flow Variant"s:

  01  Baseline
  02  Control flow: if(1) / if(0)
  11  Control flow: via function calls returning true/false
  18  Control flow: goto statements
  31  Data flow: copy of data within the same function
  44  Data/control flow: data passed via a function pointer

This is the actual point of Juliet's flow-variant design: proving a tool
generalizes to the same bug dressed differently in C, rather than
pattern-matching one file's exact source layout.

For each variant:
  1. Compile the real `_bad()` function with AddressSanitizer and run it -
     confirms the bug is genuinely triggerable in THIS variant's exact
     source, not assumed from variant 01.
  2. Claude analyzes the file (same generic prompt `benchmark.py` uses).
  3. Claude generates a safe Rust replacement of the vulnerable function.
  4. Deterministic checks, NOT Claude: does the Rust compile? Zero
     `unsafe`? Does it run without crashing?

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python benchmark_modernization.py
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import requests

from benchmark import cwe_was_identified, analyze_generic_c, EXPECTED_CWE_NUMBER
from llm_client import AnthropicClient
from modernize import strip_fences
from verify_parity import check_no_unsafe_blocks

ROOT = Path(__file__).parent

JULIET_SUPPORT_BASE = (
    "https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/"
    "testcasesupport/"
)
JULIET_TESTCASE_BASE = (
    "https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/"
    "testcases/CWE121_Stack_Based_Buffer_Overflow/s02/"
    "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_{variant}.c"
)

VARIANTS = {
    "01": "Baseline",
    "02": "Control flow: if(1) / if(0)",
    "11": "Control flow: via function calls returning true/false",
    "18": "Control flow: goto statements",
    "31": "Data flow: copy of data within the same function",
    "44": "Data/control flow: data passed via a function pointer",
}

RUST_REQUIREMENTS = """Hard requirements for the Rust replacement:
- Single self-contained file, Rust standard library ONLY (no external
  crates - this is compiled directly with `rustc`, no Cargo/crates.io).
- Reproduce the same intended behavior as the C function: build the fixed
  string and print it.
- Absolutely NO `unsafe` blocks, and no fixed-size buffer copied into with
  an unchecked length - use safe String/Vec/str methods, which have no
  fixed capacity and cannot overflow.
- Include a `fn main()` so the file is directly runnable."""


def fetch(url: str) -> str:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def fetch_support_files(tmpdir: Path) -> None:
    for name in ("std_testcase.h", "std_testcase_io.h", "io.c"):
        (tmpdir / name).write_text(fetch(JULIET_SUPPORT_BASE + name))


def compile_and_run_bad_c(c_source: str, variant: str, tmpdir: Path) -> dict:
    """Compiles the real `_bad()` function (with AddressSanitizer) and
    runs it - deterministic, not an LLM claim. Confirms the vulnerability
    is genuinely triggerable in THIS variant's exact source, not assumed
    from a different variant."""
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
    summary = next((l for l in run_result.stderr.splitlines() if "SUMMARY" in l), None)
    return {"compiled": True, "crashed": crashed, "asan_summary": summary}


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
    response = client.create(
        system="You are a senior Rust engineer performing a careful, memory-safe rewrite of legacy C.",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2048,
    )
    text = "".join(b.text for b in response.content if b.type == "text")
    return strip_fences(text)


def compile_and_run_rust(rust_source: str, variant: str, tmpdir: Path) -> dict:
    """Deterministic checks, NOT Claude: does it compile, is it free of
    `unsafe`, and does it run to completion without crashing?"""
    src_path = tmpdir / f"modern_{variant}.rs"
    src_path.write_text(rust_source)
    bin_path = tmpdir / f"modern_bin_{variant}"

    unsafe_check = check_no_unsafe_blocks(rust_source)

    compile_result = subprocess.run(  # nosec B603 B607
        ["rustc", "-O", "-o", str(bin_path), str(src_path)],
        capture_output=True, text=True, timeout=60,
    )
    if compile_result.returncode != 0:
        return {"compiled": False, "unsafe_check": unsafe_check, "ran": False,
                "error": compile_result.stderr}

    run_result = subprocess.run([str(bin_path)], capture_output=True, text=True, timeout=10)  # nosec B603
    ran_clean = run_result.returncode == 0
    return {"compiled": True, "unsafe_check": unsafe_check, "ran": ran_clean,
            "stderr": run_result.stderr[:500] if not ran_clean else None}


def main() -> None:
    client = AnthropicClient()
    results = {}

    with tempfile.TemporaryDirectory(prefix="cpp_to_rust_bench_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        print("Fetching Juliet support files (std_testcase.h, std_testcase_io.h, io.c)...")
        fetch_support_files(tmpdir)

        for variant, description in VARIANTS.items():
            print(f"\n=== Variant {variant}: {description} ===")
            url = JULIET_TESTCASE_BASE.format(variant=variant)
            c_source = fetch(url)

            print("  Compiling + running the real _bad() function under AddressSanitizer...")
            bad_result = compile_and_run_bad_c(c_source, variant, tmpdir)
            print(f"  Bug confirmed real in this variant: {bad_result['crashed']}")

            print("  Claude analyzing for memory-safety risk...")
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
    bug_confirmed = sum(1 for r in results.values() if r["bad_c"]["crashed"])
    cwe_identified = sum(1 for r in results.values() if r["cwe_identified"])
    rust_fully_safe = sum(
        1 for r in results.values()
        if r["rust"]["compiled"] and r["rust"]["unsafe_check"]["ok"] and r["rust"]["ran"]
    )

    print("\n=== Summary ===")
    print(f"Variants tested: {total}")
    print(f"Real bug confirmed under ASan: {bug_confirmed}/{total}")
    print(f"CWE-{EXPECTED_CWE_NUMBER} correctly identified: {cwe_identified}/{total}")
    print(f"Rust compiled + zero unsafe + ran clean: {rust_fully_safe}/{total}")

    (ROOT / "benchmark_modernization_result.json").write_text(json.dumps(results, indent=2) + "\n")
    print("\nWrote benchmark_modernization_result.json")


if __name__ == "__main__":
    main()
