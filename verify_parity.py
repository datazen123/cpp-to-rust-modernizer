"""
Deterministic cross-language verification harness - not something Claude is
trusted to judge itself, exactly like every other verifier in this
portfolio. Three independent checks, all required to pass:

1. Standard behavioral parity: compile legacy/asset_risk.c (with
   AddressSanitizer instrumentation) and modernized/asset_risk.rs, run both
   against the same valid sample records via stdin, and diff every output
   field.

2. The actual point of this repo - a live memory-safety proof, not a claim:
   run the ASan-instrumented legacy C binary against a crafted, real
   overflow-triggering input and confirm AddressSanitizer genuinely reports
   a stack-buffer-overflow (the vulnerability is observed, not asserted).
   Then run the modernized Rust binary against the identical input and
   confirm it does NOT crash - the DARPA TRACTOR value proposition (see
   README), made concrete and runnable rather than just claimed.

3. A cheap, real static check used in actual Rust security review (the same
   metric tools like cargo-geiger report): counts `unsafe` keyword
   occurrences in the generated Rust. Using `unsafe` to just re-implement
   the C bug would defeat the entire point of this migration, so this is a
   hard gate, not a suggestion.

Run standalone:
    python verify_parity.py
(requires legacy/asset_risk.c and modernized/asset_risk.rs to both exist -
run `python modernize.py` first if modernized/asset_risk.rs is missing.)
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
LEGACY_C = ROOT / "legacy" / "asset_risk.c"
MODERN_RS = ROOT / "modernized" / "asset_risk.rs"
VALID_INPUT = ROOT / "data" / "sample_assets.txt"
ADVERSARIAL_INPUT = ROOT / "data" / "adversarial_overflow_input.txt"

LEGACY_BIN = Path("/tmp/cpp_to_rust_legacy_bin")
MODERN_BIN = Path("/tmp/cpp_to_rust_modern_bin")

FIELDS = ["id", "days_since_check", "is_overdue", "risk"]
UNSAFE_RE = re.compile(r"\bunsafe\b")


def compile_legacy() -> tuple[bool, str]:
    result = subprocess.run(
        ["clang", "-fsanitize=address", "-g", "-O0", "-o", str(LEGACY_BIN), str(LEGACY_C)],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode == 0, result.stderr


def compile_modern(rust_path: Path = MODERN_RS) -> tuple[bool, str]:
    result = subprocess.run(
        ["rustc", "-O", "-o", str(MODERN_BIN), str(rust_path)],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode == 0, result.stderr


def parse_output(text: str) -> list[dict] | None:
    """Returns None (not []) on any malformed line - a modernized binary
    that emits garbage should fail loudly, not silently compare as empty."""
    rows = []
    for line in text.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 4:
            return None
        try:
            rows.append({
                "id": parts[0],
                "days_since_check": int(parts[1]),
                "is_overdue": parts[2] in ("1", "true", "True"),
                "risk": parts[3],
            })
        except ValueError:
            return None
    return rows


def run_binary(binary: Path, input_path: Path, timeout: int = 10) -> subprocess.CompletedProcess:
    with open(input_path) as f:
        return subprocess.run([str(binary)], stdin=f, capture_output=True, text=True, timeout=timeout)


def check_standard_parity() -> dict:
    """Runs both binaries against the same valid input, diffs every field.
    Pure orchestration + comparison - no LLM judgment involved."""
    legacy_proc = run_binary(LEGACY_BIN, VALID_INPUT)
    modern_proc = run_binary(MODERN_BIN, VALID_INPUT)

    if legacy_proc.returncode != 0:
        return {"ok": False, "error": f"legacy binary crashed on valid input (exit {legacy_proc.returncode}): {legacy_proc.stderr[:500]}"}
    if modern_proc.returncode != 0:
        return {"ok": False, "error": f"modern binary crashed on valid input (exit {modern_proc.returncode}): {modern_proc.stderr[:500]}"}

    legacy_rows = parse_output(legacy_proc.stdout)
    modern_rows = parse_output(modern_proc.stdout)
    if legacy_rows is None:
        return {"ok": False, "error": f"could not parse legacy output:\n{legacy_proc.stdout}"}
    if modern_rows is None:
        return {"ok": False, "error": f"could not parse modern output (malformed line):\n{modern_proc.stdout}"}

    legacy_rows.sort(key=lambda r: r["id"])
    modern_rows.sort(key=lambda r: r["id"])

    if len(legacy_rows) != len(modern_rows):
        return {"ok": False, "error": f"row count mismatch: legacy={len(legacy_rows)} modern={len(modern_rows)}",
                "field_mismatches": []}

    field_mismatches = []
    for l, m in zip(legacy_rows, modern_rows):
        for field in FIELDS:
            if l[field] != m[field]:
                field_mismatches.append({"id": l["id"], "field": field, "legacy": l[field], "modern": m[field]})

    return {"ok": len(field_mismatches) == 0, "field_mismatches": field_mismatches,
            "legacy_count": len(legacy_rows), "modern_count": len(modern_rows)}


def check_memory_safety_proof() -> dict:
    """The actual proof: legacy C really does corrupt memory on this exact
    input (ASan catches it live, not asserted), and the Rust replacement
    really does handle the identical input without crashing."""
    legacy_proc = run_binary(LEGACY_BIN, ADVERSARIAL_INPUT)
    legacy_asan_triggered = "AddressSanitizer" in legacy_proc.stderr and legacy_proc.returncode != 0

    modern_proc = run_binary(MODERN_BIN, ADVERSARIAL_INPUT)
    modern_crashed = modern_proc.returncode != 0

    return {
        "ok": legacy_asan_triggered and not modern_crashed,
        "legacy_asan_triggered": legacy_asan_triggered,
        "legacy_exit_code": legacy_proc.returncode,
        "legacy_asan_summary": next((l for l in legacy_proc.stderr.splitlines() if "SUMMARY" in l), None),
        "modern_crashed": modern_crashed,
        "modern_exit_code": modern_proc.returncode,
        "modern_stderr": modern_proc.stderr[:500] if modern_crashed else None,
        "modern_output": modern_proc.stdout.strip(),
    }


def check_no_unsafe_blocks(rust_source: str) -> dict:
    """Deterministic static check, not an LLM judgment call - the same
    "count unsafe usage" metric real-world tools like cargo-geiger report.
    Using `unsafe` to just re-implement the C bug in Rust would defeat the
    entire point of this migration, so this is a hard gate."""
    count = len(UNSAFE_RE.findall(rust_source))
    return {"ok": count == 0, "unsafe_keyword_count": count}


def run_full_verification(rust_path: Path = MODERN_RS) -> dict:
    """Runs everything: compile both, the unsafe-block check, standard
    parity, and the memory-safety proof. Returns one combined result dict."""
    ok, err = compile_legacy()
    if not ok:
        return {"ok": False, "stage": "compile_legacy", "error": err}

    ok, err = compile_modern(rust_path)
    if not ok:
        return {"ok": False, "stage": "compile_modern", "error": err}

    unsafe_check = check_no_unsafe_blocks(rust_path.read_text())
    parity = check_standard_parity()
    safety = check_memory_safety_proof()

    overall_ok = unsafe_check["ok"] and parity.get("ok", False) and safety["ok"]
    return {
        "ok": overall_ok,
        "stage": "verification",
        "unsafe_check": unsafe_check,
        "parity": parity,
        "safety_proof": safety,
    }


def main() -> None:
    if not MODERN_RS.exists():
        print(f"{MODERN_RS} not found - run `python modernize.py` first.", file=sys.stderr)
        sys.exit(1)
    result = run_full_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
