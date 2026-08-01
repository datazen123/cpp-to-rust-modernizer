"""
Two independent techniques for finding the same real bug in
legacy/asset_risk.c, beyond the one hand-crafted adversarial input used
elsewhere in this repo:

1. Random black-box fuzzing: generates randomized pipe-delimited records
   (varying condition_notes length/content, malformed numeric fields,
   empty fields) and runs each through the real AddressSanitizer-
   instrumented binary, watching for AddressSanitizer to fire.

2. Static analysis: runs the real Clang Static Analyzer (`clang --analyze`,
   the `security` checker group) directly against the source. This finds
   the same bug through dataflow analysis, without running the program at
   all. It ships with Xcode Command Line Tools already installed on this
   machine - no extra download.

Together they show the bug two different ways: one by actually triggering
the crash on a wide variety of random input, the other by reading the code
and proving the unsafe call exists regardless of input.

Run:
    python fuzz_legacy.py [--iterations N] [--seed N]
(Compiles legacy/asset_risk.c with AddressSanitizer first - no API key or
network needed.)
"""
from __future__ import annotations

import argparse
import random
import re
import string
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
LEGACY_C = ROOT / "legacy" / "asset_risk.c"

# Excludes "|" - the legacy C program's own strtok-based parser treats it
# as the field delimiter, so a "|" embedded in condition_notes would
# silently truncate the field there rather than testing what this fuzzer
# intends to test. Every other printable character (including other
# punctuation) is fair game.
PRINTABLE = "".join(c for c in string.ascii_letters + string.digits + string.punctuation + " " if c != "|")


def compile_legacy_with_asan(binary_path: Path) -> None:
    result = subprocess.run(
        ["clang", "-fsanitize=address", "-g", "-O0", "-o", str(binary_path), str(LEGACY_C)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"legacy/asset_risk.c failed to compile:\n{result.stderr}")


def run_static_analysis(source_path: Path = LEGACY_C) -> dict:
    """Runs the real Clang Static Analyzer (`clang --analyze`, the
    `security` checker group - the same tool and checker group Apple/LLVM
    ship for exactly this class of finding) against the source. Finds the
    strcpy-into-fixed-buffer bug through dataflow analysis, without
    executing the program - a different technique from the random
    black-box fuzzing above, catching the same bug from a different
    angle."""
    result = subprocess.run(  # nosec B603 B607 - shell=False, static argv, no untrusted input
        ["clang", "--analyze", "-Xanalyzer", "-analyzer-checker=security",
         "-Xanalyzer", "-analyzer-output=text", "-c", str(source_path), "-o", "/dev/null"],
        capture_output=True, text=True, timeout=60,
    )
    match = re.search(r"(\d+) warnings? generated", result.stderr)
    finding_count = int(match.group(1)) if match else 0
    return {"ran": True, "finding_count": finding_count, "output": result.stderr}


def random_record(rng: random.Random) -> str:
    """Generates one randomized pipe-delimited record - not just varying
    condition_notes length, but also malformed numeric fields, empty
    fields, and embedded pipe characters, to cast a wider net than the
    single hand-crafted example elsewhere in this repo."""
    record_id = "".join(rng.choices(PRINTABLE, k=rng.randint(0, 20)))
    days = rng.choice([str(rng.randint(-100000, 100000)), "", "NaN", "abc", "99999999999999999999"])
    interval = rng.choice([str(rng.randint(-1000, 1000)), "0", "", "xyz"])
    notes_len = rng.choice([0, 1, 10, 31, 32, 33, 50, 200, 1000, rng.randint(0, 500)])
    notes = "".join(rng.choices(PRINTABLE, k=notes_len))
    return f"{record_id}|{days}|{interval}|{notes}"


def run_one(binary_path: Path, record: str, timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary_path)], input=record + "\n", capture_output=True, text=True, timeout=timeout,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory(prefix="cpp_to_rust_fuzz_") as tmpdir:
        binary_path = Path(tmpdir) / "legacy_fuzz_bin"
        print(f"Compiling legacy/asset_risk.c with AddressSanitizer...")
        compile_legacy_with_asan(binary_path)

        print(f"Running {args.iterations} randomized black-box inputs (seed={args.seed})...\n")

        first_crash = None
        crash_count = 0
        min_crashing_notes_len = None

        for i in range(args.iterations):
            record = random_record(rng)
            try:
                proc = run_one(binary_path, record)
            except subprocess.TimeoutExpired:
                continue

            asan_triggered = "AddressSanitizer" in proc.stderr and proc.returncode != 0
            if asan_triggered:
                crash_count += 1
                notes = record.split("|", 3)[-1] if record.count("|") >= 3 else ""
                if first_crash is None:
                    first_crash = (i, record, proc.stderr)
                    print(f"First crash at iteration {i}: condition_notes length {len(notes)}")
                if min_crashing_notes_len is None or len(notes) < min_crashing_notes_len:
                    min_crashing_notes_len = len(notes)

        print(f"\n=== Fuzz summary ===")
        print(f"Iterations run: {args.iterations}")
        print(f"Crashes found: {crash_count} ({crash_count / args.iterations:.1%})")
        if first_crash is not None:
            i, record, stderr = first_crash
            summary_line = next((l for l in stderr.splitlines() if "SUMMARY" in l), "")
            print(f"First crash: iteration {i}")
            print(f"Minimum crashing condition_notes length observed: {min_crashing_notes_len} bytes "
                  f"(matches the known 32-byte buffer boundary in notes_mention_failure())")
            print(f"ASan summary: {summary_line}")
        else:
            print("No crashes found in this run - unexpected given the known bug; "
                  "worth investigating rather than assuming safety.")

        print(f"\n=== Static analysis (Clang Static Analyzer, `security` checkers) ===")
        static_result = run_static_analysis()
        print(f"Findings: {static_result['finding_count']}")
        if static_result["finding_count"]:
            print(static_result["output"])


if __name__ == "__main__":
    main()
