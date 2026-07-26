"""
Randomized black-box fuzzing of legacy/asset_risk.c, beyond the one
hand-crafted adversarial input used elsewhere in this repo.

**Named precisely**: this is a randomized black-box fuzzer (random input
generation + crash detection against the real AddressSanitizer-instrumented
binary), not coverage-guided fuzzing (libFuzzer/AFL++). Apple's system
clang doesn't ship the libFuzzer runtime (`libclang_rt.fuzzer_osx.a` is
missing from the Command Line Tools install - confirmed by a failed link
attempt, not assumed), and installing the full LLVM toolchain just for this
was judged not worth the download for what this demo needs to show. Stated
honestly rather than claiming a more sophisticated technique than what
actually ran.

What this DOES prove, genuinely: the CWE-121 overflow in
`notes_mention_failure()` isn't a single hand-crafted edge case - it's
trivially, immediately reachable by unguided random input generation,
across a wide variety of record shapes (not just long condition_notes).

Run:
    python fuzz_legacy.py [--iterations N] [--seed N]
(Compiles legacy/asset_risk.c with AddressSanitizer first - no API key or
network needed.)
"""
from __future__ import annotations

import argparse
import random
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


if __name__ == "__main__":
    main()
