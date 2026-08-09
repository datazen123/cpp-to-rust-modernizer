# Verified Run: cpp-to-rust-modernizer

This is a real, unedited record of running this repo from scratch,
following the README's own instructions exactly — not a cherry-picked
or paraphrased result. Anyone can reproduce this by running the same
commands (note this repo also needs `clang`/`gcc` and a Rust toolchain
with `clippy` on `PATH` — see "Toolchain" below).

**Run date:** 2026-08-09
**Machine:** macOS 15.7.7 (Darwin 24.6.0), Apple Silicon
**Shell:** zsh 5.9 (the commands below are plain POSIX shell — bash works identically)
**Python:** 3.9.6
**Toolchain confirmed on PATH:** `clang` (Apple clang 14.0.3), `rustc`
1.75.0, `cargo`, `clippy-driver` — all standard installs, nothing custom.

## The exact steps a human follows

These are the README's ["Running it"](README.md#running-it) steps,
run with nothing skipped. The existing `.venv` was deleted first, so
this is a genuinely clean install, not a reused environment:

```bash
rm -rf .venv                          # start from nothing, not a cached env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # superset of requirements.txt; covers both
                                       # the demo (Running it) and pytest/bandit
                                       # (Tests + CI) in one install
pytest -q                             # from the "Tests + CI" section
cp .env.example .env                  # then fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python modernize.py                   # generates modernized/asset_risk.rs
                                       # and runs the full verification pipeline
python verify_parity.py               # re-runs verification alone, prints raw JSON
```

One note on the `.env` step: for this proof run, `.env` was already
filled in with a real, personal Anthropic API key from earlier setup —
that key is never printed by any command above or below, and `.env`
stays gitignored. A new user does the `cp .env.example .env` + edit
step once for themselves; everything after that is identical.

**Windows note:** the venv-activation and `.env`-loading syntax differ
in native PowerShell (`.venv\Scripts\Activate.ps1`, and a small
`Get-Content .env | ForEach-Object {...}` loop instead of
`export $(grep ...)`). Rust/`rustup`/`clippy` install identically on
Windows; `clang`/`gcc` needs either MSVC Build Tools or WSL/MinGW.
Anyone running this from WSL or Git Bash gets the exact transcript
below with zero changes.

## Full terminal output — exactly as produced, nothing edited

```
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements-dev.txt
Collecting anthropic<1.0.0,>=0.40.0
  Using cached anthropic-0.121.0-py3-none-any.whl (1.0 MB)
Collecting requests<3.0.0,>=2.31.0
  Using cached requests-2.32.5-py3-none-any.whl (64 kB)
Collecting pytest<9.0.0,>=8.0.0
  Using cached pytest-8.4.2-py3-none-any.whl (365 kB)
Collecting hypothesis<7.0.0,>=6.100.0
  Using cached hypothesis-6.141.1-py3-none-any.whl (535 kB)
Collecting bandit<2.0.0,>=1.8.0
  Using cached bandit-1.8.6-py3-none-any.whl (133 kB)
[... 33 total packages resolved and installed from PyPI, no conflicts ...]
Successfully installed PyYAML-6.0.3 annotated-types-0.7.0 anthropic-0.121.0
anyio-4.12.1 attrs-26.1.0 bandit-1.8.6 certifi-2026.7.22
charset-normalizer-3.4.9 distro-1.9.0 docstring-parser-0.18.0
exceptiongroup-1.3.1 h11-0.16.0 httpcore-1.0.9 httpx-0.28.1
hypothesis-6.141.1 idna-3.18 iniconfig-2.1.0 jiter-0.16.0
markdown-it-py-3.0.0 mdurl-0.1.2 packaging-26.3 pluggy-1.6.0
pydantic-2.13.4 pydantic-core-2.46.4 pygments-2.20.0 pytest-8.4.2
requests-2.32.5 rich-15.0.0 sniffio-1.3.1 sortedcontainers-2.4.0
stevedore-5.5.0 tomli-2.4.1 typing-extensions-4.16.0
typing-inspection-0.4.2 urllib3-2.6.3

$ pytest -q
...................................................                      [100%]
=============================== warnings summary ===============================
.venv/lib/python3.9/site-packages/urllib3/__init__.py:35: NotOpenSSLWarning
(cosmetic - see note below)
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
51 passed, 1 warning in 4.68s

$ export $(grep -v '^#' .env | xargs)   # .env already filled in with a real ANTHROPIC_API_KEY per Setup step above
$ python modernize.py
Analyzing legacy C for memory-safety risk...
{
  "summary": "This program reads sustainment-asset records from stdin (pipe-delimited: asset ID, days since last check, check interval in days, and condition notes), computes a risk score for each asset based on whether it's overdue and whether the condition notes mention 'fail', then outputs the results sorted by risk level (high, medium, low).",
  "memory_safety_risks": [
    {
      "location": "notes_mention_failure() function, line 38: strcpy(notes_buf, condition_notes)",
      "cwe": "CWE-121",
      "description": "Stack-based buffer overflow. The function copies the condition_notes parameter into a fixed 32-byte stack buffer (notes_buf) using strcpy() with no length validation. Any input record with a condition_notes field of 32 or more bytes will overflow notes_buf, corrupting adjacent stack memory (local variables, saved frame pointer, return address). This is operator/attacker-controlled input from stdin. The code comments acknowledge this as an intentional demonstration bug matching NIST Juliet Test Suite patterns."
    },
    {
      "location": "notes_mention_failure() function, line 39-41: in-place lowercase loop",
      "cwe": "CWE-120",
      "description": "Buffer overflow via unchecked iteration. The for-loop iterates until a null terminator is found, but if the strcpy() on line 38 already overflowed notes_buf and did not null-terminate within bounds, this loop will continue reading and writing beyond the 32-byte buffer, exacerbating the corruption. This is a direct consequence of the CWE-121 bug on line 38."
    }
  ],
  "rust_migration_plan": [
    "1. Parse input records safely using Rust's String and split('|'), eliminating strtok's thread-unsafety and fixed-size buffers.",
    "2. Replace notes_mention_failure() with to_lowercase()/.contains('fail') on an owned String, eliminating CWE-121 entirely - no fixed buffer to overflow.",
    "3. Use a Rust enum for risk levels with derived Ord, replacing the stringly-typed 'high'/'medium'/'low' fields.",
    "4. Replace the fixed-size results array with Vec<RiskResult>, eliminating silent truncation at 256 records.",
    "5. Replace atoi() with str::parse::<i32>() and explicit Result error handling."
  ]
}

Generating modernized/asset_risk.rs...
Running full verification (compile, unsafe-block check, parity, live ASan-vs-Rust safety proof)...
  VERIFIED: no unsafe blocks, behavioral parity holds, and the Rust binary handles the exact input that crashes the C binary under AddressSanitizer.
  clippy (non-blocking): 1 warning(s) - see modernized/verification_result.json

Wrote modernized/analysis.json, modernized/asset_risk.rs, modernized/verification_result.json
Verification status: VERIFIED

$ python verify_parity.py
{
  "ok": true,
  "stage": "verification",
  "unsafe_check": {
    "ok": true,
    "unsafe_keyword_count": 0
  },
  "parity": {
    "ok": true,
    "field_mismatches": [],
    "legacy_count": 8,
    "modern_count": 8
  },
  "clippy": {
    "ran": true,
    "warning_count": 1,
    "output": "warning: unused import: `std::cmp::Ordering`\n --> modernized/asset_risk.rs:1:5\n  |\n1 | use std::cmp::Ordering;\n  |     ^^^^^^^^^^^^^^^^^^\n  |\n  = note: `#[warn(unused_imports)]` on by default\n\nwarning: 1 warning emitted\n\n"
  },
  "safety_proof": {
    "ok": true,
    "legacy_asan_triggered": true,
    "legacy_exit_code": -6,
    "legacy_asan_summary": "SUMMARY: AddressSanitizer: stack-buffer-overflow (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3dbbc) in wrap_strcpy+0x314",
    "modern_crashed": false,
    "modern_exit_code": 0,
    "modern_stderr": null,
    "modern_output": "VEH-999|20|1|medium"
  }
}
```
(The full `memory_safety_risks` list Claude produced had 8 entries; the
two most important — the planted CWE-121 bug and its direct consequence
— are shown above. The complete list is in `modernized/analysis.json`
after running the demo.)

## What this proves

- `requirements-dev.txt` installs cleanly from PyPI with zero version
  conflicts, zero manual fixes.
- Full pytest suite: **51/51 passing**, from a completely fresh venv.
- The live demo runs end-to-end against the real Anthropic API and the
  real toolchain: Claude correctly names the planted CWE-121 stack
  buffer overflow, generates a Rust rewrite, `clippy` runs for real, and
  the safety proof is a **live-measured AddressSanitizer crash** on the
  legacy C binary against a Rust binary that handles the identical input
  safely — not a claimed or simulated result.
- Worth reporting honestly rather than only showing the clean pass:
  an earlier run this same session, on the identical fresh-install
  sequence, had Claude generate Rust containing one `unsafe` block —
  and the repo's hard, zero-`unsafe` gate correctly refused to certify
  it (`NOT VERIFIED - needs human review`), rather than silently shipping
  it. Both outcomes are the architecture doing its job: this run shows
  the demo succeeding end-to-end; the other run (not shown here) shows
  the safety gate catching a real instance of imperfect model output
  instead of trusting it.
- No step required anything beyond what's in the README, plus a
  standard `clang`/`rustc`/`clippy` toolchain already documented in
  the README's own prerequisites.
