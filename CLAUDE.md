# Context for Claude Code working in this repo

This repo is one of a **10-repo public portfolio** (github.com/datazen123)
demonstrating real, live-verified agentic AI engineering for a specific
DoD-contractor job pursuit. Full README below covers this repo in detail;
this file covers conventions and status a coding agent needs before making
changes.

## This repo's role

Claude-driven C-to-Rust migration, targeting the same CWE-121 class of bug
behind memory-safety migration efforts industry-wide (NSA/CISA, the White
House ONCD, MISRA C's safety-critical lineage, and - as one concrete
funded example - DARPA's TRACTOR program via GrammaTech,
`HR001123C0079`, $1.5M; see README "Why this exists" for the full
picture). `legacy/asset_risk.c` has a
real, genuinely-triggerable CWE-121 stack buffer overflow (confirmed live
under AddressSanitizer). `verify_parity.py` is the deterministic proof
engine: compiles both languages, checks standard behavioral parity,
proves the C binary crashes on an adversarial input under ASan AND the
Rust binary handles the identical input safely, checks for zero `unsafe`
blocks (hard gate), and runs real `clippy` (reported, non-blocking).
`fuzz_legacy.py` adds randomized black-box fuzzing beyond the one
hand-crafted adversarial input.

**Status (2026-08-10)**: 67/67 tests passing, live-verified end-to-end
(first attempt, no correction pass needed on the last full run). Generated
Rust now derives `Ord` on a `RiskLevel` enum instead of a stringly-typed
risk field, and writes through a single `BufWriter` - see README "Rust
practices, grounded in real sources". Fuzzing result: 663/2000 random
inputs crash the legacy binary (33.1%), minimum crashing `condition_notes`
length exactly 32 bytes - matching the known buffer boundary precisely.
`self_consistency_check.py` now also runs discrete semantic entropy
(Farquhar et al., *Nature* 2024) over the sampled `summary` text from
`analyze()`, in `semantic_entropy.py` - the one signal this repo's
self-consistency check didn't have before, since `analyze()` has no
severity field to majority-vote. See README "Self-consistency check" for
the live-measured result (default samples bumped 3->5 per the paper's
own guidance).

**Toolchain note**: this repo needs `clang`/`gcc`, `rustc`, and
`clippy-driver` on `PATH` (see README "Running it"). The original
development machine didn't have Rust pre-installed - see this portfolio's
private cross-repo context repo's CLAUDE.md for the exact setup commands
used, or just `rustup component add clippy` on a standard rustup install
(CI already handles this via `dtolnay/rust-toolchain@stable`).
`fuzz_legacy.py` runs two independent bug-finding techniques against
`legacy/asset_risk.c`: a randomized black-box fuzzer (Apple clang lacks
the libFuzzer runtime needed for coverage-guided fuzzing) and the real
Clang Static Analyzer (`clang --analyze`, `security` checker group, ships
with Xcode Command Line Tools - no extra install), which finds the same
bug via dataflow analysis instead of execution. See README "Finding the
bug two ways".

## Non-negotiable discipline this whole portfolio follows

1. Never fabricate a source - every real-data claim is independently
   fetched/verified. If a primary source can't be reached, say so plainly
   (this repo's own `fuzz_legacy.py` docstring is a direct example of
   this - it documents the failed libFuzzer link attempt rather than
   silently using a lesser technique without saying so).
2. Deterministic code owns any mechanical computation/decision (the
   parity check, the safety proof, the unsafe-block count); Claude only
   handles generation and explanation.
3. Live-verify against the real Anthropic API before claiming a result.
4. Synthetic demo data is always labeled as synthetic; real data (the
   NIST Juliet Test Suite file in `benchmark.py`) is cited with exact
   source/CWE IDs.
5. Pytest suite (including Hypothesis property-based tests), GitHub
   Actions CI (pytest + bandit, non-blocking on low severity), "Security
   notes" README section, pinned dependencies.
6. No real client, unit, or classified-sounding content ever - the
   planted CWE-121 bug is intentional and clearly documented as such.
7. Ask Sage (not Claude directly) is named as the realistic DoD/DIB
   production deployment path.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY, never commit it
pytest -q
```

Full cross-repo strategy, founder research, and environment notes live in
this portfolio's private cross-repo context repo - not duplicated here
since this repo is public.
