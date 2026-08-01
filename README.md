# cpp-to-rust-modernizer

Old C code can crash - or get hijacked - if it's fed input longer than it
expects, like water overflowing a cup and soaking whatever's next to it.
This repo takes one small, realistic example of that kind of bug, has
Claude rewrite it in Rust (a newer language built so that specific mistake
can't happen), and then proves it: a separate program actually runs both
versions and confirms the old one really does crash and the new one
really doesn't. Claude doesn't get to grade its own work - something else
checks it.

The code and sample data here are made up for this demo, not from a real
system. The bug itself is real, though - not a toy example. (For the full
technical detail - the exact function, line, and vulnerability class - see
"The real bug" below.)

## Why this exists

This repo follows the same architecture as this portfolio's other
legacy-modernization demos - analyze → generate → deterministically
verify → bounded corrective retry - applied here to C-to-Rust migration
specifically.

**The underlying problem is global, not agency-specific.** A stack-based
buffer overflow like the one in `legacy/asset_risk.c` is the same bug
class behind real incidents across aviation, automotive, medical devices,
and industrial control systems - anywhere C/C++ still runs code that
can't be allowed to crash or be corrupted. That's the entire reason
**[MISRA C](https://misra.org.uk/)** exists: a coding standard originally
built for the automotive industry, now used across aerospace, rail,
industrial, and medical-device software specifically to eliminate
undefined-behavior bugs like this one.

A few real, checkable data points on how broad this shift already is:

- The White House Office of the National Cyber Director's **February 2024**
  report, *"Back to the Building Blocks: A Path Toward Secure and
  Measurable Software,"* calls on the software industry generally - not
  just government contractors - to move away from memory-unsafe languages
  like C/C++ for exactly this class of bug.

- **NSA and CISA's own published guidance** (2022 NSA Cybersecurity
  Information Sheet, reinforced by CISA's Dec 2023 "The Case for Memory
  Safe Roadmaps" and a June 2025 update) names the languages it recommends
  as C/C++ replacements: **C#, Go, Java, Python, Ruby, Rust, and Swift**
  (verified against multiple independent secondary sources after an
  earlier automated web-search summary incorrectly added JavaScript to
  this list - corrected here rather than repeated). CISA has set a
  **January 1, 2026** deadline for organizations to publish memory-safety
  roadmaps.

- One concrete, currently-funded example of this shift already in motion:
  DARPA's **TRACTOR** program is paying **GrammaTech, Inc.**
  (`HR001123C0079`, **$1,499,786**, **2023-02-28 → 2026-09-16**, active
  right now) to build AI-assisted C++-to-Rust migration with automated
  correctness verification - the same two-part shape (generate, then
  independently verify) this repo implements at a much smaller scale.
  https://www.usaspending.gov/award/CONT_AWD_HR001123C0079_9700_-NONE-_-NONE-

## The real bug

`legacy/asset_risk.c`'s `notes_mention_failure()` copies an operator-
supplied `condition_notes` field into a fixed 32-byte stack buffer with
`strcpy()` and no length check - classic **CWE-121: Stack-based Buffer
Overflow**, the exact category NIST's Juliet Test Suite catalogs and
NSA/CISA's guidance cites by name. It's not contrived to only trigger on
adversarial input: any condition note of 32+ characters overflows it,
including entirely mundane-looking maintenance notes.

```
$ clang -fsanitize=address -g -O0 -o legacy_bin legacy/asset_risk.c
$ echo 'VEH-999|20|14|this note is deliberately much longer than thirty two bytes...' | ./legacy_bin
==14466==ERROR: AddressSanitizer: stack-buffer-overflow ...
WRITE of size 95 at ... thread T0
    #1 0x... in notes_mention_failure asset_risk.c:44
    #2 0x... in compute_risk asset_risk.c:65
==14466==ABORTING
```

This is a live, reproduced crash, not an assertion - `verify_parity.py`
re-runs this exact check every time.

## Architecture

```
legacy/asset_risk.c  (real CWE-121 stack buffer overflow, see above)
        |
        v
  modernize.py: analyze()  --(Claude)-->  modernized/analysis.json
                                            (names the exact CWE + line)
        |
        v
  modernize.py: generate_modern_rust()  --(Claude)-->  modernized/asset_risk.rs
        |
        v
  verify_parity.py -- deterministic, NOT Claude:
    1. compile legacy C (AddressSanitizer) and modernized Rust
    2. unsafe-block check: grep the Rust for `unsafe` (same metric
       cargo-geiger reports) - a hard gate, not a suggestion
    3. standard parity: same valid input -> same output on every field
    4. THE PROOF: run the adversarial input through both binaries -
       legacy MUST crash under ASan, modern MUST NOT crash
        |
        v
  ok? -> done, VERIFIED
  not ok? -> exact failure fed back to Claude, ONE corrective rewrite,
             re-verify. Still failing? -> printed plainly as NOT VERIFIED,
             not shipped as if it were.
```

- `llm_client.py` - thin provider adapter, same interface as every other
  repo in this portfolio. Anthropic is the tested backend; OpenAI and Ask
  Sage adapters are included but unverified.
- `modernize.py` - the two Claude calls, plus the correction-prompt builder
  for each of the four ways verification can fail (compile error, unsafe
  block, parity mismatch, safety-proof failure).
- `verify_parity.py` - the actual proof, callable standalone
  (`python verify_parity.py`) or from `modernize.py`.

## Rust practices, grounded in real sources

The generation prompt in `modernize.py` requires patterns drawn from real,
established Rust engineering references - not invented house style:

- **[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)**
  (the official rust-lang project) - use the type system instead of
  stringly-typed data. `risk` is a proper `enum RiskLevel`, not a `String`
  - the compiler guarantees there are exactly three tiers, not "whatever
  text happened to be assigned this time."

- **[The Rust Performance Book](https://nnethercote.github.io/perf-book/)**
  (Nicholas Nethercote - the standard community reference for Rust
  performance) - lock stdout once and write through a single buffered
  writer, instead of one `println!` syscall per output record.

- **RustBelt** (Jung, Jourdan, Krebbers, Dreyer - *Proc. ACM Program.
  Lang.* 2, POPL, Article 66, 2018) - the peer-reviewed, machine-checked
  formal proof that Rust's ownership type system is actually memory-safe
  when `unsafe` isn't used. This is the theoretical grounding behind why
  this repo's zero-`unsafe` hard gate (see Architecture above) is a real
  safety guarantee, not a style preference.

- Two peer-reviewed empirical studies on where Rust's safety guarantees
  actually break down in practice - both point at the same place, `unsafe`
  code: **["Understanding Memory and Thread Safety Practices and Issues in
  Real-World Rust Programs"](https://cseweb.ucsd.edu/~yiying/RustStudy-PLDI20.pdf)**
  (Qin et al., PLDI 2020) and
  **["Is Rust Used Safely by Software Developers?"](https://www.cs.virginia.edu/~bjc8c/papers/evans20rust.pdf)**
  (Evans, Campbell, Soffa, ICSE 2020). Both are part of why this repo
  treats the unsafe-block count as a hard gate rather than a suggestion.

## Live result

Run end-to-end against the real Anthropic API (`claude-sonnet-4-5`), first
attempt, no correction pass needed:

- **Analysis**: correctly named `CWE-121` at the exact `notes_mention_failure()`
  line, plus 7 additional, legitimate secondary observations about the
  same file (an unvalidated `atoi()` with no overflow/zero-division
  handling, a fragile `strncpy` null-termination pattern, an unbounded
  `fgets` line-splitting edge case, a `strcpy` onto a fixed buffer from
  string literals, a `strtok` dangling-pointer risk if the code were ever
  refactored, and silent truncation past `MAX_RECORDS`) - none are the
  planted bug, all are real, checkable observations about this file.
- **Generated Rust**: zero `unsafe` blocks; `risk` is a proper
  `enum RiskLevel` deriving `Ord` (not a `String`), output goes through a
  single locked `BufWriter`, and every function carries a `///` doc
  comment - the practices required in "Rust practices, grounded in real
  sources" above, not hand-tuned after the fact.
- **Verification**: `{"ok": true}` on all three gates - full detail in
  `modernized/verification_result.json`. The Rust binary handles the exact
  input that crashes the C binary under AddressSanitizer:
  `VEH-999|20|1|medium` printed cleanly, no crash.
- **clippy** (Rust's own standard linter, run via `clippy-driver` directly
  and reported but non-blocking - see "Static analysis" below): this run's
  generated code triggered 1 warning, `unused_imports` on
  `std::cmp::Ordering` (left over from deriving `Ord` on `RiskLevel`,
  which already provides `.cmp()`). Claude's output style varies run to
  run - this is whatever the most recent run actually produced.

## Static analysis

Beyond the three hard verification gates above, `verify_parity.py` also
runs real `clippy` against every generated Rust file and reports every
warning verbatim in `modernized/verification_result.json` - not a
simulated or hand-summarized lint pass. Unlike the unsafe-block/parity/
safety checks, clippy findings don't block verification: a style lint
isn't a memory-safety signal, and gating on it would risk unnecessary
correction-loop churn over stylistic preference rather than correctness.
It's surfaced for a human reviewer, not silently discarded.

## Finding the bug two ways

`fuzz_legacy.py` runs two independent techniques against the legacy binary,
beyond the one hand-crafted adversarial input used in `verify_parity.py`'s
safety proof:

**1. Random black-box fuzzing.** Generates randomized records (varying
`condition_notes` length/content, malformed numeric fields, empty fields)
and runs each through the real ASan-instrumented legacy binary, watching
for AddressSanitizer to fire.

Actual measured result (2,000 iterations, seed 42, ~30s runtime):
**663 crashes (33.1%)**. The very first randomly-generated record already
triggered AddressSanitizer, and the minimum crashing `condition_notes`
length observed across the whole run was exactly 32 bytes - precisely
matching the known fixed-buffer boundary in `notes_mention_failure()`. The
overflow isn't a narrow, hand-crafted edge case - it's the single most
common way to crash this program, reachable by unguided random input on
the first attempt.

**2. Static analysis.** Runs the real Clang Static Analyzer (`clang
--analyze`, the `security` checker group) directly against the source -
finding the bug through dataflow analysis, without running the program at
all. Ships with Xcode Command Line Tools; no extra install.

Actual measured result: **1 finding**, on the exact `strcpy` line, citing
CWE-119 (the parent category of the planted CWE-121):

```
legacy/asset_risk.c:46:5: warning: Call to function 'strcpy' is insecure
as it does not provide bounding of the memory buffer. [security.insecureAPI.strcpy]
```

```bash
python fuzz_legacy.py --iterations 2000 --seed 42
```

## Real-data benchmark

`benchmark.py` fetches a real file live from **NIST's own Juliet Test Suite
for C/C++ v1.3** (via a public GitHub mirror of the official SARD release).
The file (`CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c`)
is NIST-labeled in its own header comments as CWE-121.

**Actual measured result**: Claude correctly identified `CWE-121`, and
additionally flagged `CWE-676` (use of a dangerous function) on both the
"bad" and "good" variants in the file - a legitimate secondary observation,
since the "good" fix still uses `strcpy()`, just with a correctly-sized
buffer. Full analysis in `benchmark_report.md`.

This is a pass/fail check on one real, NIST-labeled case, not a
statistical benchmark - a sample size of one can't support a
precision/recall number.

```bash
python benchmark.py
```

## Deployment path

This demo calls the Anthropic API directly. A production version for a
DoD-adjacent client would more likely run through
**[Ask Sage](https://www.asksage.ai/)** - the IL5/IL6-authorized multi-model
gateway built for Defense Industrial Base contractors (`llm_client.py`
includes an `AskSageClient` built from Ask Sage's
[public API docs](https://github.com/Ask-Sage/AskSage-Open-Source-Community),
untested pending an account). Claude's status specifically at the DoD-
contract level has been politically contested since early 2026 (excluded
from GenAI.mil's provider list) - a reason to keep this adapter provider-
agnostic, not a reason to avoid building with Claude.

Worth noting for this specific repo: DARPA's own TRACTOR program (the real
contract cited above) is run by GrammaTech under a DARPA SBIR vehicle, not
via a direct-to-Anthropic API call - whatever model/gateway that program
actually uses internally is not publicly disclosed in the award data this
repo cites.

## Prerequisites

Python 3.9 or newer (`python3 --version`), plus `clang` (or `gcc`),
`rustc`, and `clippy-driver` on `PATH`. `clippy-driver` ships with
`rustup`'s `clippy` component (`rustup component add clippy`).

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python modernize.py
# or, once modernized/asset_risk.rs exists, re-run verification alone:
python verify_parity.py
```

The `python3 -m venv` step matters, not just good practice: on macOS,
plain `pip install` can silently resolve to a leftover Python 2.7
install instead of Python 3 - see Troubleshooting below.

## Troubleshooting

**`ERROR: Could not find a version that satisfies the requirement
anthropic<1.0.0,>=0.40.0 ... (from versions: none)`, alongside a "Python
2.7 reached end of life" warning:**

Your `pip` command is resolving to a Python 2.7 installation, not Python
3 - common on macOS, where an old Python 2.7 framework install can sit
earlier on `PATH` than Python 3. The `anthropic` package doesn't publish
anything for Python 2 at all, hence "no versions: none" - it's not a
network or permissions problem.

Fix: create and activate a virtual environment first, exactly as shown
above (`python3 -m venv .venv && source .venv/bin/activate`), then run
`pip install` again inside it. If you'd rather not use a venv, run
`python3 -m pip install -r requirements.txt` instead of bare `pip
install` - that forces the install through Python 3's own pip regardless
of what `pip` alone resolves to on your system.

## Tests + CI

`test_verify_parity.py` covers the deterministic parsing/checking functions
(`parse_output`, `check_no_unsafe_blocks`, `check_clippy`) with real
`clang`/`rustc`/`clippy-driver` runs where relevant. `test_modernize.py`
covers JSON/fence handling and every branch of the correction-prompt
builder (compile error, unsafe block, parity mismatch, safety-proof
failure). `test_benchmark.py` covers the CWE-matching logic.
`test_verify_parity_properties.py` adds Hypothesis property-based tests -
round-trip parsing across hundreds of generated ticket-shaped inputs,
"never crashes on arbitrary text," and word-boundary correctness for the
unsafe-keyword check across generated surrounding contexts, not just one
hand-picked example. `test_fuzz_legacy.py` covers the fuzzer's own
deterministic generation logic (delimiter exclusion, reproducibility given
a fixed seed) plus a live run of the Clang Static Analyzer against the
real buggy source, confirming it actually flags the bug. None need an API
key or network:

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Security notes

- API keys are read from environment variables only, never hardcoded;
  `.env` is gitignored, `.env.example` ships placeholders only.
- The planted CWE-121 overflow is real and genuinely triggerable - this is
  intentional and is the entire point of the demo, not an oversight. It
  lives only in `legacy/asset_risk.c`, is clearly commented as such, and
  the compiled binaries are never installed or run against untrusted
  network input.
- `subprocess` calls in `verify_parity.py` use explicit timeouts (60s
  compile, 10s run) so a hung compile or infinite loop in generated code
  can't hang the pipeline indefinitely.
- **Real `bandit` (Python security linter) findings, checked and fixed**:
  an earlier version used fixed, predictable `/tmp` filenames for compiled
  binaries - `bandit` flagged this correctly (`B108`, a symlink/race-
  condition class of issue on shared multi-user machines). Fixed by using
  `tempfile.mkdtemp()` (mode 0700, unpredictable name) instead of hardcoded
  paths. Remaining `bandit` findings (`B603`/`B607` - subprocess calls
  using `shell=False` with PATH-resolved compiler names) are the expected,
  low-severity shape of any program that shells out to `clang`/`rustc`/
  `clippy-driver` and are reported, not silently suppressed - CI runs
  `bandit` at `--severity-level medium`, so these low-severity findings are
  visible in the log but don't fail the build; a real medium+ finding
  would.
- A malformed/non-JSON model response raises a clear, actionable error
  (with the raw response attached) instead of an opaque traceback.
- Dependencies are version-pinned with an upper bound
  (`>=X,<NEXT_MAJOR`), not left open-ended.

Built with [Claude Code](https://claude.com/claude-code).
