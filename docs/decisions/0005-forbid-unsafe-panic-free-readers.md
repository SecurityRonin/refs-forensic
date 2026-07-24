# 5. `forbid(unsafe_code)` + panic-free bounds-checked little-endian readers

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable disk images**. The fleet's
Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`, "Security & Robustness
Standard") requires such crates to never panic, never read out of bounds, and
never trust a length field. ReFS is a little-endian on-disk format (Windows/NT
platform). This reader touches no `mmap` and needs no positioned I/O primitive, so
the `unsafe` mmap exception does not apply.

## Decision

- **`#![forbid(unsafe_code)]`** at the crate root (`core/src/lib.rs`), reinforced
  by `[workspace.lints.rust] unsafe_code = "forbid"` (root `Cargo.toml`). No
  bounded-allow downgrade — there is no `unsafe` to justify.
- **Panic-free lint posture**: `[workspace.lints.clippy]` denies `unwrap_used` and
  `expect_used`, denies `correctness`/`suspicious`, warns `all`/`pedantic` (root
  `Cargo.toml`); tests are exempted via `clippy.toml`
  (`allow-unwrap-in-tests`/`allow-expect-in-tests`) and
  `#![cfg_attr(test, allow(...))]`.
- **Bounds-checked little-endian readers** (`core/src/bytes.rs`): `le_u16/le_u32/
  le_u64/u8_at` return `0` when the range lies outside the buffer, so a truncated
  image cannot panic a parser; callers that must distinguish "absent" from "zero"
  length-check up front and surface `RefsError::Truncated`. Saturating arithmetic
  and allocation caps guard against length-field allocation bombs
  (`REFS-IMPOSSIBLE-GEOMETRY`).
- **Fuzzing**: one `cargo-fuzz` target per parsed structure — `boot`,
  `superblock`, `metablock`, `minstore`, `objecttable`, `container`, `directory` —
  plus `fuzz_forensic` for the full audit pipeline (`fuzz/fuzz_targets/`); the
  invariant is never-panic.

## Consequences

- The reader is provably free of the memory-corruption/RCE class on crafted input;
  it earns the `unsafe forbidden` README badge honestly.
- Robustness is claimed as **"input-fuzzed" (measured) + "panic-free by lint"
  (static)** — the qualified, evidence-based form, never a bare "panic-free"
  absolute.

## Known divergence — hand-rolled `bytes.rs` vs the fleet `safe-read` crate

The fleet standard also mandates routing every fixed-width integer read through
the shared, audited **`safe-read`** crate and **never** hand-rolling a per-crate
`bytes.rs`. This repo currently **hand-rolls** `core/src/bytes.rs`, whose module
doc says it "mirror[s] `xfs-core`'s big-endian helpers with LE decode." The
immediate rationale (consistency with the `xfs-core` sibling) is recoverable from
the source comment, but **the rationale for not adopting `safe-read` here is not
recovered in the available history** — it is a divergence from the binding
standard, recorded honestly rather than justified after the fact. Migrating
`bytes.rs` to `safe-read` (which covers exactly these `leN`/`u8` reads) is the
follow-up this ADR flags; the panic-free behavior is equivalent today, but the
single-audited-implementation and `checked_add` overflow guarantees of `safe-read`
are not yet inherited.

## Alternatives considered

- **`unsafe_code = "deny"` + bounded allow** — unnecessary; no `unsafe` site
  exists, so `forbid` is strictly stronger and locally un-overridable.
- **Panicking readers with up-front validation only** — rejected; the Paranoid
  Gatekeeper standard wants defense-in-depth, so the readers degrade to `0` even
  if a length check is ever missed.
