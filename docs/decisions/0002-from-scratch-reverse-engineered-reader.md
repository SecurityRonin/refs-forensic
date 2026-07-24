# 2. From-scratch, pure-Rust ReFS reader over a reverse-engineered format

Date: 2026-07-24
Status: Accepted

## Context

ReFS (Resilient File System) is **undocumented**: Microsoft publishes no on-disk
specification. Every structural fact must come from third-party reverse
engineering — primarily libyal [`libfsrefs`](https://github.com/libyal/libfsrefs)
(a C library) and Prade's academic TSK fork + paper. There is **no ground-truth
forensic corpus** for ReFS. The Research-First pass that opened this repo
(`git show 2f04ae8`, "Research-First report for refs-core/refs-forensic")
surveyed the prior art before any code.

The ecosystem alternatives are C (`libfsrefs`, TSK) — pulling one into the fleet
means a C-FFI `-sys` dependency, the worst `unsafe` liability under the fleet's
`unsafe`-cost-benefit law, in a codebase whose whole posture is
`forbid(unsafe_code)` over attacker-controllable images. No maintained pure-Rust
ReFS reader existed.

## Decision

**Build a from-scratch, pure-Rust ReFS v3 reader.** Encode each structure's
offsets from `libfsrefs` and byte-verify them against a real ReFS **v3.14** volume
minted on the live Windows driver (module docs across
`core/src/{boot,superblock,metablock,minstore,container,directory}.rs` each carry
a byte-verified offset table and cite `tests/data/README.md`). Development was
phased and TDD'd (RED/GREEN commits per phase): P0 boot/superblock/version
(`8cb059b`), P1 metablock/checkpoint/object-table/minstore (`251120d`), P2
directory index (`8f54908`), P3 container virtual→physical (`8a4b571`), P4
directory descent (`c4cba34`).

**State the validation tier honestly.** Structural metadata is **Tier-2 at best**
— we self-mint the volume and author the expected answers, so they share a blind
spot; only *file content* could reach Tier-1 (hashing against the Windows driver).
The crate does **not** claim Tier-1 for structural findings (`README.md`,
`core/src/lib.rs` module docs, `docs/validation.md`).

## Consequences

- Zero C, zero FFI: the reader keeps `#![forbid(unsafe_code)]` (ADR 0005) and the
  fleet's pure-Rust posture.
- The reverse-engineered references remain the cross-check oracle, not a runtime
  dependency; divergence from a real v3.14 volume is the correctness signal.
- Honesty is load-bearing: because no ground-truth corpus exists, the docs cap
  structural claims at Tier-2 and mark oracle-blocked paths (deep non-resident
  directory recovery) as such rather than fabricating a green result.
- New ReFS versions/quirks are absorbed by extending the pure-Rust parser, not by
  chasing an upstream C library's coverage.

## Alternatives considered

- **Bind `libfsrefs` / TSK (C) via `-sys`** — rejected; a C-FFI `unsafe` surface
  on untrusted input, breaking `forbid(unsafe)` and the pure-Rust posture.
- **Wait for a maintained pure-Rust ReFS crate** — none exists; building is
  justified (Research-First: absence of prior art justifies the build).
