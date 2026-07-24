# 6. Low, CI-verified MSRV of 1.83 — dictated by the `crc` dependency

Date: 2026-07-24
Status: Accepted

## Context

Per the fleet MSRV policy (`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy"), the
**dev toolchain** and the **declared MSRV** are separate promises. `refs-core` and
`refs-forensic` are **published libraries**, so they keep a **low, CI-verified
MSRV** — a downstream-facing compatibility feature — even though the dev toolchain
pins the current stable (`rust-toolchain.toml` → `channel = "1.96.0"`).

Our own code needs only Rust 1.82 (the `is_none_or` combinator in
`core/src/minstore.rs`). But the `crc` dependency (`crc 3.4.0`) requires rustc
**1.83**, so the *dependency* dominates the floor. An earlier value of 1.85 was
lowered to the true CI-verified floor in `git show 2baa517`
("lower declared MSRV 1.85 -> 1.83").

## Decision

Declare **`rust-version = "1.83"`** once in `[workspace.package]` (root
`Cargo.toml`, with the rationale in an inline comment), inherited by both members
via `rust-version.workspace = true`. A dedicated CI `msrv` job builds `refs-core`
on exactly this floor so the promise is verified, not aspirational.

## Consequences

- The published crates stay consumable by toolchains as old as 1.83, widening the
  crates.io audience.
- The floor tracks *reality* (the `crc` requirement + our `is_none_or` use), not
  the dev pin — bumping it is a near-breaking change requiring a real reason
  (e.g. a new dependency or language feature), never a reflexive match to the
  toolchain.

## Alternatives considered

- **MSRV = the pinned dev toolchain (1.96.0)** — rejected; that is the apps rule.
  For a published library it would needlessly exclude older consumers.
- **Keep 1.85** — rejected; not the true floor. A verified low MSRV is a real
  guarantee, so it was lowered to what CI actually proves (1.83).
- **Drop the `is_none_or` use to reach 1.81** — pointless; `crc 3.4.0` already
  pins the floor at 1.83, so it would not lower the declared MSRV.
