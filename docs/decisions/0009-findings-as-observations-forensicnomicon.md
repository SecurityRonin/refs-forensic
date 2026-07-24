# 9. Findings as graded observations via the `forensicnomicon` report model

Date: 2026-07-24
Status: Accepted

## Context

The fleet has one normalized reporting vocabulary — `forensicnomicon::report`
(`ronin-issen/CLAUDE.md`, "The Reporting Model") — so every analyzer emits the
same `Finding`/`Severity`/`Observation` types and ORCHESTRATION (Issen) renders
them uniformly instead of N bespoke `XxxAnalysis` shapes. Two fleet disciplines
constrain the output: analyzer codes are a **published contract** (scheme-prefixed
SCREAMING-KEBAB), and findings are **observations, never legal conclusions**
("consistent with …", the examiner concludes).

## Decision

`refs-forensic` adopts the fleet **producer pattern** (`forensic/src/lib.rs`):

- Keep a typed `AnomalyKind` (the ReFS domain knowledge) with `severity()` /
  `code()` / `note()` / `evidence()`, and convert to canonical
  `forensicnomicon::report::Finding`s via `impl Observation` — mirroring
  `xfs-forensic` / `btrfs-forensic` / `ntfs-forensic`.
- Public surface: `audit_image` → `Vec<Anomaly>`, `audit_findings` →
  `Vec<Finding>` (F-INTEGRITY), `recover_residue` → `Vec<StalePage>` (F-CARVE).
- The emitted `Finding` codes are `REFS-`-prefixed and stable — the six
  `AnomalyKind::code()` values: `REFS-BOOT-SIGNATURE-INVALID`,
  `REFS-METADATA-CRC-MISMATCH`, `REFS-SELF-BLOCK-MISMATCH`,
  `REFS-CHECKPOINT-DIVERGENCE`, `REFS-ORPHANED-OR-UNRESOLVED`,
  `REFS-IMPOSSIBLE-GEOMETRY` (`forensic/src/lib.rs`, `AnomalyKind::code`).
  F-CARVE emits no `Finding`: `recover_residue` returns `Vec<StalePage>`, and the
  labels `REFS-STALE-METADATA-PAGE` / `REFS-CARVED-DIRECTORY-ENTRY`
  (`README.md` / `docs/index.md`) are descriptive names for its carved output, not
  emitted Finding codes.
- Every finding is phrased as an **observation** ("consistent with a
  relocated/tampered page"), never a verdict.

## Consequences

- ReFS findings aggregate into one `forensicnomicon::report::Report` alongside
  every other fleet analyzer, with no bespoke type for Issen to special-case.
- The emitted `REFS-*` `Finding` codes are a stable published contract: existing
  codes never change meaning; new signals get new codes.
- `forensicnomicon` supplies the shared **report model** only —
  `report::{Severity, Observation, Finding, Evidence, Location, Source}`
  (`forensic/src/lib.rs`). The ReFS **structure knowledge** comes from `refs-core`
  plus the on-disk constants defined locally in `forensic/src/lib.rs`
  (`MSB_SIGNATURE`, the header offsets), not from `forensicnomicon`. So
  `refs-forensic` depends **downward on two crates** — `refs-core` **and**
  `forensicnomicon` (`forensic/Cargo.toml`; ADR 0001), never on `forensicnomicon`
  alone.

## Alternatives considered

- **A bespoke `RefsAnalysis` result type** — rejected; it would force Issen to
  learn one more shape and diverge from the fleet's single report vocabulary.
- **Emit verdicts ("this volume was tampered")** — rejected; findings are
  observations, and the tribunal/examiner draws the conclusion.
