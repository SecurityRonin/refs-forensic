# 1. Reader/analyzer split — `refs-core` + `refs-forensic`

Date: 2026-07-24
Status: Accepted

## Context

ReFS work has two distinct jobs with opposite instincts. One is to read the
on-disk structures robustly on the *valid* path — boot VBR, superblock,
checkpoint, container table, Minstore B+tree, directories — the way any tool that
wants to *use* a ReFS volume needs. The other is *forensic auditing*: seeing the
raw self-block bytes, checkpoint divergence, and stale copy-on-write pages that a
robust reader normalizes away or discards.

The fleet's crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") makes this a binding two-crate layout for
every format: a `core/` reader crate with no findings, and a `forensic/` analyzer
crate that emits graded `forensicnomicon::report::Finding`s. The reference impl is
`ntfs-forensic`; siblings `xfs-forensic` / `btrfs-forensic` follow it.

## Decision

Ship one workspace repo `refs-forensic` with two members (`Cargo.toml`
`members = ["core", "forensic"]`):

1. **`refs-core`** (`core/`) — the pure reader. Parses boot/superblock/checkpoint/
   metablock/minstore/container/directory over any `&[u8]`; emits **no findings**
   (`core/src/lib.rs`).
2. **`refs-forensic`** (`forensic/`) — the anomaly auditor. Keeps a typed
   `AnomalyKind` and converts to canonical `Finding`s via the producer pattern
   (`forensic/src/lib.rs`).

Dependency direction is downward only: `forensic` depends on `core`
(`forensic/Cargo.toml` `refs-core = { workspace = true }`) and on
`forensicnomicon`; `core` depends on neither.

Per the standard's binding principle that `-forensic` **need not route every
audit through the reader's happy-path API**, `refs-forensic` reads through
`refs-core` for valid-path structure but **parses the raw self-block / checkpoint
bytes directly** where the audit must see what the reader normalizes
(`forensic/src/lib.rs` module docs: "where the audit must see the raw self-block /
checkpoint bytes the reader normalizes away it parses those bytes directly").

## Consequences

- A downstream tool that only wants to *read* ReFS links `refs-core` alone and
  never pulls `forensicnomicon`.
- The auditor can surface anomalies (relocated blocks, torn checkpoints, stale CoW
  pages) that the reader would hide, without contorting the reader's API.
- Two independently versioned crates (`version` is not hoisted in
  `[workspace.package]`; each member keeps its own), so the reader and analyzer
  release on their own cadence.

## Alternatives considered

- **A single `refs` crate** — rejected; forces every reader-only consumer to
  compile the audit surface and `forensicnomicon`, and couples the medium-agnostic
  parser to the analyzer.
- **`refs-forensic` built strictly on the `refs-core` public API** — rejected as a
  hard rule; the auditor needs the raw, possibly-broken structure a happy-path
  reader normalizes, so it drops to direct byte parsing where required.
