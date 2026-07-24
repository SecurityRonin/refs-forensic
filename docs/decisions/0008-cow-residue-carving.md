# 8. F-CARVE — recover copy-on-write metadata residue as the primary forensic lever

Date: 2026-07-24
Status: Accepted

## Context

ReFS is an **allocate-on-write (copy-on-write) filesystem**: when a directory page
is updated, the new version is written to a *new* block and the object table is
re-pointed at it, leaving the **old `MSB+` page behind** in place. That stale page
still holds the pre-update directory-entry rows — deleted names, prior metadata —
which is exactly the residue a forensic examiner wants. This CoW property is the
distinctive lever ReFS offers, and the audit layer is built to pull it
(`forensic/src/lib.rs` module docs).

## Decision

Provide **F-CARVE** via `recover_residue(&image) -> Vec<StalePage>`: scan for
`MSB+` directory pages whose self-recorded block number is **not** the current
object-table mapping (= stale/old CoW versions) and carve the directory-entry
rows still present. F-CARVE returns plain `StalePage` structs
(`self_block` / `table_id` / `offset` / `entries`) — it does **not** emit
`forensicnomicon` `Finding`s or codes. The labels `REFS-STALE-METADATA-PAGE` /
`REFS-CARVED-DIRECTORY-ENTRY` (`README.md` / `docs/index.md`) name the two things
it surfaces (an old CoW page and its carved entries); they are descriptive output
labels, not emitted Finding codes. Only F-INTEGRITY (`audit_findings`) emits
graded `forensicnomicon` Findings, so F-CARVE is the second, structurally distinct
audit axis (`forensic/src/lib.rs`).

## Consequences

- Deleted/prior directory state is recoverable directly from CoW residue without
  a journal, exploiting the format's own design.
- Validation is **honest about its reach** (ADR 0002): F-CARVE is validated on a
  **real resident stale CoW `0x600` page** carrying `System Volume Information`
  plus synthetic pages. The minted user-file bands are non-resident (beyond the
  oracle slice; source VHD lost), so end-to-end deleted-user-file recovery is
  **oracle-blocked and surfaced as such**, never fabricated
  (`docs/validation.md`, `README.md`).
- File-content extraction and USN-journal parsing are explicit later phases, not
  claimed now.

## Alternatives considered

- **Only report current directory state** — rejected; discards the CoW residue
  that is the forensic point of a copy-on-write filesystem.
- **Claim full deleted-file recovery now** — rejected; the non-resident user
  bands are oracle-blocked, so claiming it would fabricate an unvalidated result.
