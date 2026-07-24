# 3. Crate naming under the `refs` crates.io collision

Date: 2026-07-24
Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar" +
"Crate-structure standard") makes a single-format repo Pattern A: exactly
`<x>-core` (reader) + `<x>-forensic` (analyzer), and — where safe — publish the
reader with `[lib] name = "<x>"` so consumers write `use <x>::…`.

For ReFS the bare name `refs` on crates.io is **taken by an unrelated,
actively-published third-party crate** (hundreds of versions). The grammar's rule
for a *popular*/occupied bare name is to **not hijack the import path** — the
model case is `ntfs-core` importing as `ntfs_core` because `ntfs` belongs to Colin
Finck.

## Decision

- Reader crate = **`refs-core`**, imported as **`refs_core`** — do **not** set
  `[lib] name = "refs"`. `core/Cargo.toml` documents the collision in a comment;
  `core/src/lib.rs` and `README.md` state the import path.
- Analyzer crate = **`refs-forensic`** (the repo/headline name), imported as
  `refs_forensic`.
- The inter-crate dependency is declared once in `[workspace.dependencies]`
  (`refs-core = { path = "core", version = "0.1.0" }`) so a version bump touches
  one line (DRY).

## Consequences

- No namespace fight with the unrelated `refs` crate; both coexist on crates.io.
- Import path `refs_core` matches the established `ntfs-core` precedent, so the
  fleet's collision handling is consistent.
- Because `refs-core` *is itself* available (only the bare `refs` is taken), the
  reader does **not** need the heavier `<x>-forensic-core` fallback form used when
  even `<x>-core` is occupied (e.g. `zfs-forensic-core`).

## Alternatives considered

- **Publish the reader as `refs` with `[lib] name = "refs"`** — impossible; the
  name is taken by a third party.
- **Hijack the import via `[lib] name = "refs"` on the `refs-core` package** —
  rejected; the grammar forbids hijacking a popular occupied bare name, and it
  would confuse consumers of the existing `refs` crate.
