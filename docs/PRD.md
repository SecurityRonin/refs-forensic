# refs-forensic — Purpose & Scope (design doc)

This is a **library repo** (two published crates a developer *links*, not a binary
an examiner runs), so this is a design/scope doc, not a PRD. It records why the
crates exist and where their boundaries are. Load-bearing decisions live in
[`docs/decisions/`](decisions/); the honest validation state lives in
[`docs/validation.md`](validation.md).

## Purpose

Give the fleet a **pure-Rust, from-scratch reader and forensic auditor for ReFS
v3.x** (the Windows Resilient File System) that works over any byte source and
never panics on a crafted image. ReFS has no official Microsoft on-disk spec and
no ground-truth forensic corpus, so no maintained pure-Rust reader existed; the C
alternatives (`libfsrefs`, TSK) would force a C-FFI `unsafe` dependency into a
`forbid(unsafe)` fleet (see ADR 0002).

Two crates, one downward dependency edge (ADR 0001):

- **`refs-core`** — parses the ReFS on-disk structures and emits no findings:
  boot VBR (with a fail-loud v3 version gate, ADR 0004), superblock (`SUPB`),
  checkpoint (`CHKP`), the self-describing metadata-block header, the container
  table (virtual→physical block resolution), Minstore B+tree (`MSB+`) pages, and
  directory entries. Imports as `refs_core` (the bare `refs` name is taken, ADR
  0003).
- **`refs-forensic`** — grades ReFS-specific anomalies as
  `forensicnomicon::report::Finding`s (F-INTEGRITY) and recovers copy-on-write
  metadata residue (F-CARVE, ADR 0008), each a "consistent with …" observation,
  never a verdict (ADR 0009).

## Who links it

- **Issen / disk-forensic (ORCHESTRATION)** — to ingest ReFS volumes and fold
  `REFS-*` findings into the unified `forensicnomicon::report::Report`.
- **Rust developers** who need to read ReFS structures over `&[u8]` without a
  C dependency (`refs-core` alone, no `forensicnomicon` pull).

## What it does

- Walk the boot region → superblock → checkpoint → object/container tables →
  Minstore B+tree → directories, byte-verified against a real ReFS **v3.14**
  volume and cross-checked against libyal `libfsrefs` / Prade.
- Resolve **virtual → physical** container addresses so object-table-referenced
  metadata blocks are reachable (the P3 wall this reader had to crack).
- Fail loud on a non-v3 volume, an unrecognized signature, or impossible geometry
  — always naming the offending value.
- Emit graded structural anomalies and carve stale copy-on-write directory pages
  as deleted-metadata residue.

## Scope (in)

- ReFS **v3.x** structural parsing and forensic auditing over any byte source.
- Copy-on-write metadata-residue recovery from stale `MSB+` directory pages.
- Panic-free, `forbid(unsafe)`, input-fuzzed parsing of untrusted images (ADR
  0005).

## Non-goals (out, or deferred)

- **ReFS v1.x** (Server 2012 / 8.1) — a different layout; rejected fail-loud, not
  best-effort parsed (ADR 0004).
- **File-content extraction** and **USN-journal parsing** — explicit later phases,
  not claimed now.
- **Tier-1 structural correctness** — impossible without a ground-truth corpus;
  structural findings are capped at **Tier-2** and oracle-blocked paths (deep
  non-resident directory recovery) are surfaced as blocked, never fabricated
  (ADR 0002, `docs/validation.md`).
- **Automatic whole-block CRC verdicts** — the ReFS coverage range is
  undetermined, so a CRC mismatch is emitted only over a caller-supplied range,
  never guessed (ADR 0007).
- A **runnable CLI / GUI / MCP server** — this repo is linked, not run; the
  user-facing surface is `disk4n6` / Issen.

## Validation approach

Tier-2 structural, honestly stated. Correctness is byte-verified against a
self-minted real v3.14 volume on the live Windows driver and cross-checked against
the reverse-engineered references; F-INTEGRITY is validated on real resident
metadata (a clean volume emits nothing false) plus crafted corruption; F-CARVE is
validated on a real resident stale CoW `0x600` page carrying `System Volume
Information`. Full evidence, tiering, and the oracle-blocked gaps are in
[`docs/validation.md`](validation.md).
