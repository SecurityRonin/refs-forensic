# 7. A metadata-CRC mismatch is emitted only over a caller-supplied range — never auto-fabricated

Date: 2026-07-24
Status: Accepted

## Context

Every ReFS v3 metadata block carries a checksum in its header
(`core/src/metablock.rs`). A CRC mismatch is a strong tamper/corruption signal, so
it is tempting for the auditor to compute and check it automatically. But the
**exact byte range ReFS's own whole-block checksum covers is undetermined** in the
reverse-engineered references (`core/src/metablock.rs` docs; `refs-forensic`
`lib.rs` module docs). Guessing the coverage range would make the reader *encode*
a checksum algorithm to a fixture — the LZNT1 trap — and, worse, in a forensic
tool a wrong "CRC mismatch" **fabricates evidence** of tampering.

## Decision

Never auto-compute a whole-block CRC verdict. `refs-core` exposes the primitives
(`crc32c`, `crc64_ecma`, `MetaBlock::verify_crc32c(data, start, end, stored)`
returning `Option<bool>`), and `refs-forensic` emits **`REFS-METADATA-CRC-
MISMATCH` only via `audit_crc_range`**, over a **caller-supplied explicit coverage
range** (`README.md` code table; `forensic/src/lib.rs`). With no known range, no
CRC finding is produced.

## Consequences

- The audit never fabricates a tamper finding from a guessed coverage range: a
  CRC verdict appears only when a caller asserts the range it knows.
- The CRC primitives (CRC-32C / CRC-64 ECMA-182, via the audited `crc` crate) are
  available for any future work that establishes ReFS's real coverage range, at
  which point the automatic path can be added honestly.
- This mirrors the fleet rule that findings are observations, not manufactured
  verdicts, and the fail-loud "show the value, don't invent one" discipline.

## Alternatives considered

- **Auto-check the CRC over a guessed range** — rejected; a wrong guess fabricates
  tampering evidence (or masks it), the worst failure class for a forensic tool.
- **Drop CRC support entirely** — rejected; the primitives are cheap and correct,
  and the caller-supplied-range API lets a knowledgeable caller use them safely
  today.
