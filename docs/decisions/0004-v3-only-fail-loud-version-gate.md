# 4. Target ReFS v3.x only, with a fail-loud version gate

Date: 2026-07-24
Status: Accepted

## Context

ReFS is **version-fragmented**: the on-disk layout differs materially between
v1.x (Server 2012 / Windows 8.1) and v3.x (Server 2016+ / Windows 10+/11), and
each Windows release tweaks it. The boot VBR records a major/minor format version
at offsets 40/41 (`core/src/boot.rs`). Parsing a v1 (or otherwise non-v3) volume
with v3 offsets would silently misparse — the exact silent-wrong-output failure
the fleet's fail-loud discipline exists to prevent.

## Decision

Target **v3.x** and **fail loud** on anything else, naming the actual version
bytes:

- `BootSector::is_v3()` = `major_version == 3` (`core/src/boot.rs`).
- `BootSector::require_v3()` returns `RefsError::UnsupportedVersion` when
  `major_version != 3`, carrying the real version bytes (`core/src/boot.rs`), so
  the report hands the investigator the offending value (show-the-unrecognized-
  value standard).
- Callers gate on `require_v3()` before trusting any deeper structure (`README.md`
  quick-start: `boot.require_v3()?`).

## Consequences

- A non-v3 volume is rejected explicitly, never quietly turned into garbage
  fields.
- The reader's scope is bounded and honest: v3.x is what is byte-verified against a
  real v3.14 oracle; v1.x support is a deliberate non-goal, not an accidental gap.
- The version bytes travel in the error, so an examiner learns *which* unsupported
  version they hit.

## Alternatives considered

- **Best-effort parse any version** — rejected; without a v1 oracle it would emit
  confidently-wrong fields, violating fail-loud.
- **Silently return empty on non-v3** — rejected; indistinguishable from a clean
  v3 volume with no findings (the bootstrap-failure-as-empty trap).
