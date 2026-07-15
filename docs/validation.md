# Validation — `refs-core` / `refs-forensic`

## The honest tier: Tier-2 at best (structural), no ground-truth corpus

**ReFS is undocumented.** Microsoft publishes no on-disk specification. Every
structural fact this reader encodes is third-party **reverse engineering**
(libyal [`libfsrefs`](https://github.com/libyal/libfsrefs), Prade's academic
TSK fork + paper). There is **no ground-truth forensic corpus** for ReFS.

Consequently:

- **Structural metadata (boot VBR, superblock, version, block headers) is
  Tier-2 at best** — validated by self-minting a volume on the live Windows
  ReFS driver and cross-checking against the reverse-engineered references. We
  authored both the fixture and the expected answers, so they can share a blind
  spot with a wrong reference. **Structural metadata cannot reach true Tier-1 on
  this filesystem** — the only "oracle" (libfsrefs) is itself reverse-engineered
  (the LZNT1-trap risk: a wrong reader and a wrong reference can agree and ship
  green).
- **File content can reach Tier-1** in a later phase, by hashing reconstructed
  file bytes against `Get-FileHash` on the live Windows driver (the only
  authoritative source of true file bytes). The mint already captured those
  SHA-256 hashes (see [`../tests/data/README.md`](../tests/data/README.md)).

This is stated plainly, per the fleet Evidence-Based Rigor discipline: we do
**not** claim Tier-1 for any structural finding.

## P0 — boot VBR + superblock + version detection

Validated against a **Tier-2 self-minted ReFS v3.14** volume (Windows 11 Pro,
build 26200, Dev Drive on a 60 GB dynamic VHD — the only ReFS path on Win11
client). Ground truth is `fsutil fsinfo refsinfo` on the live Windows driver.

Every boot-VBR offset was byte-verified against the fixture **and** reconciled
against the driver's `fsutil` output:

| Field | Offset | Reader value | `fsutil` / driver | Match |
|---|---|---|---|---|
| FS signature | 3 (8) | `"ReFS\0\0\0\0"` | — (identity) | ✅ |
| FSRS identifier | 16 (4) | `"FSRS"` | — (identity) | ✅ |
| Number of sectors | 24 (8) | 125,698,048 | `0x077e0000` = 125,698,048 | ✅ |
| Bytes per sector | 32 (4) | 512 | `Bytes Per Sector 512` | ✅ |
| Sectors per cluster | 36 (4) | 8 | (512 × 8 = 4096 = `Bytes Per Cluster`) | ✅ |
| Major version | 40 (1) | 3 | `REFS Volume Version 3.14` | ✅ |
| Minor version | 41 (1) | 14 | `REFS Volume Version 3.14` | ✅ |
| Volume serial | 56 (8) | `0x4e32fc4432fc3317` | `0x4e32fc4432fc3317` | ✅ |
| Container size | 64 (8) | 67,108,864 | — | (RE) |
| SUPB block | cluster 30 (`0x1e000`) | signature `SUPB`, self-describing block # = 30 | — (RE, libfsrefs) | (RE) |

`(RE)` = reverse-engineered structural fact with no independent driver field to
reconcile against — Tier-2 by nature.

The env-gated test (`REFS_TIER2_ORACLE`) re-runs the same parse against the full
16 MiB minted partition head, not just the committed 128 KiB slice.

## Fail-loud gates (never silently misparse)

Per RESEARCH.md, the reader **fails loud with the offending value** rather than
guessing:

- Bad FS signature / FSRS identifier → error carries the offending bytes.
- A **v1 (or any non-v3) major version** is rejected by `require_v3()` naming the
  real `major.minor` — a v1 volume (Server 2012 / 8.1) has a materially
  different layout, so parsing it as v3 would silently misparse.
- Bad `SUPB` block signature → error carries the offending bytes **and** the byte
  offset.
- Truncated / hostile buffers never panic (bounds-checked LE readers, saturating
  arithmetic, `#![forbid(unsafe_code)]`).

## Later phases (not P0)

Object table + virtual-address indirection, Minstore B+-tree traversal, page
checksum (CRC64) validation, directory/file records → data runs → file-content
extraction (the Tier-1 content-hash gate), and the `refs-forensic` audit surface
(page-checksum mismatch, CoW stale-page carving, USN journal) follow in
subsequent, individually-validated increments — each version-gated (a reader
validated on v3.14 may break on v3.4/v3.9).
