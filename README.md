# refs-forensic

[![refs-core](https://img.shields.io/crates/v/refs-core.svg?label=refs-core)](https://crates.io/crates/refs-core)
[![refs-forensic](https://img.shields.io/crates/v/refs-forensic.svg?label=refs-forensic)](https://crates.io/crates/refs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/refs-forensic?label=docs.rs)](https://docs.rs/refs-forensic)
[![Rust 1.83+](https://img.shields.io/badge/rust-1.83%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/refs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/refs-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://securityronin.github.io/refs-forensic/validation/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security audit](https://img.shields.io/badge/security-cargo--deny-brightgreen.svg)](deny.toml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/refs-forensic/)

**A from-scratch, reverse-engineered reader and graded anomaly auditor for ReFS v3 (the Windows Resilient File System) — walk the boot region, checkpoint, object table, and Minstore B+tree over any byte source, resolve virtual→physical container addresses, and surface copy-on-write metadata residue as evidence.**

`refs-core` parses the on-disk structures; `refs-forensic` grades ReFS-specific
anomalies as `forensicnomicon::report::Finding`s and recovers copy-on-write
metadata residue.

> **ReFS is reverse-engineered.** Microsoft publishes **no** official on-disk
> specification for ReFS. Every structural fact this crate encodes comes from
> third-party reverse engineering — primarily libyal
> [`libfsrefs`](https://github.com/libyal/libfsrefs) and Prade's academic work.
> There is **no ground-truth forensic corpus**. Structural metadata is therefore
> **Tier-2 at best** (self-minted on the live Windows driver + cross-checked
> against the reverse-engineered references); only *file content* can reach
> Tier-1, by hashing against the Windows driver. This crate does **not** claim
> Tier-1 for structural findings. See [`docs/validation.md`](docs/validation.md).

## What `refs-core` parses

- The **boot Volume Boot Record** (FS-recognition structure at offset 0):
  `ReFS`/`FSRS` signatures, sector/cluster geometry, volume serial, and the
  **major/minor format version**.
- **Version detection + fail-loud gate:** targets ReFS **v3.x**; a v1 (or any
  non-v3) volume is rejected naming the real version bytes, never silently
  misparsed.
- The primary **superblock** (`SUPB`, at cluster 30) and the **checkpoint**
  pair it names: block-signature validation, self-describing block number, and
  torn/zero-copy detection.
- The **object table** and **container** layer: virtual→physical address
  resolution so metadata blocks are reachable by object id.
- **Minstore B+tree** (`MSB+`) pages — node/leaf walking — and the **directory**
  entries they carry.

> Validation is **Tier-2** for structural metadata (no ReFS ground-truth corpus
> exists); deep non-resident directory recovery is oracle-blocked and surfaced as
> such — see the honest validation state below and [`docs/validation.md`](docs/validation.md).

```rust
use refs_core::BootSector;

let boot = BootSector::parse(&image)?;          // image = bytes at the ReFS partition
boot.require_v3()?;                              // fail loud on a non-v3 volume
println!("ReFS v{}.{}, serial {:#018x}, cluster {} bytes",
         boot.major_version, boot.minor_version, boot.volume_serial, boot.cluster_size());
let sb = refs_core::Superblock::parse_at(&image, boot.superblock_offset())?;
assert_eq!(sb.block.block_number, 30);          // self-describing
```

Import path is `refs_core` (the bare `refs` crate name is held by an unrelated
third party on crates.io, so the import is not hijacked).

## `refs-forensic` — the audit layer

Graded structural anomalies (**F-INTEGRITY**) and copy-on-write metadata-residue
recovery (**F-CARVE**), each finding an **observation** ("consistent with …"),
never a verdict. Full evidence + tiering in [`docs/validation.md`](docs/validation.md).

```rust
// F-INTEGRITY — structural anomalies as graded forensicnomicon Findings.
let findings = refs_forensic::audit_findings(&image, "volume: REFSTEST");
for f in &findings {
    println!("{:?} {} — {}", f.severity, f.code, f.note);
}

// F-CARVE — recover directory-entry residue from stale copy-on-write pages.
for stale in refs_forensic::recover_residue(&image) {
    println!("stale 0x{:x} page (self-block {}): {:?}",
             stale.table_id, stale.self_block, stale.entries);
}
```

| Code | Signal |
|---|---|
| `REFS-BOOT-SIGNATURE-INVALID` | boot VBR signature ≠ `ReFS\0\0\0\0` (fail-loud value) |
| `REFS-SELF-BLOCK-MISMATCH` | metadata block self-block ≠ its location (relocated/tampered) |
| `REFS-METADATA-CRC-MISMATCH` | stored CRC fails over a **known** coverage range (via `audit_crc_range`; never auto-fabricated — ReFS's own range is undetermined) |
| `REFS-CHECKPOINT-DIVERGENCE` | the superblock names zero / torn checkpoint copies |
| `REFS-ORPHANED-OR-UNRESOLVED` | a child reference resolving to no resident page (directory-walk caller) |
| `REFS-IMPOSSIBLE-GEOMETRY` | cluster/geometry beyond bounds (allocation-bomb guard) |
| `REFS-STALE-METADATA-PAGE` / `REFS-CARVED-DIRECTORY-ENTRY` | an old CoW `MSB+` directory page + the entries it still holds |

**Honest validation state (Tier-2).** F-INTEGRITY is validated on the real
resident v3.14 metadata (a clean volume emits nothing false) plus crafted
corruption. F-CARVE is validated on a **real resident stale CoW `0x600` page**
carrying `System Volume Information`. The minted **user** files live in a
non-resident band beyond the oracle slice (source VHD lost), so their
deleted-recovery end-to-end is **oracle-blocked** — surfaced as such, never
fabricated. File-content extraction and USN journal parsing are later phases.

## Robustness

`#![forbid(unsafe_code)]`, panic-free bounds-checked little-endian readers, and
saturating arithmetic — the crate parses untrusted, attacker-controllable disk
images and must never panic, read out of bounds, or trust a length field.

<!-- TODO(corpus-catalog): add the refs-forensic fixtures
     (tests/data/refs_boot_superblock.bin — committed Tier-2 self-mint;
     refs_partition_head.bin — gitignored) to issen/docs/corpus-catalog.md.
     Deferred: this task touches ONLY the refs-forensic repo. -->

[Privacy Policy](https://securityronin.github.io/refs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/refs-forensic/terms/) · © 2026 Security Ronin Ltd
