# refs-forensic

Pure-Rust, from-scratch reader and forensic auditor for **ReFS** (the Windows
Resilient File System). `refs-core` parses the on-disk structures; `refs-forensic`
(scaffold) will grade ReFS-specific anomalies as `forensicnomicon::report::Finding`s.

> **ReFS is reverse-engineered.** Microsoft publishes **no** official on-disk
> specification for ReFS. Every structural fact this crate encodes comes from
> third-party reverse engineering — primarily libyal
> [`libfsrefs`](https://github.com/libyal/libfsrefs) and Prade's academic work.
> There is **no ground-truth forensic corpus**. Structural metadata is therefore
> **Tier-2 at best** (self-minted on the live Windows driver + cross-checked
> against the reverse-engineered references); only *file content* can reach
> Tier-1, by hashing against the Windows driver. This crate does **not** claim
> Tier-1 for structural findings. See [`docs/validation.md`](docs/validation.md).

## Status — Phase 0 (boot VBR + superblock + version)

`refs-core` currently parses:

- The **boot Volume Boot Record** (FS-recognition structure at offset 0):
  `ReFS`/`FSRS` signatures, sector/cluster geometry, volume serial, and the
  **major/minor format version**.
- **Version detection + fail-loud gate:** targets ReFS **v3.x**; a v1 (or any
  non-v3) volume is rejected naming the real version bytes, never silently
  misparsed.
- The primary **superblock** (`SUPB`, at cluster 30): block signature validation
  and the self-describing block number.

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

### Not yet implemented (later, individually-validated phases)

Object table + virtual-address indirection, Minstore B+-tree traversal, page
(CRC64) checksum validation, directory/file records → data runs → file-content
extraction, and the `refs-forensic` audit surface (page-checksum mismatch, CoW
stale-page carving, USN journal).

## Robustness

`#![forbid(unsafe_code)]`, panic-free bounds-checked little-endian readers, and
saturating arithmetic — the crate parses untrusted, attacker-controllable disk
images and must never panic, read out of bounds, or trust a length field.

<!-- TODO(corpus-catalog): add the refs-forensic fixtures
     (tests/data/refs_boot_superblock.bin — committed Tier-2 self-mint;
     refs_partition_head.bin — gitignored) to issen/docs/corpus-catalog.md.
     Deferred: this task touches ONLY the refs-forensic repo. -->

[Privacy Policy](https://securityronin.github.io/refs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/refs-forensic/terms/) · © 2026 Security Ronin Ltd
