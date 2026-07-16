# refs-forensic

**A from-scratch ReFS reader and a graded anomaly auditor — walk the boot VBR, superblock, Minstore B+-trees, container tree, and directory pages of a Windows ReFS volume over any byte source, then turn its copy-on-write history into evidence: invalid boot signatures, self-block mismatches from relocated pages, diverging checkpoints, unresolved virtual references, and directory-entry residue still carvable from stale CoW metadata pages.**

Two crates, one workspace:

- **[`refs-core`](https://crates.io/crates/refs-core)** — the reader: boot Volume Boot Record (`ReFS`/`FSRS` signatures, geometry, version), `SUPB` superblock, Minstore B+-tree pages + rows, the object table, the container (virtual→physical) resolver, and directory parsing/walking, over any byte slice. No `unsafe`, no C bindings.
- **[`refs-forensic`](https://crates.io/crates/refs-forensic)** — the auditor: turns parsed ReFS structures into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, and recovers CoW directory-entry residue, so a ReFS volume's anomalies aggregate uniformly with the partition and container layers.

!!! warning "ReFS is reverse-engineered — no Microsoft specification"
    Microsoft publishes **no** official on-disk specification for ReFS. Every structural fact these crates encode comes from third-party reverse engineering — primarily libyal [`libfsrefs`](https://github.com/libyal/libfsrefs) and Prade's academic work. There is **no public third-party ReFS forensic corpus**. Structural metadata is therefore **Tier-2 at best** (validated against real self-minted v3.14 volume bytes, cross-checked against the reverse-engineered `libfsrefs` structural oracle); only *file content* could reach Tier-1, by hashing against the live Windows ReFS driver — and user-file listing/content is presently **constrained by that Windows-only oracle**. These crates do **not** claim Tier-1 for structural findings. See [Validation](validation.md).

## Audit a ReFS volume in 30 seconds

```toml
[dependencies]
refs-forensic = "0.1"   # pulls in refs-core
```

```rust
use refs_forensic::audit_findings;

// Feed it the raw ReFS partition bytes; get back graded findings.
for finding in audit_findings(&image_bytes, "volume: REFSTEST") {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] REFS-SELF-BLOCK-MISMATCH — metadata page self-block …
}
```

`audit_findings` validates the boot VBR + geometry, the superblock's self-block, the checkpoint set the superblock names, and sweeps every resident metadata page for a self-block that disagrees with its location. A clean volume yields no findings (corruption is surfaced as its own finding or by the carver, never a panic).

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | What it observes |
|---|---|
| `REFS-BOOT-SIGNATURE-INVALID` | Boot VBR signature ≠ `ReFS\0\0\0\0` (the fail-loud value is named) |
| `REFS-METADATA-CRC-MISMATCH` | A stored CRC fails over a **known** coverage range (via `audit_crc_range` — never auto-fabricated; ReFS's own range is undetermined) |
| `REFS-SELF-BLOCK-MISMATCH` | A metadata page's self-block ≠ its location — consistent with a relocated / tampered page |
| `REFS-CHECKPOINT-DIVERGENCE` | The superblock names zero / torn checkpoint copies |
| `REFS-ORPHANED-OR-UNRESOLVED` | A child reference resolving to no resident page (directory-walk caller) |
| `REFS-IMPOSSIBLE-GEOMETRY` | Cluster/geometry beyond bounds — an allocation-bomb / corruption guard |
| `REFS-STALE-METADATA-PAGE` / `REFS-CARVED-DIRECTORY-ENTRY` | An old CoW directory page + the directory-entry names it still holds |

CoW residue recovery is separate: `recover_residue(&image)` scans for `MSB+`-family directory pages whose self-block is not the current (highest-block) version, and carves the directory-entry rows those stale pages still hold.

## The reader: navigate a volume

`refs-core` reads a ReFS volume over any byte slice:

```rust
use refs_core::BootSector;

let boot = BootSector::parse(&image)?;          // image = bytes at the ReFS partition
boot.require_v3()?;                              // fail loud on a non-v3 volume
let sb = refs_core::Superblock::parse_at(&image, boot.superblock_offset())?;
assert_eq!(sb.block.block_number, 30);          // self-describing
# Ok::<(), refs_core::RefsError>(())
```

The bare crate name `refs` on crates.io is held by an unrelated live third party, so this on-disk reader publishes as `refs-core` and imports as `refs_core`.

## Trust but verify

- **`#![forbid(unsafe_code)]`** in `refs-core` — no `unsafe`, no C bindings.
- **Panic-free** — every integer/length/offset field is read through bounds-checked little-endian helpers; a malformed volume degrades to an empty/typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (boot, superblock, metablock, minstore, objecttable, container, directory) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_residue` pipeline. See [Validation](validation.md).
- **Tier-2 validated (honestly).** ReFS is reverse-engineered with no Microsoft spec and no public third-party corpus, so structural findings are validated against real self-minted v3.14 volume bytes cross-checked with libyal `libfsrefs`, plus crafted corruption — **not** Tier-1. User-file listing/content is constrained by the Windows-only oracle. See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
