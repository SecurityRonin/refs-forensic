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
  SHA-256 hashes (see [`tests/data/README.md`](https://github.com/SecurityRonin/refs-forensic/blob/main/tests/data/README.md)).

This is stated plainly, per the fleet Evidence-Based Rigor discipline: we do
**not** claim Tier-1 for any structural finding.

## Reproduce from a clean clone — no Tier-1 path exists

**ReFS has no downloadable third-party corpus** (Microsoft publishes no on-disk
spec; the only references — `libfsrefs`, Prade's TSK fork — are reverse-engineered
and cannot serve as a Tier-1 answer key). So, unlike the other filesystem repos,
**there is no download URL that reconstitutes a Tier-1 validation here.** The only
real-volume oracle is a **Tier-2 self-mint** on the live Windows ReFS driver, and
re-minting it produces a *new, different* Tier-2 volume — it can never reconstitute
a Tier-1 validation (a re-mint is self-authored by definition).

The two env-gated real-volume oracles are **gitignored** (16 MiB / 256 MiB slices)
because the source VHD was detached and lost, so they are **not byte-for-byte
re-mintable**; a fresh mint via the generators in `tests/data/README.md` yields a
*different* v3.14 volume the tests re-verify against, not the identical bytes.

| Oracle | env var | md5 | committed? | mint command | run command |
|---|---|---|---|---|---|
| 16 MiB partition head (`refs_partition_head.bin`) | `REFS_TIER2_ORACLE` | `1a38a7ff099bcd1d58cce9f8e29c9db2` | No (gitignored) | `tests/data/README.md` → "How the oracle was minted" (`mint4.ps1`) | see below |
| 256 MiB container head (`refs_container_head256.bin`) | `REFS_TIER2_ORACLE256` | `8d09e81af8b939151fe0ae81d90b4623` | No (gitignored) | `tests/data/README.md` → "P3 generator" (`mint5.ps1` / `slice256.ps1`) | see below |

**Always-on (committed, no env var, no mint):** the P0 boot/superblock path runs
against the committed `refs_boot_superblock.bin` and the small `refs_v314_*.bin`
metadata pages — `cargo test -p refs-core` and `cargo test -p refs-forensic`
exercise the whole structural + audit path with zero setup.

**Run commands for the Tier-2 real-volume oracles** (after minting a v3.14 volume
per `tests/data/README.md` and slicing the head):

```bash
# 16 MiB head: boot/superblock, Minstore object tree, directory reachability, clean sweep
REFS_TIER2_ORACLE=/abs/path/to/refs_partition_head.bin \
  cargo test -p refs-core --test boot full_partition_head_env_gated
REFS_TIER2_ORACLE=/abs/path/to/refs_partition_head.bin \
  cargo test -p refs-forensic --test integrity real_volume_clean_sweep_emits_nothing_false_env_gated

# 256 MiB head: container resolve, descent (no-fabrication), F-CARVE CoW residue
REFS_TIER2_ORACLE256=/abs/path/to/refs_container_head256.bin \
  cargo test -p refs-core --test container \
  real_volume_container_resolves_root_directory_page_env_gated
REFS_TIER2_ORACLE256=/abs/path/to/refs_container_head256.bin \
  cargo test -p refs-forensic --test carve \
  real_volume_stale_directory_page_carved_env_gated
```

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

## `refs-forensic` — the audit layer (F-INTEGRITY + F-CARVE)

The analyzer emits graded `forensicnomicon::report::Finding`s. Each finding is an
**observation** ("consistent with …"), never a verdict. What is validated, and
against what, stated plainly per the Evidence-Based Rigor discipline:

### F-INTEGRITY — structural anomalies (the solid, validatable deliverable)

Validated on the **real resident v3.14 metadata** (a clean volume must emit
nothing false — the anti-LZNT1-trap regression guard, run over all 39 real `MSB+`
pages via `REFS_TIER2_ORACLE`) plus crafted corruption of the real bytes:

| Code | Detects | Validated on |
|---|---|---|
| `REFS-BOOT-SIGNATURE-INVALID` | boot VBR signature ≠ `ReFS\0\0\0\0` (fail-loud value) | real SUPB region + byte-flipped signature |
| `REFS-SELF-BLOCK-MISMATCH` | a metadata block whose self-recorded block # ≠ its location (relocated/tampered) | real SUPB (self-block 30) + a planted MSB+ page |
| `REFS-METADATA-CRC-MISMATCH` | a stored CRC that fails over a **known** coverage range | self-contained CRC-32C over an explicit span |
| `REFS-CHECKPOINT-DIVERGENCE` | the superblock names zero / torn checkpoint copies | real SUPB with a zeroed checkpoint-count field |
| `REFS-IMPOSSIBLE-GEOMETRY` | cluster/geometry beyond bounds (allocation-bomb guard) | real boot VBR with an absurd sectors-per-cluster |
| `REFS-ORPHANED-OR-UNRESOLVED` | a child reference that resolves to no resident page (reserved for a directory-walk caller — not emitted on a partial slice, where non-residence is normal) | vocabulary unit test |

**CRC honesty (which codes are validated vs deliberately NOT fabricated).** ReFS's
own whole-block checksum **coverage range is undetermined** in the
reverse-engineered references (`libfsrefs` marks it `TODO`; an empirical
brute-force over the real SUPB self-reference did not reproduce it — see
[`tests/data/README.md`](https://github.com/SecurityRonin/refs-forensic/blob/main/tests/data/README.md)). So `refs-forensic` **never
auto-fabricates** a `REFS-METADATA-CRC-MISMATCH` on a clean block. The code is
emitted **only** via `audit_crc_range(block, offset, start, end, stored)` — a
caller-supplied, KNOWN coverage range (validated here with a self-contained CRC-32C
whose answer key is the crate's own `crc32c`, an independent Tier-1 algorithm
oracle). Automatic whole-block CRC verification stays absent until a future phase
pins ReFS's range. This is the LZNT1-trap avoidance the fleet standards mandate:
we ship the mechanism, not a guessed range that would flag every clean block.

### F-CARVE — CoW metadata-residue recovery

ReFS is **allocate-on-write**: an updated metadata page is written NEW at a higher
block number and the tree re-points at it, leaving the OLD `MSB+` page behind.
`recover_residue` surfaces `MSB+` directory pages that are not the current version
(the highest self-block for their table id — the CoW-monotonic discriminator,
corroborated by the object table's resolvable `0x600` → `80_384` mapping) and
carves the directory-entry rows they still hold that the current version dropped.

**Validated on real resident bytes (`REFS_TIER2_ORACLE256`):** on the 256 MiB
v3.14 oracle, the current `0x600` root directory (self-block `80_384`, cluster
14848) no longer carries the `System Volume Information` entry, but an **older CoW
copy** (self-block `70_656`, cluster 5120) still does — F-CARVE surfaces that
stale page and its carved `System Volume Information` entry. A genuine, resident
CoW-residue recovery, not synthetic. Also validated on synthetic stale/current
page pairs.

**Oracle-blocked (stated plainly, never fabricated).** The minted **user** files
(`dir_a` / `known1.txt` / `nested` / `big.bin`) live in a non-resident band beyond
the 256 MiB slice, and the source VHD was detached and lost (see
[`tests/data/README.md`](https://github.com/SecurityRonin/refs-forensic/blob/main/tests/data/README.md) P4 note), so their
**deleted-recovery end-to-end is not reproducible**. F-CARVE returns what IS
resident and the real-volume test asserts the non-resident files do **not** appear
— the carver never fabricates the oracle-blocked band.

### Robustness (Paranoid Gatekeeper)

`#![forbid(unsafe_code)]`; every field read through bounds-checked, saturating LE
helpers; a lying block/row/count never panics or over-reads (malformed-input tests
sweep truncations and garbage across both `audit_image` and `recover_residue`).
100% gate-effective line coverage on both crates (uncovered lines are
defence-in-depth guards annotated `// cov:unreachable`).

## Later phases (not yet built)

File-content extraction (data runs → the Tier-1 content-hash gate against
`Get-FileHash` on the live Windows driver), USN Change Journal parsing, and a
pinned ReFS CRC coverage range (turning `audit_crc_range` into an automatic
whole-block sweep) follow in subsequent, individually-validated increments — each
version-gated (a reader validated on v3.14 may break on v3.4/v3.9).
