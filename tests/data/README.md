# ReFS Forensic Test Data — Provenance

**ReFS is undocumented.** Microsoft publishes no on-disk specification; every
structural fact this repo encodes is third-party **reverse engineering**
(libyal [`libfsrefs`](https://github.com/libyal/libfsrefs), Prade's academic
work). There is **no ground-truth forensic corpus** for ReFS. Consequently the
fixtures here are **Tier-2 (self-mint)** — we authored both the volume and the
expected answers, cross-checked at mint time against the live Windows ReFS
driver (`fsutil fsinfo refsinfo`). *File-content* validation could reach Tier-1
(the Windows driver is the only authoritative source of true file bytes), but
**structural metadata cannot reach true Tier-1 on this filesystem** — state so
plainly. See [`../../docs/validation.md`](../../docs/validation.md).

## How the oracle was minted (Tier-2 self-mint)

A ReFS **v3.14** volume minted on a Parallels **Windows 11 Pro** VM (build
26200) on 2026-07-15. On Win11 client, ReFS is only formattable as a **Dev
Drive** (`Format-Volume -FileSystem ReFS -DevDrive`), which requires a volume
≥ 50 GB — so a 60 GB *dynamic* VHD was used (small on-disk footprint). The exact
mint script is [`mint4.ps1`](#generator) (verbatim commands below); it was run
over the Parallels `\\Mac\Cases` shared folder.

Ground truth from `fsutil fsinfo refsinfo R:` on the live Windows driver:

```
REFS Volume Serial Number :  0x4e32fc4432fc3317
REFS Volume Version :        3.14
REFS Driver Maximum Supported Version : 3.14
Number Sectors :             0x00000000077e0000   (= 125,698,048)
Bytes Per Sector  :          512
Bytes Per Cluster :          4096                 (=> 8 sectors/cluster)
Metadata Checksum Type :     CHECKSUM_TYPE_CRC64
Data Checksum Type :         CHECKSUM_TYPE_NONE
```

Files written to the volume (SHA-256 from `Get-FileHash`, the Tier-1 content
oracle for a later phase):

| Path                       | SHA-256 |
|----------------------------|---------|
| `R:\dir_a\known1.txt` ("hello refs P0", no newline) | `2D181D16EEF49251A951F26E2906A5E11183F57758A1982E3BFF6137F6FD481F` |
| `R:\dir_a\nested\big.bin` (1 MiB, `fsutil file createNew`) | `30E14955EBF1352266DC2FF8067E68104607E750ABB9D3B36582B8AF909FCB58` |

Partition offset in the VHD: **16,777,216** (16 MiB).

## Fixtures

#### refs_boot_superblock.bin (committed, always-on)

- **Class:** REAL-self Tier-2 (self-mint).
- **Source:** first **128 KiB** of the ReFS partition described above — covers
  the boot VBR (cluster 0) through the primary superblock (`SUPB`) at cluster 30
  (byte offset `0x1e000`).
- **Identity/metadata:** ReFS v3.14, serial `0x4e32fc4432fc3317`, 512-byte
  sectors, 4096-byte clusters.
- **MD5:** `073a99d7b12fd06eb72426ef036eff72`
- **SHA-256:** `95dff9c082cc6890921bdb654a0fafaa379e4c9e632e2bb4986d3dbf899c1358`
- **Verified offsets (each byte confirmed against the fixture AND fsutil):**
  `[3..11]="ReFS\0\0\0\0"`, `[16..20]="FSRS"`, `[24]` num_sectors=125698048,
  `[32]` bytes_per_sector=512, `[36]` sectors_per_cluster=8, `[40]` major=3,
  `[41]` minor=14, `[56]` serial=0x4e32fc4432fc3317, `[64]` container=67108864,
  `SUPB` block at `0x1e000` (cluster 30) whose self-describing block number = 30.
- **Consumed by:** `core/tests/boot.rs` (P0 boot + superblock + version tests).
- **Redistribution:** self-authored bytes of an empty-ish minted volume; no
  third-party IP. Committed (128 KiB, excluded from the published `.crate`).

#### refs_partition_head.bin (gitignored — NOT committed)

- **Class:** REAL-self Tier-2 (self-mint).
- **Source:** first **16 MiB** of the same partition (boot + superblock +
  ministore blocks). Too large to commit; the 128 KiB slice above is the
  always-on subset.
- **MD5:** `1a38a7ff099bcd1d58cce9f8e29c9db2`
- **SHA-256:** `f2388f5fa0f4b077400d96a01835fb65f60d15ccfe377c0cba7007061201ccb0`
- **Consumed by:** `core/tests/boot.rs::full_partition_head_env_gated` and
  `core/tests/minstore.rs::real_volume_*_env_gated` (P1), gated on
  `REFS_TIER2_ORACLE` (points at this file). Re-mint from the generator to
  reproduce; skips cleanly when absent.
- **P1 verified contents (real-volume Doer-Checker):** at 16 KiB metadata pages,
  the SUPB (`0x1e000`, cluster 30) and **39 Minstore B+-tree (`MSB+`) pages**
  (clusters 36+). The **object tree** is the `MSB+` page at cluster 56
  (`0x38000`, table id `0x2`), a level-0 leaf carrying object ids
  `0x7,0x8,0x9,0xa,0xd,0x500,0x501`; cluster 40 (`0x28000`) is a level-1 branch
  node. The SUPB's checkpoint references name blocks `[157156, 1885500]`.

> **NOTE — checkpoint block is NOT reachable in any committable slice (ReFS v3
> virtual addressing).** The checkpoint block numbers `[157156, 1885500]` are
> **virtual addresses** (byte offsets ~614 MiB and ~7.2 GiB into the volume),
> far beyond the sparse **520 MiB** physical partition — a full raw dump of the
> whole partition contains **no `CHKP` block at all**. Resolving a virtual block
> number to a physical one needs the container table, so parsing the `CHKP`
> body (its object-table pointer) is deferred to a later phase; P1 validates the
> object tree directly from its physically-resident `MSB+` page (cluster 56)
> and exposes the checkpoint *locations* the superblock names. The 60 GB dynamic
> VHD that minted the P0 fixture was detached after minting and is not retained
> at full size, so a larger slice could not be pulled; the 16 MiB head remains
> the oracle. (Investigated 2026-07-15 by re-attaching the residual VHDX in the
> Parallels Windows 11 VM and dumping `\\.\PhysicalDrive` at the partition
> offset — confirmed the checkpoint lies outside the physical partition.)

<!-- TODO(corpus-catalog): also record in issen/docs/corpus-catalog.md the P1
     verified contents above (object tree @ cluster 56, checkpoint = virtual
     addresses). NOT done here — this task touches ONLY refs-forensic. -->

### CRC coverage-range — undetermined (do not fabricate)

The ReFS v3 metadata block reference carries a checksum descriptor (type `1` =
CRC-32C, `2` = CRC64-ECMA-182). The exact **byte range** the checksum covers is
**not documented** in the reverse-engineered references (libfsrefs marks it
`TODO`) and an empirical brute-force over the real SUPB self-reference
(`0x41e9cc52`) did not reproduce it from any obvious contiguous range (starts
`{0, 80, 208}` × every end, checksum-field zeroed or not, both CRC init
conventions). `refs-core` therefore ships the CRC **algorithms** (validated
against their published check values — an independent Tier-1 answer key) and a
**range-explicit** verifier (`MetaBlock::verify_crc32c(data, start, end,
stored)`), but does **not** guess ReFS's coverage range — automatic whole-block
`crc_valid` stays `None`-equivalent until a later phase pins the range, so a
clean block is never mislabelled corrupt (the LZNT1-trap the fleet standards
warn against).

<a name="generator"></a>
## Generator (verbatim)

Re-mint on a Windows 11 (build ≥ 22621) VM with the Parallels `\\Mac\Cases`
share enabled. The full script is preserved at
`~/Documents/Cases/refs-mint/mint4.ps1`; its load-bearing steps:

```powershell
# 60 GB DYNAMIC VHD via diskpart (Dev Drive needs >= 50 GB; dynamic keeps the
# on-disk footprint small). No Hyper-V module required.
diskpart /s dp_create.txt   # create vdisk file=C:\cases\refs-test.vhdx maximum=61440 type=expandable
                            # attach vdisk ; convert gpt ; create partition primary
$part = Get-Partition -DiskNumber <n> | ? { $_.Type -ne 'Reserved' } | sort Size -desc | select -First 1
Format-Volume -Partition $part -FileSystem ReFS -DevDrive -NewFileSystemLabel REFSTEST -Confirm:$false
$part | Add-PartitionAccessPath -AccessPath "R:\"
fsutil fsinfo refsinfo R:
New-Item -ItemType Directory "R:\dir_a\nested" -Force
"hello refs P0" | Out-File "R:\dir_a\known1.txt" -Encoding utf8 -NoNewline
fsutil file createNew "R:\dir_a\nested\big.bin" 1048576
Get-ChildItem -Recurse -File R: | Get-FileHash -Algorithm SHA256
# read the first 16 MiB of the partition from \\.\PhysicalDrive<n> at the
# partition offset (16777216) -> refs_partition_head.bin
diskpart /s dp_detach.txt   # select vdisk file=... ; detach vdisk
```

<!-- TODO(corpus-catalog): add a REAL-self Tier-2 row for
     tests/data/refs_boot_superblock.bin (ReFS v3.14 boot+SUPB, self-mint,
     md5 073a99d7b12fd06eb72426ef036eff72) and a gitignored row for
     refs_partition_head.bin (md5 1a38a7ff099bcd1d58cce9f8e29c9db2) to
     issen/docs/corpus-catalog.md. NOT done here — this task touches ONLY the
     refs-forensic repo; add it to the issen catalog in a separate change. -->

See the fleet catalog at
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) for the
machine index; this README is the co-located human detail.
