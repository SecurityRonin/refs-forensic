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

> **NOTE — the root DIRECTORY tree is NOT reachable in the oracle either (ReFS
> v3 virtual addressing, P2).** The minted files live under the root directory
> (object id `0x600`). On the real oracle the object tree's level-1 **branch**
> node (cluster 40/44) points every child at **virtual block `34_494_087_168`**
> — a virtual address ~132 TiB into the volume, far outside the sparse physical
> partition. A full scan of the 16 MiB head (P2 Doer-Checker, 2026-07-15) finds
> **zero** directory-index rows (record type `0x0030`) and **zero** occurrences
> of the minted filenames `dir_a` / `nested` / `known1.txt` / `big.bin`: the
> root-directory B+tree pages are **not physically resident**. Every resident
> `MSB+` page (clusters 30–3584) is system metadata (object table, allocators,
> schema, container/attribute tables). Reaching `0x600`'s directory page needs
> the container table (virtual→physical translation), a later phase — pulling a
> larger *physical* slice cannot help, because the address is virtual, not a
> byte offset. So `refs_core::list_dir(&oracle, 0x600)` deliberately fails LOUD
> with `RefsError::UnresolvedVirtualBlock`/`ObjectIdNotFound`
> (`core/tests/directory.rs::real_volume_root_directory_is_unreachable_env_gated`)
> rather than fabricate a listing; the directory/file-record **parsing**
> (`parse_directory` / `FileMetadata` / `find_by_path`) is validated **Tier-3**
> against synthetic pages built to the exact libfsrefs directory-object layout.

> **CORRECTION (P3, 2026-07-15) — `34_494_087_168` was a MIS-IDENTIFIED
> checksum descriptor, not a virtual block.** P3 re-examined the object/branch
> record values byte-for-byte: the object record value's real tree-root block
> number sits at value `+32` (the metadata block reference's first block
> number). The `34_494_087_168` (`0x8_0802_0000`) that P2 read as a virtual
> block is the **checksum descriptor** bytes at value `+64`
> (`00 00 02 08 08 00 00 00` = unknown `0x0000`, checksum type `0x02` = CRC64,
> data offset `0x08`, data size `0x0008`) — a constant template that repeats on
> every record, which is why it looked like "every child points at the same
> block." The real root-directory tree-root block on the fresh P3 volume is
> `80_384` — a small, resolvable virtual block. The P2 wall was real (the root
> dir page is non-resident in the 16 MiB head), but its stated *cause* is
> corrected here.

> **P3 — the container table CRACKS virtual→physical; the root-dir page now
> resolves (2026-07-15).** P3 builds the ReFS **container table** (`libfsrefs`
> §8) — the virtual→physical band map — and translates. Mechanism (byte-verified
> on a fresh v3.14 mint): a **band** is `band_size / cluster_size = 67_108_864 /
> 4096 = 16_384` clusters; a virtual block decomposes into
> `container_index = vblock / 16_384` and `offset = vblock % 16_384`; the
> container tree's 160-byte records give each band's physical base cluster (value
> `+144` = LCN, `+152` = cluster count). The `container_index → physical_base`
> map is bootstrapped from resident pages' self-block-numbers (ground truth:
> `self % 16_384 == phys_cluster - LCN` holds on **every** resident page).
> **Result:** object `0x600` → block `80_384` → container 4, offset `14_848` →
> **physical cluster `14_848`**, and the page there has self-block-number exactly
> `80_384` and table id `0x600` — resolution correct by self-block round-trip.
> **Honest remaining wall:** the resolved `0x600` page is an *index-root* whose
> directory *entry* records live one Minstore indirection deeper, in a
> non-resident band, so the real minted-file *listing* still cannot be produced
> here (`list_dir(0x600)` stays fail-loud); that descent is `parse_directory`'s
> job (P2 layer), not the container table's.

#### refs_v314_container_tree_page.bin, refs_v314_object_table_0x600.bin, refs_v314_dir_0x600_root.bin (committed, always-on — P3)

- **Class:** REAL-self Tier-2 (self-mint), three single 16 KiB `MSB+` metadata
  pages extracted from a **fresh** ReFS v3.14 volume (see the P3 mint below).
- **`refs_v314_container_tree_page.bin`** — the real container tree (`libfsrefs`
  §8) leaf, table id `0xB`, self-block `16_384`, **88** 160-byte container
  records (band_id → physical LCN). MD5 `3194738db0c407f01fa053bc9773a382`,
  SHA-256 `a152d615d044bc854fe0e0bbad548b04fab92105987e6cd717e5dc62d9ed7256`.
- **`refs_v314_object_table_0x600.bin`** — the object table (table id `0x2`)
  carrying `0x600` → tree-root block `80_384`. Self-block `67_588`. MD5
  `d5e83093e33c4f982a68aff075e55e48`, SHA-256
  `b9c14ce18575c3b40303f19e922427d53cca97d7c76d883d238ab634ebf02018`.
- **`refs_v314_dir_0x600_root.bin`** — the `0x600` directory root page the
  container resolver lands on (table id `0x600`, self-block `80_384`). MD5
  `192c772fd7882d595a8308a01573242b`, SHA-256
  `46eff658227b14e5d2d138de3cdac10186276febac8afec2b19dda4e7576d731`.
- **Consumed by:** `core/tests/container.rs` (P3 container-table + resolver
  tests, always-on).
- **Redistribution:** self-authored bytes of a minted volume; no third-party IP.

#### refs_container_head256.bin (gitignored — NOT committed, P3 oracle)

- **Class:** REAL-self Tier-2 (self-mint).
- **Source:** first **256 MiB** of a **fresh** ReFS v3.14 partition (see the P3
  mint below) — reaches the object table (cluster 2052), the container tree
  (cluster 16384), and the resolved `0x600` directory root (cluster 14848).
- **MD5:** `8d09e81af8b939151fe0ae81d90b4623`
- **SHA-256:** `efe5eb01594c56e486cf4845a2cd948d4daf73c3243d7f1076e0314a1640a679`
- **Consumed by:** `core/tests/container.rs::real_volume_container_resolves_root_directory_page_env_gated`,
  gated on `REFS_TIER2_ORACLE256`. Re-mint from the P3 generator to reproduce;
  skips cleanly when absent.

##### P3 generator (fresh v3.14 mint + 256 MiB slice)

The original 60 GB VHD that produced `refs_partition_head.bin` was detached and
gone (only an empty leftover `refs-test.vhdx` with no ReFS remained), so P3
minted a **fresh** volume. This means the P3 fixtures are a **different** volume
than the P1/P2 16 MiB oracle — the container-resolver facts are re-verified on
this new volume, not cross-referenced to the old head. Minted 2026-07-15 on the
Parallels **Windows 11** VM (build 26200) via a script run through the
`\\Mac\Cases` shared folder (`C:\cases5\mint5.ps1` / `slice256.ps1`), load-bearing
steps:

```powershell
# 60 GiB dynamic VHD via diskpart (Dev Drive needs >= 50 GB), attach, GPT,
# primary partition; disk number detected as the newly-attached disk.
diskpart /s dp_create.txt        # create/attach/convert gpt/create partition primary
$part = Get-Partition -DiskNumber $diskNum | ? { $_.Type -ne 'Reserved' } | sort Size -desc | select -First 1
Format-Volume -Partition $part -FileSystem ReFS -DevDrive -NewFileSystemLabel REFSTEST -Confirm:$false
$part | Add-PartitionAccessPath -AccessPath 'R:\'
fsutil fsinfo refsinfo R:        # ReFS 3.14, 4096-byte clusters, band size 67108864
New-Item -ItemType Directory 'R:\dir_a\nested' -Force
"hello refs P0" | Out-File 'R:\dir_a\known1.txt' -Encoding utf8 -NoNewline
fsutil file createNew 'R:\dir_a\nested\big.bin' 1048576
# read the first 256 MiB of the partition from \\.\PhysicalDrive<n> at the
# partition offset (16777216) -> refs_container_head256.bin ; copy to the share
diskpart /s dp_detach.txt        # detach vdisk
```

<!-- TODO(corpus-catalog): also record in issen/docs/corpus-catalog.md the P1
     verified contents above (object tree @ cluster 56, checkpoint = virtual
     addresses), the P2 finding (root directory 0x600 non-resident; directory
     parsing is Tier-3), and the P3 container-table crack (band size 16384
     clusters; container tree 160-byte records band_id->LCN; 0x600 block 80384 ->
     container 4 offset 14848 -> cluster 14848; fresh v3.14 mint fixtures
     refs_v314_*.bin + gitignored refs_container_head256.bin md5
     8d09e81af8b939151fe0ae81d90b4623). NOT done here — this task touches ONLY
     refs-forensic. -->

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
