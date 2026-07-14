# ReFS Forensic Reader — Research-First Report (`refs-core` + `refs-forensic`)

Read-only Research-First deliverable.

**Overriding caveat (threaded throughout):** ReFS is **undocumented** — Microsoft
publishes *no* on-disk specification. Every structural fact below is from third-party
**reverse engineering** → Tier-2 at best. ReFS is also **version-fragmented**: the
on-disk format changed materially between v1.x (Server 2012/8.1) and v3.x (Server
2016+/Win10+/Win11), and *each Windows release tweaks it further*. A reader validated
against one build can silently misparse another. Windows **auto-upgrades a volume to
the newest format version on mount** (Nordvik et al.) → the newest v3.x is what matters
forensically. This version fragmentation — not algorithmic depth — is the single
hardest thing.

## 1. Authoritative sources (reverse-engineered — NO official Microsoft spec)

**De-facto spec (single most important reference):**
- **libfsrefs (Joachim Metz / libyal)** — https://github.com/libyal/libfsrefs. C
  library + `fsrefsinfo`, LGPLv3+, experimental, read-only.
- Its format doc: **`documentation/Resilient File System (ReFS).asciidoc`**
  (https://github.com/libyal/libfsrefs/blob/main/documentation/Resilient%20File%20System%20(ReFS).asciidoc)
  — the closest thing to a spec; honest about its own incompleteness (many fields
  `TODO`/`Unknown`; the **C library is v1-only**, v2/v3 unsupported in code — though the
  *documentation* + a contributor's PR go further, see §2).

**Academic / peer-reviewed (strongest secondary — deeper than libfsrefs on v3.x + CoW):**
- **Nordvik, Georges, Toolan, Axelsson — "Reverse engineering of ReFS"** (Digital
  Investigation, 2019) — https://www.sciencedirect.com/science/article/pii/S1742287619301252.
  Documents v1.2 (Server 2012) + v3.2; block-sharing (copy → shared content blocks;
  edit → new runs, unchanged blocks shared) — relevant to carving.
- **Prade, Groß, Dewald — "Forensic Analysis of the Resilient File System (ReFS)
  Version 3.4"** (FSI: Digital Investigation, 2020) —
  https://www.sciencedirect.com/science/article/pii/S266628172030010X /
  DFRWS PDF. **The deepest v3.x source** — reverse-engineers v3.4, introduces virtual
  addresses, documents CoW, proposes deleted-file/old-version recovery, extends TSK,
  implements a **page carver**. Source: Paul Prade's TSK fork
  (https://faui1-gitlab.cs.fau.de/paul.prade/refs-sleuthkit-implementation).
- **"Forensic analysis of ReFS journaling"** (DFRWS APAC 2021) — ReFS Logfile + Change
  Journal; **Log Record** + **USN_RECORD_V3** (distinct from NTFS).

**Unverified — dropped:** a "Williballenthin / FireEye-Mandiant ReFS" reverse-
engineering piece could **not be confirmed**; the load-bearing secondary literature is
Nordvik + Prade, not a Mandiant blog. (Paragon Software's ReFS driver is closed-source
commercial — behavioral reference only.)

**What IS known of the structures (from the libfsrefs asciidoc):**
- **Boot / FS-recognition** at **offset 0**: 3-byte jump, signature `"ReFS\x00\x00\x00\x00"`
  at offset 3, **`"FSRS"`** at offset **16**, then sector count, sector size,
  sectors-per-cluster, **Major/Minor format version at offsets 40/41** (where you read
  the version), volume serial (56), container/band size (64).
- **Page-based metadata.** Block signatures by level: **`"SUPB"` superblock (L0),
  `"CHKP"` checkpoint (L1), `"MSB+"` Ministore B+-tree (L2+)**. Block/page typically
  **16 KB** (confirm per volume via cluster fields / `fsutil`).
- **Minstore B+-tree** — the core structure (ReFS is a key-value B+-tree store).
  Everything (dirs, object table, volume info) is a Minstore tree of key→value records.
  Node header + tree header (36 bytes) + records.
- **Metadata block header differs by version:** a **format-v1** header is 48 bytes
  starting with a volume-relative block number; a **format-v3 metadata block reference**
  is 48 bytes carrying **four block numbers** (redundancy) + a **checksum descriptor**
  (type/data offset/data size). This four-copy + checksum-descriptor layout is a
  concrete v1↔v3 divergence.
- **Object table indirection** — maps **logical object IDs → metadata block locations**
  (Prade's "virtual addresses" in v3.x add another indirection: resolve virtual →
  physical before reading). Walked before file records resolve.
- **Directory object** = a Minstore B+-tree of directory records; entry types **0 =
  FS-metadata file, 1 = File, 2 = Directory**. Attributes reuse NTFS-like type codes
  (`0x10 $STANDARD_INFORMATION`, `0x30 $FILENAME`, `0x80 $DATA`, `0xa0 $INDEX_ALLOCATION`,
  `0xc0 $REPARSE_POINT`, `0xe0 $EA`). **Data runs** map file data to metadata-block
  ranges (logical offset + run size in blocks). Filenames are **UCS-2 + unpaired
  surrogates** (not strict UTF-16 — a robustness quirk the spec calls out).
- **Nature:** integrity-streams (checksummed metadata, optional file-data integrity),
  **allocate-on-write / copy-on-write** — metadata never overwritten in place; a new
  page is allocated and the tree re-pointed → **stale metadata pages recoverable** (the
  basis of deleted-file/old-version carving).

**Version fragmentation (the biggest problem), per the libfsrefs version table:**

| Version | Windows release |
|---|---|
| 1.2 | Server 2012 / 8.1 (legacy) |
| 3.0 | Server 2016 (preview) |
| 3.1 | Server 2016 |
| 3.2 | Win10 1703 |
| 3.3 | Win10 1709 |
| 3.4 | Win10 1803 / Server 2019 |
| 3.5–3.6 | Win11 (preview) |
| 3.7 | Win11 / Server 2022 |
| 3.9 | Win11 Enterprise Insider (25236) — adds LZ4/ZSTD compression |

A v1 reader and a v3 reader parse genuinely different layouts.
([XenoPanther version gist](https://gist.github.com/XenoPanther/15d8fad49fbd51c6bd946f2974084ef8) = build→version cross-ref.)

## 2. Existing implementations (build-vs-reuse)

**Pure-Rust ReFS parser: effectively NONE** — a genuine greenfield. The only Rust hits
are unrelated (`copy_on_write` uses ReFS reflink Win APIs; the `windows` crate's
`REFS_COMPRESSION_FORMATS` binding).

**Reference readers / oracles:**
- **libfsrefs (`fsrefsinfo`)** — most mature RE reader + **structural oracle**.
  Completeness: shipped **C library is v1-only** ("finishing planned"), BUT its
  [PR #10](https://github.com/libyal/libfsrefs/pull/10) records a contributor parsing
  **v3.1/v3.4/v3.7/v3.9** (all dirs/files + content from data runs, with the
  UCS-2+surrogate caveat) — so the *documentation* reaches v3.x even where the C code
  doesn't. Specimens: **dfirlabs `refs-specimens`**.
- **Prade's TSK fork** (GitLab) — a **second, independent v3.4 reader + page carver**,
  validated vs the Windows driver → a second oracle (breaks the LZNT1-trap correlation
  with libfsrefs).
- **TSK does NOT support ReFS** (confirmed; mainline supports NTFS/FAT/exFAT/APFS/UFS/
  ext/HFS/ISO9660/YAFFS2). ReFS-in-TSK exists only as Prade's academic fork.
- **Commercial (behavioral references only):** X-Ways, EnCase, Magnet AXIOM read ReFS;
  Paragon ships a ReFS driver for Linux/macOS. Cross-check behavior, not spec.

**Recommendation: BUILD** pure-Rust clean-room `refs-core` from the libfsrefs asciidoc
+ Prade/Nordvik papers (no Rust prior art; C libs are LGPL and forbid-unsafe rules out
FFI). Use `fsrefsinfo` as the structural cross-check + **Prade's TSK fork as a second,
independent structural oracle**.

**LZNT1-trap risk is acute here:** libfsrefs is *itself* reverse-engineered → a
wrong-reader + wrong-oracle can agree and ship green. **Content-hash validation against
the live Windows ReFS driver is mandatory, not optional** — Windows' own driver is the
only authoritative source of true file bytes. **Structural metadata cannot reach Tier-1
on this filesystem.**

## 3. Real sample data + oracle (Tier-1 plan)

Mint on the Parallels Windows 11 VM. Win11 client creates ReFS via **Dev Drive**
(`Format-Volume -DevDrive`, `format D: /DevDrv`) and, on a VHDX, via plain
`Format-Volume -FileSystem ReFS`. The version stamped is build-dependent (Win11/Server
2022 → v3.7; newer Insiders → v3.9); C: cannot be a Dev Drive. **Record the stamped
version — it's the whole ballgame.**

```powershell
$vhd = "C:\cases\refs-test.vhdx"
New-VHD -Path $vhd -SizeBytes 8GB -Dynamic
Mount-VHD -Path $vhd
$disk = Get-VHD -Path $vhd | Get-Disk
Initialize-Disk -Number $disk.Number -PartitionStyle GPT
$part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $part -FileSystem ReFS -NewFileSystemLabel "REFSTEST" -Confirm:$false
$drv = ($part.DriveLetter + ":")
fsutil fsinfo refsinfo $drv     # ReFS version (e.g. 3.7) + cluster/metadata block size
New-Item -ItemType Directory "$drv\dir_a\nested" | Out-Null
"hello refs" | Out-File "$drv\dir_a\known1.txt" -Encoding utf8
fsutil file createNew "$drv\dir_a\nested\big.bin" 5242880
Get-ChildItem -Recurse -File $drv | Get-FileHash -Algorithm SHA256 |
    Select-Object Path,Hash | Export-Csv C:\cases\refs-truth.csv -NoTypeInformation
Remove-Item "$drv\dir_a\known1.txt"   # optional: exercise CoW deleted-file recovery
Dismount-VHD -Path $vhd     # then copy the .vhdx off; parse the partition offline
```

Oracles:
```bash
# (a) libfsrefs fsrefsinfo — STRUCTURAL, Tier-2 (reverse-engineered)
git clone https://github.com/libyal/libfsrefs && cd libfsrefs
./synclibs.sh && ./autogen.sh && ./configure && make
./fsrefsinfo /path/to/refs-partition.raw
./fsrefsinfo -H /path/to/refs-partition.raw
# reconcile vs Prade's TSK fork (fsstat/fls/usnjls) as an independent 2nd structural oracle
# (b) mount on Windows + Get-FileHash — CONTENT oracle, Tier-1 (LZNT1-trap breaker)
```

**Explicit tiering:** **content = Tier-1** (Windows driver); **structure = Tier-2 only**
(libfsrefs/Prade, both RE). **ReFS is the one filesystem where structural metadata
cannot reach true Tier-1** — state so in `docs/validation.md`. **Corpora:** rare;
dfirlabs `refs-specimens`; otherwise self-mint. Document per fleet provenance standard.

## 4. Scope/difficulty + phased order

**Why hard — a different axis than ZFS:** not algorithmic depth (ordinary B+tree,
simple checksums) — **undocumented + version-fragmented**: reverse-engineering from
incomplete third-party notes, correctness a per-version/per-build moving target.
**Moderate algorithmic complexity, HIGH reverse-engineering + version-testing burden —
harder to validate than to write.**

**Target ONE version first: ReFS v3.x — the v3.4 / v3.7 line** (Win10 1803+/Server
2019 → Win11/Server 2022). Rationale: most forensically relevant (Server, Hyper-V VM
storage, Storage Spaces, backup targets, Win11 Dev Drives); Windows auto-upgrades on
mount; v3.4 is best-documented (Prade paper + TSK code + carver). **De-scope v1.2** to
a later phase (materially different, low-value).

**MVP `refs-core` scope (v3.x read-only):**
1. Boot/FS-recognition at offset 0 → `FSRS` + Major/Minor version (**gate: fail loud
   with the actual version bytes on any untested version — never silently misparse**).
2. Superblock (`SUPB`) → checkpoint (`CHKP`) → locate object/container table.
3. **Minstore B+-tree traversal** (generic key→value node walker — the reusable engine).
4. **Object-table + virtual-address indirection** (logical→physical before reading).
5. **Page checksum validation** (checksum-descriptor type/offset/size).
6. Directory-object walk → file records → attributes → **data runs** → **file content
   extraction** (the Tier-1 content-hash gate).
7. UCS-2-with-unpaired-surrogates filename decoding.

**What libfsrefs already solved (we follow):** metadata-block layout, level signatures,
Minstore node/tree headers, attribute type codes, data-run format. Prade adds v3.4
virtual addresses + CoW.

**Version-coverage RISK (own explicitly):** a reader validated on one build (v3.7) may
break on v3.4/v3.9 (Minstore tweaked per release; v3.9 adds LZ4/ZSTD). Mitigation:
version-gate hard, keep a **per-version test image** for every claimed version, mark
unclaimed versions unsupported-fail-loud (show the version bytes).

**Phases:**
- **`refs-core`** — Phases 1→7, single version (v3.7 or v3.4). Panic-free bounds-checked;
  fuzz target per parsed structure (boot, metadata-block, minstore node, object-table
  entry, data-run); **Tier-1 content-hash** vs the Windows driver + **Tier-2 structural**
  reconcile vs `fsrefsinfo` and Prade's TSK, in `docs/validation.md`. Widen versions
  (v3.4, v3.9) as separate individually-validated increments.
- **`refs-forensic`** — over `refs-core` (or at the raw page level per the reader/
  analyzer-split principle): **(a) deleted-file/old-version recovery via CoW stale
  metadata pages** (Prade's page carver = model + oracle); **(b) integrity-stream/
  page-checksum analysis** (mismatch = corruption/tampering); **(c) USN Change Journal
  + Logfile** (`USN_RECORD_V3`, Log Record). Findings → `forensicnomicon::report::Finding`
  (`REFS-PAGE-CHECKSUM-MISMATCH`, `REFS-DELETED-FILE-CARVED`, `REFS-USN-…`).

**Tiering (restated):** every value-producing path in `refs-core` (file content, data-
run resolution) needs **Tier-1 content validation** (Windows driver hashes — the only
independent oracle); structural metadata is **Tier-2** and must be cross-checked vs
**both** libfsrefs *and* Prade's TSK fork (avoid a single-RE-oracle blind spot).

**Gaps/throttling:** Andrea Fortuna intro blog (404), ScienceDirect full texts (403
paywall — DFRWS open PDFs captured instead), one MS versions page (404) — none load-
bearing. The "Williballenthin/FireEye-Mandiant ReFS" reference is unverified — dropped.
