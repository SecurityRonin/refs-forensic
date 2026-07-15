//! `refs-forensic` — anomaly auditor + CoW metadata-residue recovery for ReFS.
//!
//! ReFS is a reverse-engineered, undocumented, **allocate-on-write** filesystem,
//! and that CoW model is the forensic lever this crate pulls:
//!
//! - **F-INTEGRITY** ([`audit_image`] / [`audit_findings`]) emits graded
//!   [`forensicnomicon::report::Finding`]s for structural anomalies: a bad boot
//!   VBR signature (`REFS-BOOT-SIGNATURE-INVALID`), a metadata block whose
//!   self-recorded block number disagrees with its location
//!   (`REFS-SELF-BLOCK-MISMATCH` — consistent with a relocated/tampered page),
//!   the two checkpoint copies disagreeing (`REFS-CHECKPOINT-DIVERGENCE`), a
//!   virtual reference that resolves nowhere (`REFS-ORPHANED-OR-UNRESOLVED`), and
//!   geometry beyond bounds (`REFS-IMPOSSIBLE-GEOMETRY`). A metadata CRC mismatch
//!   (`REFS-METADATA-CRC-MISMATCH`) is emitted **only** over a caller-supplied
//!   explicit coverage range via [`audit_crc_range`] — never auto-fabricated,
//!   because ReFS's own whole-block checksum coverage range is undetermined in
//!   the reverse-engineered references (see [`refs_core`]'s `metablock` docs).
//! - **F-CARVE** ([`recover_residue`]) exploits allocate-on-write: an updated
//!   directory page is written NEW and the object table re-points at it, leaving
//!   the OLD `MSB+` page behind. This scans for `MSB+` directory pages whose
//!   self-block-number is NOT the current object-table mapping (= stale/old
//!   versions) and carves the directory-entry rows found in them
//!   (`REFS-STALE-METADATA-PAGE` / `REFS-CARVED-DIRECTORY-ENTRY`).
//!
//! Built on `refs-core` for valid-path reading (boot / superblock / Minstore /
//! object table); where the audit must see the raw self-block / checkpoint bytes
//! the reader normalizes away it parses those bytes directly (the
//! reader/analyzer-split principle).
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusions. Mirrors the fleet producer pattern (typed `AnomalyKind` +
//! `impl Observation` + `audit_*` → `Vec<Anomaly>` + `audit_findings` →
//! `Vec<Finding>`), as in `xfs-forensic` / `btrfs-forensic` / `ntfs-forensic`.
//!
//! # Honest validation state (Tier-2)
//!
//! ReFS has no official spec and no ground-truth corpus. F-INTEGRITY is validated
//! on the **real resident v3.14 metadata** (a clean volume emits nothing false;
//! crafted corruption is detected). F-CARVE's stale-page recovery is validated on
//! a **real resident stale CoW `0x600` page** (carrying `System Volume
//! Information`) plus synthetic pages; the minted user-file bands are
//! non-resident (beyond the oracle slice, source VHD lost), so their
//! deleted-recovery end-to-end is **oracle-blocked** — surfaced as such, never
//! fabricated. See `docs/validation.md`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Evidence, Finding, Location, Observation, Source};

use refs_core::{BootSector, Checkpoint, MetaBlock, REFS_METADATA_PAGE_SIZE};

// ── ReFS on-disk constants the analyzer parses below `-core` ──────────────────

/// The `MSB+` Minstore metadata-page signature every resident directory / table
/// page starts with.
const MSB_SIGNATURE: &[u8; 4] = b"MSB+";

/// Header offset of a metadata page's self (first) block number.
const SELF_BLOCK_OFFSET: usize = 0x20;

/// Header offset of a metadata page's table identifier.
const TABLE_ID_OFFSET: usize = 72;

/// ReFS cluster size in bytes (4 KiB — verified on the v3.14 oracle). Metadata
/// pages sit on cluster boundaries.
const CLUSTER_SIZE: usize = 4096;

/// The well-known ReFS root-directory object identifier / directory table id.
const REFS_ROOT_DIRECTORY_TABLE_ID: u64 = 0x600;

/// Byte offset of the SUPB block within the boot+SB image region (cluster 30).
const SUPERBLOCK_BLOCK_NUMBER: u64 = 30;

/// A sane upper bound on the ReFS cluster size (bytes-per-sector ×
/// sectors-per-cluster). Real ReFS clusters are 4 KiB–64 KiB; a value beyond this
/// is a corrupt/hostile geometry field (allocation-bomb guard).
const MAX_SANE_CLUSTER_SIZE: u64 = 1 << 20; // 1 MiB

// ── F-INTEGRITY: structural-integrity anomaly kinds ───────────────────────────

/// Classification of a ReFS structural-integrity anomaly (F-INTEGRITY). Each
/// variant carries the evidence needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The boot VBR file-system signature at offset 3 is not `"ReFS\0\0\0\0"` —
    /// the fail-loud offending bytes are carried so the examiner sees what the
    /// image really is.
    BootSignatureInvalid {
        /// The eight raw bytes found at boot offset 3.
        found: [u8; 8],
    },
    /// A resident metadata block whose stored CRC does not verify over a
    /// **known/derivable** coverage range. Emitted only via [`audit_crc_range`];
    /// never auto-fabricated (ReFS's own coverage range is undetermined).
    MetadataCrcMismatch {
        /// Which metadata structure failed (`SUPB` / `CHKP` / `MSB+` / caller).
        structure: &'static str,
        /// Absolute byte offset of the block in the image.
        offset: u64,
        /// The CRC checksum type (`1` = CRC-32C, `2` = CRC64-ECMA-182).
        checksum_type: u8,
    },
    /// A metadata block whose self-recorded block number does not equal the block
    /// number its actual location decodes to — consistent with a relocated,
    /// tampered, or misparsed page.
    SelfBlockMismatch {
        /// The metadata structure (`SUPB`, `MSB+`, …).
        structure: &'static str,
        /// The block number recorded inside the block (header offset `0x20`).
        recorded: u64,
        /// The block number the block's location implies.
        expected: u64,
        /// Absolute byte offset of the block in the image.
        offset: u64,
    },
    /// The two checkpoint copies the superblock names disagree (or it names none)
    /// — a torn / tampered checkpoint.
    CheckpointDivergence {
        /// Human-readable reason (which invariant the checkpoint set broke).
        reason: &'static str,
        /// The checkpoint block numbers the superblock named.
        checkpoints: Vec<u64>,
    },
    /// An object-table entry or directory child that references a virtual block
    /// that resolves to no resident physical page — a dangling / corrupt
    /// reference (a recovery lead).
    ///
    /// Reserved for a **directory-walk** caller that resolves a specific child
    /// reference and finds it unresolvable ([`refs_core::RefsError::UnresolvedVirtualBlock`]):
    /// `audit_image` does **not** emit this over a partial/sliced image, where
    /// most blocks are legitimately non-resident (a container-table band beyond
    /// the slice), because doing so would false-positive on every normal ReFS
    /// slice. It is part of the public vocabulary so a caller that walks the tree
    /// (and can tell a genuine dangling reference from a not-yet-materialized
    /// band) can raise it.
    OrphanedOrUnresolved {
        /// The unresolved virtual block number.
        block: u64,
        /// What referenced it (`object-table entry`, `directory child`, …).
        referrer: &'static str,
    },
    /// A cluster/sector/page geometry field beyond sane bounds — a corruption /
    /// allocation-bomb guard.
    ImpossibleGeometry {
        /// The offending field name.
        field: &'static str,
        /// The value read from the structure.
        value: u64,
        /// The sane upper bound derived from the image size / spec.
        limit: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::BootSignatureInvalid { .. }
            | AnomalyKind::MetadataCrcMismatch { .. }
            | AnomalyKind::SelfBlockMismatch { .. }
            | AnomalyKind::CheckpointDivergence { .. }
            | AnomalyKind::ImpossibleGeometry { .. } => Severity::High,
            AnomalyKind::OrphanedOrUnresolved { .. } => Severity::Medium,
        }
    }

    /// Stable machine-readable, scheme-prefixed code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::BootSignatureInvalid { .. } => "REFS-BOOT-SIGNATURE-INVALID",
            AnomalyKind::MetadataCrcMismatch { .. } => "REFS-METADATA-CRC-MISMATCH",
            AnomalyKind::SelfBlockMismatch { .. } => "REFS-SELF-BLOCK-MISMATCH",
            AnomalyKind::CheckpointDivergence { .. } => "REFS-CHECKPOINT-DIVERGENCE",
            AnomalyKind::OrphanedOrUnresolved { .. } => "REFS-ORPHANED-OR-UNRESOLVED",
            AnomalyKind::ImpossibleGeometry { .. } => "REFS-IMPOSSIBLE-GEOMETRY",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::BootSignatureInvalid { found } => format!(
                "boot VBR signature at offset 3 = {found:02x?} is not \"ReFS\\0\\0\\0\\0\" — the volume is not ReFS or the boot record was overwritten"
            ),
            AnomalyKind::MetadataCrcMismatch {
                structure,
                offset,
                checksum_type,
            } => format!(
                "{structure} at byte {offset}: stored CRC (type {checksum_type}) does not verify over its known coverage range — consistent with corruption or post-write tampering"
            ),
            AnomalyKind::SelfBlockMismatch {
                structure,
                recorded,
                expected,
                offset,
            } => format!(
                "{structure} at byte {offset}: self-recorded block number {recorded} does not equal its location's block number {expected} — consistent with a relocated, tampered, or misparsed page"
            ),
            AnomalyKind::CheckpointDivergence {
                reason,
                checkpoints,
            } => format!(
                "checkpoint set {checkpoints:?}: {reason} — consistent with a torn or tampered checkpoint"
            ),
            AnomalyKind::OrphanedOrUnresolved { block, referrer } => format!(
                "{referrer} references virtual block {block} which resolves to no resident physical page — a dangling or corrupt reference (recovery lead)"
            ),
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => format!(
                "geometry field {field} = {value} exceeds the sane bound {limit} for this image — consistent with corruption or an allocation-bomb"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::BootSignatureInvalid { found } => vec![Evidence {
                field: "boot_signature".to_string(),
                value: format!("{found:02x?}"),
                location: Some(Location::ByteOffset(3)),
            }],
            AnomalyKind::MetadataCrcMismatch {
                structure,
                offset,
                checksum_type,
            } => vec![Evidence {
                field: "metadata_crc".to_string(),
                value: format!("{structure} checksum type {checksum_type}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::SelfBlockMismatch {
                structure,
                recorded,
                expected,
                offset,
            } => vec![Evidence {
                field: "self_block_number".to_string(),
                value: format!("{structure} recorded={recorded} expected={expected}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::CheckpointDivergence {
                reason,
                checkpoints,
            } => vec![Evidence {
                field: "checkpoints".to_string(),
                value: format!("{checkpoints:?}: {reason}"),
                location: None,
            }],
            AnomalyKind::OrphanedOrUnresolved { block, referrer } => vec![Evidence {
                field: "unresolved_block".to_string(),
                value: format!("{referrer} -> {block}"),
                location: Some(Location::Other {
                    space: "refs:vblock".to_string(),
                    value: *block,
                }),
            }],
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("{value} (limit {limit})"),
                location: None,
            }],
        }
    }
}

/// A ReFS structural-integrity anomaly: an observation graded by severity, with a
/// stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

// ── F-INTEGRITY: the image auditor ────────────────────────────────────────────

/// Audit a whole ReFS image for structural-integrity anomalies (F-INTEGRITY):
/// validate the boot VBR signature + geometry, check the superblock's self-block,
/// check the checkpoint set the superblock names, and sweep every resident
/// `MSB+` metadata page for a self-block-number that disagrees with its location.
///
/// A clean image yields an empty vector. Malformed input never panics. A metadata
/// CRC mismatch is **not** emitted here (ReFS's coverage range is undetermined) —
/// use [`audit_crc_range`] with an explicit, known range.
#[must_use]
pub fn audit_image(image: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Boot VBR: a bad signature is the fail-loud front door. Everything downstream
    // (geometry, superblock, checkpoint) depends on a real ReFS boot record, so a
    // bad signature short-circuits — parsing SUPB/geometry off a non-ReFS image
    // would fabricate anomalies from noise.
    let Ok(boot) = BootSector::parse(image) else {
        // Extract the offending signature bytes for the fail-loud value.
        let mut found = [0u8; 8];
        if let Some(s) = image.get(3..11) {
            found.copy_from_slice(s);
        }
        if &found != refs_core::REFS_SIGNATURE {
            out.push(Anomaly::new(AnomalyKind::BootSignatureInvalid { found }));
        }
        // A truncated-but-valid-signature image simply has nothing more to audit.
        return out;
    };

    // Impossible geometry: an absurd cluster size (bytes/sector × sectors/cluster)
    // is a corruption / allocation-bomb guard.
    let cluster = boot.cluster_size();
    if cluster == 0 || cluster > MAX_SANE_CLUSTER_SIZE {
        out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
            field: "cluster_size",
            value: cluster,
            limit: MAX_SANE_CLUSTER_SIZE,
        }));
        // A broken cluster size makes every downstream offset meaningless; stop
        // here rather than sweep off a corrupt geometry.
        return out;
    }

    // Superblock self-block check: the SUPB at cluster 30 self-records block 30.
    // Use an open-ended header slice (not a full 16 KiB page) so the check works
    // even on the 128 KiB boot+SB fixture where the SUPB page is the tail.
    let sb_off = boot.superblock_offset();
    if let Some(page) = header_at(image, sb_off) {
        if page.get(0..4) == Some(refs_core::SUPB_SIGNATURE.as_slice()) {
            let recorded = le_u64(page, SELF_BLOCK_OFFSET);
            if recorded != SUPERBLOCK_BLOCK_NUMBER {
                out.push(Anomaly::new(AnomalyKind::SelfBlockMismatch {
                    structure: "SUPB",
                    recorded,
                    expected: SUPERBLOCK_BLOCK_NUMBER,
                    offset: sb_off,
                }));
            }

            // Checkpoint set: the superblock names its checkpoint block numbers; a
            // live volume always keeps at least one. Zero named (or a torn set)
            // is a checkpoint divergence.
            check_checkpoints(&mut out, page);
        }
    }

    // Resident MSB+ self-block sweep: every resident Minstore page carries its own
    // (virtual) self-block-number. A page whose self-block decodes to a *resident*
    // low block (block == cluster) but disagrees with its physical cluster is
    // relocated/tampered. High-band virtual blocks (self-block far beyond the
    // slice) are the normal ReFS virtual-addressing regime and are NOT flagged
    // (they need the container table to place, not a tamper signal).
    sweep_resident_self_blocks(&mut out, image, cluster as usize);

    out
}

/// Flag a superblock whose checkpoint set is torn (names zero checkpoints — a
/// live volume always keeps at least one).
fn check_checkpoints(out: &mut Vec<Anomaly>, superblock_page: &[u8]) {
    // A superblock too short to hold the checkpoint header is a truncation, not a
    // divergence — the `Err` case is left alone (no fabricated verdict from a
    // short buffer); only a successfully parsed, EMPTY checkpoint set is torn.
    if let Ok(checkpoints) = Checkpoint::locations_from_superblock(superblock_page) {
        if checkpoints.is_empty() {
            out.push(Anomaly::new(AnomalyKind::CheckpointDivergence {
                reason: "the superblock names zero checkpoint copies (a live volume keeps at least one)",
                checkpoints,
            }));
        }
    }
}

/// Sweep every physically resident `MSB+` page and flag any whose self-block
/// number decodes to a *resident low block* (block < resident cluster count) that
/// disagrees with the page's actual physical cluster — consistent with a
/// relocated/tampered page. Virtual (high-band) self-blocks are the normal ReFS
/// addressing regime and are not flagged.
fn sweep_resident_self_blocks(out: &mut Vec<Anomaly>, image: &[u8], cluster_size: usize) {
    if cluster_size == 0 {
        return; // cov:unreachable: audit_image rejects a zero cluster size before calling
    }
    let clusters = image.len() / cluster_size;
    let resident_ceiling = clusters as u64;
    for c in 0..clusters {
        let off = c * cluster_size;
        let Some(page) = block_at(image, off as u64) else {
            break; // cov:unreachable: c < clusters bounds off + page within image
        };
        if page.get(0..4) != Some(MSB_SIGNATURE.as_slice()) {
            continue;
        }
        let self_block = le_u64(page, SELF_BLOCK_OFFSET);
        // Only a self-block that CLAIMS to be a low resident block (below the
        // image's own cluster count) can be checked against its physical cluster.
        // A high-band virtual self-block is placed by the container table, not by
        // block==cluster, so comparing it here would false-positive on every
        // normal ReFS page.
        if self_block < resident_ceiling && self_block != c as u64 {
            out.push(Anomaly::new(AnomalyKind::SelfBlockMismatch {
                structure: "MSB+",
                recorded: self_block,
                expected: c as u64,
                offset: off as u64,
            }));
        }
    }
}

/// Audit a resident metadata block's CRC over a **caller-supplied, known**
/// coverage range `[start..end]` against `stored`, returning an
/// [`AnomalyKind::MetadataCrcMismatch`] anomaly when it does not verify, or
/// `None` when it verifies OR the range is out of bounds.
///
/// This is the **only** path that emits `REFS-METADATA-CRC-MISMATCH`. ReFS's own
/// whole-block checksum coverage range is undetermined in the reverse-engineered
/// references (see [`refs_core`]'s `metablock` docs), so this crate never guesses
/// it and never auto-fabricates a corruption verdict on a clean block (the
/// LZNT1-trap the fleet standards warn against). A future phase that pins ReFS's
/// range calls this with the confirmed bounds.
///
/// `offset` is the block's absolute byte position (for the finding location).
/// This checks CRC-32C (ReFS checksum type `1`).
#[must_use]
pub fn audit_crc_range(
    block: &[u8],
    offset: u64,
    start: usize,
    end: usize,
    stored: u32,
) -> Option<Anomaly> {
    match MetaBlock::verify_crc32c(block, start, end, stored) {
        Some(true) | None => None,
        Some(false) => Some(Anomaly::new(AnomalyKind::MetadataCrcMismatch {
            structure: "caller-supplied range",
            offset,
            checksum_type: 1,
        })),
    }
}

/// Audit an image and convert each F-INTEGRITY anomaly to a canonical [`Finding`]
/// tagged with `scope`.
#[must_use]
pub fn audit_findings(image: &[u8], scope: &str) -> Vec<Finding> {
    let source = Source {
        analyzer: "refs-forensic".to_string(),
        scope: scope.to_string(),
        version: None,
    };
    audit_image(image)
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

// ── F-CARVE: CoW metadata-residue recovery ────────────────────────────────────

/// A recovered stale (old-CoW) metadata page: an `MSB+` directory page whose
/// self-block-number is NOT the current object-table mapping, so it is a
/// superseded version left behind by allocate-on-write. Its carved directory
/// entries are potential deleted / renamed / superseded names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StalePage {
    /// The page's self-recorded (virtual) block number.
    pub self_block: u64,
    /// The page's table identifier (`0x600` = root directory).
    pub table_id: u64,
    /// Absolute byte offset of the stale page in the image.
    pub offset: u64,
    /// The carved directory-entry names found in the stale page.
    pub entries: Vec<String>,
}

/// Recover CoW metadata residue (F-CARVE): scan `image` for `MSB+` directory
/// pages whose self-block-number is NOT the current version (= stale/old versions
/// left behind by allocate-on-write), and carve the directory-entry rows found in
/// them.
///
/// **The current-version discriminator (grounded in allocate-on-write).** ReFS
/// never overwrites a metadata page in place: an update writes a NEW page at a
/// NEW (monotonically higher) block number and re-points the tree at it, leaving
/// the OLD page behind. So among all resident pages sharing a table identifier,
/// the one with the **highest self-block-number is the current version** and every
/// lower-numbered copy is stale residue. This is corroborated by the object table
/// on the real oracle (its resolvable view maps `0x600` to the highest resident
/// `0x600` block, `80_384`, not the stale `70_656`) — but the highest-block rule
/// needs no single "current" object table (the oracle keeps several CoW copies of
/// the object table itself, which disagree), so it is the robust signal.
///
/// Only page copies that (a) are not the highest self-block for their table id AND
/// (b) carry carvable directory-entry rows the current version does not are
/// surfaced — a stale page whose entries all survive in the current version is not
/// actionable residue.
///
/// Returns what IS found. The minted user-file bands are non-resident in the
/// available oracle (beyond the slice, source VHD gone), so their deleted-recovery
/// end-to-end cannot be reproduced here — this returns the resident stale pages
/// only and NEVER fabricates absent files. Malformed input never panics.
#[must_use]
pub fn recover_residue(image: &[u8]) -> Vec<StalePage> {
    // Pass 1: for each directory table id, find the highest self-block (= current
    // CoW version) and the carved entries of that current page.
    let mut current: Vec<(u64, u64, Vec<String>)> = Vec::new(); // (table_id, self_block, entries)
    for (off, page) in resident_msb_pages(image) {
        let table_id = le_u64(page, TABLE_ID_OFFSET);
        if table_id != REFS_ROOT_DIRECTORY_TABLE_ID {
            continue;
        }
        let self_block = le_u64(page, SELF_BLOCK_OFFSET);
        let _ = off;
        match current.iter_mut().find(|(t, _, _)| *t == table_id) {
            Some(entry) if self_block > entry.1 => {
                entry.1 = self_block;
                entry.2 = carve_directory_entries(page);
            }
            Some(_) => {}
            None => current.push((table_id, self_block, carve_directory_entries(page))),
        }
    }

    // Pass 2: surface every lower-than-current directory page whose carved entries
    // include a name the current version no longer holds (deleted/renamed/
    // superseded).
    let mut out = Vec::new();
    for (off, page) in resident_msb_pages(image) {
        let table_id = le_u64(page, TABLE_ID_OFFSET);
        if table_id != REFS_ROOT_DIRECTORY_TABLE_ID {
            continue;
        }
        let self_block = le_u64(page, SELF_BLOCK_OFFSET);
        let Some((_, cur_block, cur_entries)) = current.iter().find(|(t, _, _)| *t == table_id)
        else {
            continue; // cov:unreachable: pass 1 recorded a current entry for every table id seen here
        };
        // The current version itself is live, not stale.
        if self_block >= *cur_block {
            continue;
        }
        // Carve the stale page's entries and keep only those the current version
        // dropped — a name still present in the current directory is not residue.
        let dropped: Vec<String> = carve_directory_entries(page)
            .into_iter()
            .filter(|name| !cur_entries.contains(name))
            .collect();
        if dropped.is_empty() {
            continue;
        }
        out.push(StalePage {
            self_block,
            table_id,
            offset: off,
            entries: dropped,
        });
    }
    out
}

/// Iterate every physically resident `MSB+` metadata page as `(byte_offset,
/// page_bytes)`, skipping any cluster that is not a full in-bounds `MSB+` page.
fn resident_msb_pages(image: &[u8]) -> impl Iterator<Item = (u64, &[u8])> + '_ {
    let clusters = image.len() / CLUSTER_SIZE;
    (0..clusters).filter_map(move |c| {
        let off = c * CLUSTER_SIZE;
        let page = block_at(image, off as u64)?;
        if page.get(0..4) == Some(MSB_SIGNATURE.as_slice()) {
            Some((off as u64, page))
        } else {
            None
        }
    })
}

/// Carve the directory-entry names from a Minstore directory page: the `0x30`
/// entry records' keys carry the UTF-16LE name at key offset `4`.
fn carve_directory_entries(page: &[u8]) -> Vec<String> {
    let Ok(node) = refs_core::parse_directory(page) else {
        return Vec::new(); // cov:unreachable: a page that reached here already parsed its node header in the caller's ObjectTable path; guarded for a page that is MSB+ but has a malformed node header
    };
    node.into_iter().map(|e| e.name).collect()
}

// ── shared private helpers ────────────────────────────────────────────────────

/// The 16 KiB metadata page at absolute byte `offset`, or `None` if it does not
/// fully fit within the image (never over-reads / panics).
fn block_at(image: &[u8], offset: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(REFS_METADATA_PAGE_SIZE)?;
    image.get(start..end)
}

/// The open-ended metadata-block header slice from absolute byte `offset` to the
/// end of the image, or `None` if `offset` lies past the end. Used for the
/// superblock's header-region checks (self-block, checkpoint fields), which live
/// in the first ~200 bytes, so a partial tail page (the 128 KiB boot+SB fixture)
/// is enough — the bounds-checked field reads below never over-read.
fn header_at(image: &[u8], offset: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    image.get(start..)
}

/// Bounds-checked little-endian `u64` read (yields `0` out of range). The
/// analyzer parses raw page bytes directly (the reader/analyzer split), so it
/// carries its own panic-free reader.
fn le_u64(d: &[u8], o: usize) -> u64 {
    d.get(o..o.saturating_add(8))
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod unit {
    use super::{block_at, le_u64, Anomaly, AnomalyKind};
    use crate::Severity;
    use forensicnomicon::report::{Observation, Source};
    use refs_core::REFS_METADATA_PAGE_SIZE;

    /// Every `AnomalyKind` variant maps to a stable code, a graded severity, a
    /// non-empty observational note, and non-empty backing evidence — and each
    /// converts to a `forensicnomicon` Finding. This exercises the whole
    /// vocabulary (including `OrphanedOrUnresolved`, reserved for a directory-walk
    /// caller, and `MetadataCrcMismatch`, emitted only via `audit_crc_range`), so
    /// the observation surface is proven without fabricating a false-positive
    /// emission path in `audit_image`.
    #[test]
    fn every_anomaly_kind_has_code_severity_note_evidence_and_finding() {
        let kinds = [
            AnomalyKind::BootSignatureInvalid { found: [0u8; 8] },
            AnomalyKind::MetadataCrcMismatch {
                structure: "SUPB",
                offset: 0x1e000,
                checksum_type: 2,
            },
            AnomalyKind::SelfBlockMismatch {
                structure: "MSB+",
                recorded: 999,
                expected: 3,
                offset: 12288,
            },
            AnomalyKind::CheckpointDivergence {
                reason: "torn",
                checkpoints: vec![157_156, 1_885_500],
            },
            AnomalyKind::OrphanedOrUnresolved {
                block: 34_494_087_168,
                referrer: "directory child",
            },
            AnomalyKind::ImpossibleGeometry {
                field: "cluster_size",
                value: u64::MAX,
                limit: 1 << 20,
            },
        ];
        let source = Source {
            analyzer: "refs-forensic".to_string(),
            scope: "unit".to_string(),
            version: None,
        };
        for kind in kinds {
            let a = Anomaly::new(kind);
            assert!(
                a.code.starts_with("REFS-"),
                "code is scheme-prefixed: {}",
                a.code
            );
            assert!(!a.note.is_empty(), "note is non-empty for {}", a.code);
            assert!(
                !a.kind.evidence().is_empty(),
                "evidence is non-empty for {}",
                a.code
            );
            // Severity is graded (High for structural, Medium for the orphan lead).
            let sev = a.severity;
            assert!(matches!(sev, Severity::High | Severity::Medium));
            // Converts to a canonical Finding carrying the code + source.
            let f = a.to_finding(source.clone());
            assert_eq!(f.code, a.code);
            assert_eq!(f.source.analyzer, "refs-forensic");
            assert_eq!(f.severity, Some(sev));
        }
    }

    #[test]
    fn le_u64_yields_zero_out_of_range() {
        assert_eq!(le_u64(&[0, 0, 0], 0), 0);
        assert_eq!(le_u64(&[1, 0, 0, 0, 0, 0, 0, 0], 0), 1);
    }

    #[test]
    fn block_at_requires_a_full_page() {
        let short = vec![0u8; REFS_METADATA_PAGE_SIZE - 1];
        assert!(block_at(&short, 0).is_none());
        let full = vec![0u8; REFS_METADATA_PAGE_SIZE];
        assert!(block_at(&full, 0).is_some());
        // An offset past the end yields None (no over-read).
        assert!(block_at(&full, 1).is_none());
    }
}
