//! ReFS v3 container table — the virtual → physical block map.
//!
//! # The problem this solves
//!
//! In ReFS v3.x the object table names each object's tree-root as a **virtual
//! block number**, not a physical location. P2 hit this wall: object `0x600`
//! (the root directory) resolved to a virtual block whose physical page could
//! not be reached. This module builds the container table and translates.
//!
//! # Layout (reverse-engineered — libyal `libfsrefs` §8 "Container tree" + a
//! real v3.14 volume, byte-verified 2026-07-15; see tests/data/README.md)
//!
//! A ReFS **container (band)** is a fixed run of clusters. Its size in clusters
//! is `band_size / cluster_size` — on the v3.14 oracle
//! `67_108_864 / 4096 = 16_384` clusters (the boot sector's "Container (or
//! band) size" at offset 64). A **virtual block number** decomposes as:
//!
//! ```text
//! container_index    = vblock / band_clusters
//! offset_in_container = vblock % band_clusters
//! ```
//!
//! The **container tree** is a Minstore B+-tree ([`crate::MinstorePage`]) of
//! **160-byte container records**:
//!
//! ```text
//! key   +0   8  band identifier (u64)
//! value +0   8  band (container) identifier
//!       +144 8  cluster block number  (the physical LCN — the band's base)
//!       +152 8  cluster count         (= band_clusters, the band size)
//! ```
//!
//! Resolving a virtual block:
//!
//! ```text
//! physical_cluster = container_base[container_index] + offset_in_container
//! physical_offset  = physical_cluster * cluster_size
//! ```
//!
//! # The base map (bootstrap, evidence-based — not hardcoded)
//!
//! `container_base` maps a *virtual* container index to its *physical* base
//! cluster. On the real volume the container tree's `band_id` is the *physical*
//! band, and the virtual-container-index→band mapping is many-to-one (two
//! virtual indices can share one physical band), so it needs the container
//! *index* tree — a further table not always resident. This crate therefore
//! bootstraps the base map from **physically resident metadata**: every
//! resident Minstore page carries its own (self) block number at header offset
//! `0x20`, and its physical cluster is where it sits, so
//! `base[self / band_clusters] = phys_cluster - (self % band_clusters)`. This is
//! ground truth (verified: `self % band_clusters == phys_cluster - LCN` holds on
//! every resident page), needs no undocumented indirection, and resolves the
//! real `0x600` root-directory block. A virtual block whose container index was
//! never witnessed in the resident metadata is **unresolved** and fails loud
//! (never a wrong physical offset) — the bootstrap-failure-≠-empty standard.
//!
//! # Robustness
//!
//! The container tree is parsed through the bounds-checked [`crate::MinstorePage`]
//! layer (a lying record count/offset yields only in-bounds rows). Every field
//! read uses the saturating LE helpers; an out-of-range container-record field
//! yields `0`/`None`, never a panic. The base map is capped by the image's own
//! cluster count.

use crate::bytes::le_u64;
use crate::error::RefsError;
use crate::metablock::REFS_METADATA_PAGE_SIZE;
use crate::minstore::MinstorePage;

/// ReFS cluster size in bytes (4 KiB — verified on the v3.14 oracle). Four
/// clusters make one 16 KiB metadata page.
const CLUSTER_SIZE: u64 = 4096;

/// Offset of the physical cluster block number (LCN) within a 160-byte
/// container record value (`libfsrefs` §8.1.2).
const CONTAINER_LCN_OFFSET: usize = 144;

/// Offset of the cluster count (band size in clusters) within a container
/// record value.
const CONTAINER_CLUSTER_COUNT_OFFSET: usize = 152;

/// Minimum length of a container record value (`libfsrefs` §8.1.2: 160 bytes).
const CONTAINER_RECORD_VALUE_LEN: usize = 160;

/// Decompose a ReFS virtual block number into `(container_index,
/// offset_in_container)` given the band size in clusters.
///
/// `container_index = vblock / band_clusters`,
/// `offset_in_container = vblock % band_clusters`. A `band_clusters` of `0`
/// (a malformed boot sector) yields `(vblock, 0)` rather than dividing by zero
/// (the Paranoid Gatekeeper standard — no panic on hostile input).
#[must_use]
pub fn decompose_virtual_block(vblock: u64, band_clusters: u64) -> (u64, u64) {
    if band_clusters == 0 {
        return (vblock, 0);
    }
    (vblock / band_clusters, vblock % band_clusters)
}

/// One parsed container record: a band's identifier and its physical placement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerRecord {
    /// The band (container) identifier — the container-tree key.
    pub band_id: u64,
    /// The physical base cluster of this band (its cluster block number / LCN).
    pub physical_lcn: u64,
    /// The band size in clusters (the record's cluster count).
    pub cluster_count: u64,
}

/// The ReFS container tree: a Minstore B+-tree of 160-byte container records
/// mapping each band to its physical cluster block number (`libfsrefs` §8).
#[derive(Debug)]
#[non_exhaustive]
pub struct ContainerTable<'a> {
    node: MinstorePage<'a>,
}

impl<'a> ContainerTable<'a> {
    /// Parse a container-tree page (a Minstore B+-tree node).
    ///
    /// # Errors
    ///
    /// Any error from [`MinstorePage::parse`] (a page too short to hold the
    /// node header).
    pub fn parse(data: &'a [u8], offset: u64) -> Result<Self, RefsError> {
        Ok(Self {
            node: MinstorePage::parse(data, offset)?,
        })
    }

    /// Iterate the parsed container records (skipping any row whose value is
    /// shorter than the 160-byte container record — never over-reads).
    pub fn records(&self) -> impl Iterator<Item = ContainerRecord> + '_ {
        self.node.rows().filter_map(|row| {
            // A container record value is 160 bytes; a shorter value is not a
            // container record (the container tree shares the page format with
            // other Minstore trees), so skip it rather than read past it.
            if row.value.len() < CONTAINER_RECORD_VALUE_LEN {
                return None;
            }
            let band_id = le_u64(row.value, 0);
            let physical_lcn = le_u64(row.value, CONTAINER_LCN_OFFSET);
            let cluster_count = le_u64(row.value, CONTAINER_CLUSTER_COUNT_OFFSET);
            Some(ContainerRecord {
                band_id,
                physical_lcn,
                cluster_count,
            })
        })
    }

    /// The physical base cluster (LCN) of `band_id`, or `None` if the band is
    /// absent from this leaf.
    #[must_use]
    pub fn physical_base(&self, band_id: u64) -> Option<u64> {
        self.records()
            .find(|r| r.band_id == band_id)
            .map(|r| r.physical_lcn)
    }

    /// The cluster count (band size) of `band_id`, or `None` if absent.
    #[must_use]
    pub fn cluster_count(&self, band_id: u64) -> Option<u64> {
        self.records()
            .find(|r| r.band_id == band_id)
            .map(|r| r.cluster_count)
    }
}

/// A virtual → physical block resolver built from the physically resident
/// metadata of a ReFS image.
///
/// Each resident Minstore page's self-block-number (header offset `0x20`) is
/// ground truth for its container's physical base; scanning them yields a
/// `container_index → physical_base_cluster` map. Resolving a virtual block then
/// decomposes it and applies the base. See the module docs for why this
/// evidence-based bootstrap is used rather than the (many-to-one, index-tree
/// dependent) container-tree band enumeration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ContainerResolver {
    /// Band size in clusters (`band_size / cluster_size`).
    band_clusters: u64,
    /// `container_index → physical_base_cluster`, derived from resident pages.
    base: Vec<(u64, u64)>,
}

/// The ReFS metadata-block signature every resident metadata page starts with
/// (superblock/checkpoint use their own; Minstore pages use `MSB+`). The
/// resident base map is bootstrapped from `MSB+` pages, whose self-block-number
/// at header offset `0x20` is the virtual block the page answers to.
const MSB_SIGNATURE: &[u8; 4] = b"MSB+";

/// Header offset of a metadata page's self (first) block number.
const SELF_BLOCK_OFFSET: usize = 0x20;

impl ContainerResolver {
    /// Build a resolver by scanning `image` for physically resident Minstore
    /// pages and recording each container's physical base from the pages'
    /// self-block-numbers.
    ///
    /// `band_clusters` is the band size in clusters
    /// (`boot.container_size / cluster_size`; `16_384` on the v3.14 oracle).
    #[must_use]
    pub fn from_resident_image(image: &[u8], band_clusters: u64) -> Self {
        let mut base: Vec<(u64, u64)> = Vec::new();
        if band_clusters == 0 {
            return Self {
                band_clusters,
                base,
            };
        }
        let cluster = CLUSTER_SIZE as usize;
        // Metadata pages sit on cluster boundaries; step by cluster and inspect
        // any page carrying the Minstore signature.
        let clusters = image.len() / cluster;
        for c in 0..clusters {
            let off = c * cluster;
            // Need the full page in bounds to trust its self-block-number.
            if off + REFS_METADATA_PAGE_SIZE > image.len() {
                break;
            }
            if &image[off..off + 4] != MSB_SIGNATURE {
                continue;
            }
            let self_block = le_u64(image, off + SELF_BLOCK_OFFSET);
            let (idx, off_in_band) = decompose_virtual_block(self_block, band_clusters);
            // The physical base cluster this virtual container maps to.
            let phys_cluster = c as u64;
            // A (hostile) page whose offset-in-band exceeds its physical
            // cluster is inconsistent — skip it rather than record a wrong base
            // (a wrong base would mis-resolve every block in that container).
            let Some(band_base) = phys_cluster.checked_sub(off_in_band) else {
                continue;
            };
            if !base.iter().any(|&(i, _)| i == idx) {
                base.push((idx, band_base));
            }
        }
        Self {
            band_clusters,
            base,
        }
    }

    /// The physical base cluster mapped to virtual container `index`, or `None`.
    #[must_use]
    fn base_of(&self, index: u64) -> Option<u64> {
        self.base
            .iter()
            .find(|&&(i, _)| i == index)
            .map(|&(_, b)| b)
    }

    /// Resolve a virtual block number to a physical byte offset, or `None` if
    /// its container index was never witnessed in the resident metadata (an
    /// unresolved virtual address — the caller must treat this as a hard wall,
    /// not an empty result).
    #[must_use]
    pub fn resolve_virtual(&self, vblock: u64) -> Option<u64> {
        let (idx, off) = decompose_virtual_block(vblock, self.band_clusters);
        let base = self.base_of(idx)?;
        let cluster = base.checked_add(off)?;
        cluster.checked_mul(CLUSTER_SIZE)
    }

    /// Resolve a virtual block number, failing loud with the offending block
    /// number when it cannot be mapped (rather than a silent `None`).
    ///
    /// # Errors
    ///
    /// [`RefsError::UnresolvedVirtualBlock`] naming `vblock` when its container
    /// index has no resident base mapping (or the computed offset overflows).
    pub fn resolve_virtual_checked(&self, vblock: u64) -> Result<u64, RefsError> {
        self.resolve_virtual(vblock)
            .ok_or(RefsError::UnresolvedVirtualBlock { block: vblock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_zero_band_clusters_never_divides_by_zero() {
        // A malformed boot sector reporting a zero band size must not panic; the
        // virtual block passes through as `(vblock, 0)` (no division).
        assert_eq!(decompose_virtual_block(80_384, 0), (80_384, 0));
    }

    #[test]
    fn resolver_zero_band_clusters_is_empty_and_resolves_nothing() {
        // A zero band size yields an empty resolver (no base entries), and every
        // resolution then fails loud rather than dividing by zero.
        let image = vec![0u8; 64 * 4096];
        let resolver = ContainerResolver::from_resident_image(&image, 0);
        assert!(resolver.resolve_virtual(80_384).is_none());
        assert!(matches!(
            resolver.resolve_virtual_checked(80_384),
            Err(RefsError::UnresolvedVirtualBlock { block: 80_384 })
        ));
    }

    #[test]
    fn container_records_skip_short_values() {
        // A Minstore page whose rows carry values shorter than a 160-byte
        // container record must yield NO container records (the container tree
        // shares the page format with other trees) — never an over-read.
        //
        // Build a minimal valid Minstore page with one 16-byte-value row.
        let page = build_short_value_page();
        let ct = ContainerTable::parse(&page, 0).expect("parses");
        assert_eq!(
            ct.records().count(),
            0,
            "short-value rows are not container records"
        );
        assert_eq!(ct.physical_base(1), None);
        assert_eq!(ct.cluster_count(1), None);
    }

    #[test]
    fn resolver_skips_inconsistent_page_whose_offset_exceeds_its_cluster() {
        // A hostile page carrying the MSB+ signature at cluster 0 but a
        // self-block-number with a nonzero offset-in-band (offset 5 > cluster 0)
        // is inconsistent — it must be SKIPPED, never used to record a wrong
        // base. Here the only such page sits at cluster 0, so no base is learned
        // and every resolution then fails loud (rather than a wrong offset).
        const CLUSTER: usize = 4096;
        let band_clusters = 16_384u64;
        let mut image = vec![0u8; 64 * CLUSTER];
        // Page at cluster 0: MSB+ with self-block 5 → container 0, offset 5,
        // but phys cluster 0 < 5 → checked_sub underflows → skip.
        image[0..4].copy_from_slice(b"MSB+");
        image[0x20..0x28].copy_from_slice(&5u64.to_le_bytes());
        let resolver = ContainerResolver::from_resident_image(&image, band_clusters);
        // Container 0 was NOT learned (the inconsistent page was skipped).
        assert!(
            resolver.resolve_virtual(5).is_none(),
            "an inconsistent page must not seed a base map entry"
        );
    }

    /// A minimal Minstore leaf page with a single row whose value is 16 bytes
    /// (shorter than a 160-byte container record), mirroring the verified P1
    /// page layout.
    fn build_short_value_page() -> Vec<u8> {
        const PAGE: usize = REFS_METADATA_PAGE_SIZE;
        let mut page = vec![0u8; PAGE];
        page[0..4].copy_from_slice(b"MSB+");
        let node_hdr = 0x100usize;
        let nho_field = 0x50usize;
        page[nho_field..nho_field + 4]
            .copy_from_slice(&((node_hdr - nho_field) as u32).to_le_bytes());
        let rec = node_hdr + 32;
        let key = vec![0u8; 8];
        let value = vec![0u8; 16];
        let key_off = 16u16;
        let val_off = key_off + key.len() as u16;
        let rec_size = (val_off as usize + value.len()) as u32;
        page[rec..rec + 4].copy_from_slice(&rec_size.to_le_bytes());
        page[rec + 4..rec + 6].copy_from_slice(&key_off.to_le_bytes());
        page[rec + 6..rec + 8].copy_from_slice(&(key.len() as u16).to_le_bytes());
        page[rec + 8..rec + 10].copy_from_slice(&0u16.to_le_bytes());
        page[rec + 10..rec + 12].copy_from_slice(&val_off.to_le_bytes());
        page[rec + 12..rec + 14].copy_from_slice(&(value.len() as u16).to_le_bytes());
        page[rec + key_off as usize..rec + key_off as usize + key.len()].copy_from_slice(&key);
        page[rec + val_off as usize..rec + val_off as usize + value.len()].copy_from_slice(&value);
        let roff_start_abs = node_hdr + 0x2000;
        page[roff_start_abs..roff_start_abs + 4]
            .copy_from_slice(&(0xffff_0000u32 | ((rec - node_hdr) as u32 & 0xffff)).to_le_bytes());
        let nh = node_hdr;
        page[nh + 16..nh + 20].copy_from_slice(&((roff_start_abs - node_hdr) as u32).to_le_bytes());
        page[nh + 20..nh + 24].copy_from_slice(&1u32.to_le_bytes());
        page
    }
}
