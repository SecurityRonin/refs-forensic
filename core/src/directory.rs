//! ReFS directory object — the Ministore B+-tree of directory records that maps
//! names to child files and directories, plus each entry's file/directory
//! metadata (timestamps, size, attribute flags), and image-level path
//! resolution over the object table.
//!
//! # Layout (reverse-engineered — libyal `libfsrefs` "Directory object")
//!
//! A directory is a [`MinstorePage`] whose records are keyed by a **directory
//! record key**:
//!
//! ```text
//! key +0  2  record type: 0x0010 base, 0x0020 name, 0x0030 entry
//! Entry record (0x0030):
//!   +0  2  record type = 0x0030
//!   +2  2  directory entry type: 0 = FS-metadata file, 1 = File, 2 = Directory
//!   +4 ..  name — UTF-16LE, NO end-of-string character (unpaired surrogates
//!          allowed, so it is decoded loss-tolerantly, not as strict UTF-16)
//! ```
//!
//! The entry-record **value** depends on the entry type:
//!
//! ```text
//! Directory values (entry type 2, 72 bytes):
//!   +0   8  directory object identifier
//!   +16  8  creation FILETIME
//!   +24  8  modification (last-written) FILETIME
//!   +32  8  metadata-change FILETIME
//!   +40  8  access FILETIME
//!   +64  4  file attribute flags
//!
//! File values (entry type 1, embedded Ministore node, 128-byte header):
//!   +0   8  creation FILETIME
//!   +8   8  modification (last-written) FILETIME
//!   +16  8  metadata-change FILETIME
//!   +24  8  access FILETIME
//!   +32  4  file attribute flags
//!   +64  8  data size (logical file size)
//!   +72  8  allocated (reserved) data size
//! ```
//!
//! # Directory-tree descent (real v3.14 oracle, Doer-Checker)
//!
//! A directory is a Minstore B+-tree that may be more than one page deep.
//! [`list_dir`] resolves an object id to its tree-root block through the object
//! table, builds a [`ContainerResolver`] from the image's resident metadata, and
//! **descends** the tree: a **branch** node (Minstore node-type flag `0x01`)
//! carries in each row's value a format-v3 metadata block reference whose first
//! block number (value `+0`) is a child page's *virtual* block — resolved
//! virtual→physical and recursed into; a **leaf** node's `0x30` records are the
//! directory entries. Every candidate page offset is validated by a self-block
//! round-trip (the page there must be an `MSB+` page whose self-block equals the
//! requested block) so a wrong-but-in-bounds base is never trusted.
//!
//! When the whole tree is physically resident the real listing is returned (on
//! the v3.14 oracle the descent reads the real `System Volume Information`
//! directory entry). When a child leaf is a non-resident virtual block — the
//! minted user files live in a band beyond the 256 MiB slice — the walk fails
//! loud with that block ([`RefsError::UnresolvedVirtualBlock`]) rather than
//! fabricate or silently truncate the listing.
//!
//! # Robustness
//!
//! Every field is read through bounds-checked helpers; a lying name length or
//! record offset (handled in the [`MinstorePage`] layer) yields only in-bounds
//! bytes, never an over-read. Filenames decode loss-tolerantly so an unpaired
//! surrogate or an odd trailing byte cannot panic.

use crate::bytes::{le_u16, le_u32, le_u64};
use crate::container::ContainerResolver;
use crate::error::RefsError;
use crate::metablock::REFS_METADATA_PAGE_SIZE;
use crate::minstore::{MinstorePage, ObjectTable, REFS_ROOT_DIRECTORY_ID};

/// Directory record key record type: an **entry** record (name → child).
const RECORD_TYPE_ENTRY: u16 = 0x0030;

/// Band size in clusters used to build the [`ContainerResolver`] when the image
/// handed to [`list_dir`] carries no boot sector to read it from (the synthetic
/// test images, and any caller passing a bare partition body). Derived from the
/// documented v3.x layout — band size `67_108_864` / cluster `4096` = `16_384`
/// clusters — and byte-verified on the real v3.14 oracle (see
/// [`crate::ContainerResolver`] docs). A caller with the boot sector can build
/// its own resolver with the exact band size and pass it to [`walk_directory`].
const DEFAULT_BAND_CLUSTERS: u64 = 16_384;

/// Maximum B+tree descent depth. Real directory trees are only a handful of
/// levels deep; this cap makes a lying/cyclic branch chain (a hostile image
/// pointing a node at an ancestor) terminate instead of recursing without
/// bound. Paired with a visited-block set to break cycles at the same physical
/// page (the Paranoid Gatekeeper standard).
const MAX_DESCENT_DEPTH: usize = 64;

/// Maximum number of child pages a single descent will visit, independent of
/// depth — a second bound so a wide fan-out of lying branch rows cannot spin an
/// unbounded walk even within the depth cap.
const MAX_VISITED_PAGES: usize = 4096;

/// Directory entry type for a **File** (has file metadata + data attributes).
const ENTRY_TYPE_FILE: u16 = 1;
/// Directory entry type for a **Directory** (has a child object id).
const ENTRY_TYPE_DIRECTORY: u16 = 2;

/// The largest ReFS metadata block number that maps into the physically
/// resident low band of the minted oracle. Blocks below `RESIDENT_VIRTUAL_BASE`
/// map to `cluster = block`; blocks at/above it map to
/// `cluster = block - RESIDENT_VIRTUAL_BASE` (the second addressing regime seen
/// on the real volume, where cluster 52 carries self-block 65588). Any block
/// that does not land inside the supplied image is an unresolved virtual
/// address (container-table territory).
const RESIDENT_VIRTUAL_BASE: u64 = 65_536;

/// The physical cluster where the object table page sits (the real-volume
/// convention verified in P1: the `MSB+` object tree at cluster 56).
const OBJECT_TABLE_CLUSTER: u64 = 56;

/// ReFS cluster size in bytes (4 KiB — verified on the v3.14 oracle). Four
/// clusters make one 16 KiB metadata page.
const CLUSTER_SIZE: usize = 4096;

/// File/directory metadata carried by a directory entry value.
///
/// FILETIME values are the raw 100-ns-since-1601 `u64` ticks (UTC), preserved
/// verbatim so a machine consumer round-trips them losslessly; higher layers
/// convert to a calendar time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileMetadata {
    /// Logical file size in bytes (`0` for a directory).
    pub size: u64,
    /// Allocated / reserved size in bytes (`0` for a directory).
    pub allocated: u64,
    /// Creation FILETIME.
    pub created: u64,
    /// Last-modification (last-written) FILETIME.
    pub modified: u64,
    /// Last-access FILETIME.
    pub accessed: u64,
    /// Metadata-change (entry last-modification) FILETIME.
    pub changed: u64,
    /// File attribute flags (`0x10` = directory, `0x20` = archive, …).
    pub attributes: u32,
    /// True when this entry is a directory.
    pub is_directory: bool,
}

/// One resolved directory entry: a name, its kind, its metadata, and — for a
/// directory — the child object id to descend into.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name, decoded from UTF-16LE (loss-tolerant: unpaired surrogates
    /// become U+FFFD rather than a parse failure).
    pub name: String,
    /// True when the entry is a directory.
    pub is_directory: bool,
    /// For a directory, the child directory object identifier (resolve through
    /// the object table to reach its own B+tree). `None` for a file — a file's
    /// record is inline in this directory, it has no separate object-table id.
    pub object_id: Option<u64>,
    /// The entry's file/directory metadata (timestamps, size, flags).
    pub metadata: Option<FileMetadata>,
}

/// Decode a UTF-16LE byte run loss-tolerantly (unpaired surrogates → U+FFFD; an
/// odd trailing byte is dropped). ReFS names are "UTF-16 with unpaired
/// surrogates", so strict decoding would reject legitimate names.
fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Parse a directory entry-record value into [`FileMetadata`].
fn parse_metadata(value: &[u8], is_directory: bool) -> FileMetadata {
    if is_directory {
        // Directory value (72 bytes): timestamps @16/24/32/40, attr @64.
        FileMetadata {
            size: 0,
            allocated: 0,
            created: le_u64(value, 16),
            modified: le_u64(value, 24),
            changed: le_u64(value, 32),
            accessed: le_u64(value, 40),
            attributes: le_u32(value, 64),
            is_directory: true,
        }
    } else {
        // File value (128-byte header): timestamps @0/8/16/24, attr @32,
        // size @64, allocated @72.
        FileMetadata {
            size: le_u64(value, 64),
            allocated: le_u64(value, 72),
            created: le_u64(value, 0),
            modified: le_u64(value, 8),
            changed: le_u64(value, 16),
            accessed: le_u64(value, 24),
            attributes: le_u32(value, 32),
            is_directory: false,
        }
    }
}

/// Parse a Ministore directory page into its directory entries.
///
/// Only **entry records** (key record type `0x0030`) become [`DirEntry`]s; base
/// (`0x0010`) and name (`0x0020`) records are skipped (they are not name→child
/// entries). Names decode from UTF-16LE loss-tolerantly.
///
/// # Errors
///
/// - Any error from [`MinstorePage::parse`] (a page too short to hold the node
///   header). A well-formed but empty directory page yields an empty `Vec`.
pub fn parse_directory(page: &[u8]) -> Result<Vec<DirEntry>, RefsError> {
    let node = MinstorePage::parse(page, 0)?;
    let mut out = Vec::new();
    collect_entries(&node, &mut out);
    Ok(out)
}

/// Translate a physically-resident ReFS metadata block number to its byte
/// offset within `image`, or `None` if the block is a virtual address outside
/// the resident region.
///
/// Two resident regimes are observed on the real volume: low blocks
/// (`block < RESIDENT_VIRTUAL_BASE`) map directly to `cluster = block`; blocks
/// in the resident high band map to `cluster = block - RESIDENT_VIRTUAL_BASE`.
/// A resolution is accepted only when the whole 16 KiB page lies inside the
/// image; otherwise the block is treated as unresolved (container-table needed).
fn resident_block_offset(block: u64, image_len: usize) -> Option<usize> {
    let candidates = if block >= RESIDENT_VIRTUAL_BASE {
        // High-band resident mapping, then also allow the low mapping as a
        // fallback (a small image may place a page at a low block number).
        [Some(block - RESIDENT_VIRTUAL_BASE), Some(block)]
    } else {
        [Some(block), None]
    };
    for cluster in candidates.into_iter().flatten() {
        let off = usize::try_from(cluster).ok()?.checked_mul(CLUSTER_SIZE)?;
        if off.checked_add(REFS_METADATA_PAGE_SIZE)? <= image_len {
            return Some(off);
        }
    }
    None
}

/// Read the object table page from `image` (at the verified object-table
/// cluster) and parse it.
fn object_table(image: &[u8]) -> Result<ObjectTable<'_>, RefsError> {
    let off = usize::try_from(OBJECT_TABLE_CLUSTER)
        .ok()
        .and_then(|c| c.checked_mul(CLUSTER_SIZE))
        .ok_or(RefsError::Truncated {
            structure: "object table (offset overflow)",
            need: usize::MAX,
            have: image.len(),
        })?;
    let page = image.get(off..).ok_or(RefsError::Truncated {
        structure: "object table page",
        need: off,
        have: image.len(),
    })?;
    ObjectTable::parse(page, off as u64)
}

/// The `MSB+` Minstore metadata-page signature; a resolved directory page must
/// carry it (and the requested self-block) to be trusted.
const MSB_SIGNATURE: &[u8; 4] = b"MSB+";

/// Header offset of a metadata page's self (first) block number.
const SELF_BLOCK_OFFSET: usize = 0x20;

/// True when the 16 KiB page at `off` is a Minstore page whose self-block-number
/// equals `block` — the round-trip that proves a candidate offset really is the
/// page for `block` (never trusts a base that resolves to the wrong page).
fn page_answers_block(image: &[u8], off: usize, block: u64) -> bool {
    let Some(page) = image.get(off..off + REFS_METADATA_PAGE_SIZE) else {
        return false;
    };
    page.get(0..4) == Some(MSB_SIGNATURE.as_slice()) && le_u64(page, SELF_BLOCK_OFFSET) == block
}

/// Translate a directory-tree block number to its byte offset within `image`,
/// preferring the evidence-based container resolver (the real-volume
/// virtual→physical map) and falling back to the resident heuristic for images
/// that carry no resolvable band metadata (the synthetic low-block placements).
///
/// Every candidate offset is **validated by a self-block round-trip** (the page
/// there must be an `MSB+` page whose self-block-number equals `block`) before it
/// is trusted — so a base that resolves to a *wrong-but-in-bounds* page is
/// rejected and the next strategy is tried, never silently returned (the
/// validate-the-bootstrap-before-trusting-it standard). Returns `None` only when
/// no strategy lands the genuine page for `block` — a genuinely unresolved
/// virtual address (the caller fails loud with the block).
fn resolve_block_offset(image: &[u8], resolver: &ContainerResolver, block: u64) -> Option<usize> {
    // (1) Container resolver — authoritative virtual→physical, when it maps the
    // block AND the resolved page round-trips its self-block. `resolve_virtual`
    // yields a byte offset that already fit the image (a usize-bounded buffer),
    // so `usize::try_from` is infallible in practice; `.ok()` degrades a
    // (64-bit-unreachable) overflow to "not resolvable via this path" rather than
    // panicking, then falls through to the resident heuristic.
    if let Some(off) = resolver
        .resolve_virtual(block)
        .and_then(|o| usize::try_from(o).ok())
    {
        if page_answers_block(image, off, block) {
            return Some(off);
        }
    }
    // (2) Resident heuristic (block==cluster, or block-RESIDENT_VIRTUAL_BASE),
    // likewise accepted only if the page there answers the requested block.
    if let Some(off) = resident_block_offset(block, image.len()) {
        if page_answers_block(image, off, block) {
            return Some(off);
        }
    }
    None
}

/// Read the whole 16 KiB metadata page at directory-tree `block`, or fail loud
/// with the offending block when it cannot be resolved to an in-bounds page.
fn read_page<'a>(
    image: &'a [u8],
    resolver: &ContainerResolver,
    block: u64,
) -> Result<&'a [u8], RefsError> {
    let off = resolve_block_offset(image, resolver, block)
        .ok_or(RefsError::UnresolvedVirtualBlock { block })?;
    image
        .get(off..off + REFS_METADATA_PAGE_SIZE)
        .ok_or(RefsError::Truncated {
            structure: "directory page",
            need: off + REFS_METADATA_PAGE_SIZE,
            have: image.len(),
        })
}

/// Descend the directory B+tree rooted at metadata block `block`, appending
/// every leaf-level directory entry to `out`.
///
/// A **branch** node (Minstore node-type flag `0x01`) carries, in each row's
/// value, a format-v3 metadata block reference whose first block number
/// (value `+0`) is the *virtual* block of a child page — resolved here through
/// the container resolver and recursed into. A **leaf** node's `0x30` records
/// are the directory entries (parsed exactly as [`parse_directory`]).
///
/// Robustness: the walk is bounded by depth ([`MAX_DESCENT_DEPTH`]), by total
/// pages visited ([`MAX_VISITED_PAGES`]), and by a `visited` set that breaks
/// cycles at a repeated physical block — a hostile image (a node pointing at an
/// ancestor, or a fan-out of lying branch rows) terminates without panic or
/// unbounded recursion. An unmapped child block is surfaced loud (never a
/// silently-truncated listing).
fn descend(
    image: &[u8],
    resolver: &ContainerResolver,
    block: u64,
    depth: usize,
    visited: &mut Vec<u64>,
    out: &mut Vec<DirEntry>,
) -> Result<(), RefsError> {
    if depth >= MAX_DESCENT_DEPTH || visited.len() >= MAX_VISITED_PAGES {
        return Ok(());
    }
    if visited.contains(&block) {
        return Ok(());
    }
    visited.push(block);

    let page = read_page(image, resolver, block)?;
    let node = MinstorePage::parse(page, 0)?;

    if node.is_branch() {
        // Branch node: each row's value is a metadata block reference whose first
        // block number (value +0) is a child page's virtual block. Recurse.
        for row in node.rows() {
            let Some(child_bytes) = row.value.get(0..8) else {
                // A branch row too short to hold a block number is malformed (a
                // real branch value is a 48-byte block reference); skip it rather
                // than over-read a lying record the Minstore layer let through.
                continue;
            };
            let child = le_u64(child_bytes, 0);
            descend(image, resolver, child, depth + 1, visited, out)?;
        }
    } else {
        // Leaf node: its 0x30 records are the directory entries.
        collect_entries(&node, out);
    }
    Ok(())
}

/// Append the leaf-level `0x30` directory entries of a parsed Minstore node to
/// `out` (the leaf half of [`parse_directory`], factored so the descent reuses
/// it).
fn collect_entries(node: &MinstorePage<'_>, out: &mut Vec<DirEntry>) {
    for row in node.rows() {
        if le_u16(row.key, 0) != RECORD_TYPE_ENTRY {
            continue;
        }
        let entry_type = le_u16(row.key, 2);
        let name = decode_utf16le(row.key.get(4..).unwrap_or(&[]));
        let is_directory = entry_type == ENTRY_TYPE_DIRECTORY;
        let (object_id, metadata) = match entry_type {
            ENTRY_TYPE_DIRECTORY => (
                Some(le_u64(row.value, 0)),
                Some(parse_metadata(row.value, true)),
            ),
            ENTRY_TYPE_FILE => (None, Some(parse_metadata(row.value, false))),
            _ => (None, None),
        };
        out.push(DirEntry {
            name,
            is_directory,
            object_id,
            metadata,
        });
    }
}

/// List the entries of the directory with object id `dir_object_id` over a whole
/// ReFS image, **walking the directory B+tree** from its root through any branch
/// nodes down to the leaf pages.
///
/// Resolves `dir_object_id` through the object table to its tree-root block,
/// builds a [`ContainerResolver`] from the image's resident metadata, then
/// descends: a branch node's rows point (value `+0`) at child pages resolved
/// virtual→physical and recursed into; a leaf node's `0x30` records are the
/// directory entries. When the whole tree is resident the real listing is
/// returned; when a child leaf is a non-resident virtual block the walk fails
/// loud with that block (never a fabricated or silently-truncated listing).
///
/// # Errors
///
/// - [`RefsError::ObjectIdNotFound`] if the id is absent from the object table.
/// - [`RefsError::UnresolvedVirtualBlock`] if the tree-root — or any child page
///   reached during the descent — is a virtual block that resolves to no
///   in-bounds physical page (a band beyond the supplied image). A loud
///   diagnostic naming the offending block, never a silent empty listing.
/// - [`RefsError::Truncated`] if the image is too small to hold a referenced
///   page or the object table.
pub fn list_dir(image: &[u8], dir_object_id: u64) -> Result<Vec<DirEntry>, RefsError> {
    let ot = object_table(image)?;
    let root_block = ot
        .lookup(dir_object_id)
        .ok_or(RefsError::ObjectIdNotFound {
            object_id: dir_object_id,
        })?
        .block_number;
    walk_directory(image, root_block)
}

/// Walk the directory B+tree rooted at metadata block `root_block` and return
/// its entries, building the container resolver from `image`'s resident
/// metadata. Exposed for a caller that already has the tree-root block (e.g. a
/// forensic walker resolving the root itself) so it need not re-enter through
/// the object table.
///
/// # Errors
///
/// - [`RefsError::UnresolvedVirtualBlock`] if the root or any descended child is
///   a virtual block outside the resident region.
/// - [`RefsError::Truncated`] if a referenced page falls outside the image.
pub fn walk_directory(image: &[u8], root_block: u64) -> Result<Vec<DirEntry>, RefsError> {
    let resolver = ContainerResolver::from_resident_image(image, DEFAULT_BAND_CLUSTERS);
    let mut out = Vec::new();
    let mut visited = Vec::new();
    descend(image, &resolver, root_block, 0, &mut visited, &mut out)?;
    Ok(out)
}

/// Resolve an absolute path (`"/dir/file"`) to `(containing_directory_object_id,
/// FileMetadata)` by descending the directory B+trees from the root (`0x600`).
///
/// Path components are matched by UTF-16-decoded name. Returns `None` if any
/// component is missing, if the final component has no file/directory metadata,
/// or for the bare root path `"/"` (the tree root itself has no entry record).
/// A reachability wall en route (an unresolved virtual block) also yields `None`
/// — the caller that needs to distinguish "absent" from "unreachable" uses
/// [`list_dir`], which surfaces the [`RefsError`].
#[must_use]
pub fn find_by_path(image: &[u8], path: &str) -> Option<(u64, FileMetadata)> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return None; // "/" — the root has no entry record.
    }

    let mut dir_id = REFS_ROOT_DIRECTORY_ID;
    for (i, component) in components.iter().enumerate() {
        let entries = list_dir(image, dir_id).ok()?;
        let entry = entries.into_iter().find(|e| e.name == *component)?;
        let is_last = i + 1 == components.len();
        if is_last {
            return entry.metadata.map(|md| (dir_id, md));
        }
        // Descend into the next directory; a non-directory mid-path fails.
        dir_id = entry.object_id?;
    }
    None // cov:unreachable: components is non-empty (guarded above) so the final loop iteration always has is_last == true and returns at line 330; this fallthrough exists only to satisfy the return type.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid Minstore page carrying only a v3 header with the
    /// given signature and self-block — enough for `page_answers_block` and the
    /// resident-heuristic paths.
    fn header_only_page(signature: [u8; 4], self_block: u64) -> Vec<u8> {
        let mut page = vec![0u8; REFS_METADATA_PAGE_SIZE];
        page[0..4].copy_from_slice(&signature);
        page[SELF_BLOCK_OFFSET..SELF_BLOCK_OFFSET + 8].copy_from_slice(&self_block.to_le_bytes());
        page
    }

    #[test]
    fn page_answers_block_rejects_out_of_bounds_offset() {
        // An offset past the end of the image cannot answer any block (no panic).
        let image = vec![0u8; REFS_METADATA_PAGE_SIZE];
        assert!(!page_answers_block(&image, REFS_METADATA_PAGE_SIZE, 0));
    }

    #[test]
    fn page_answers_block_rejects_wrong_signature_and_wrong_self_block() {
        // Wrong signature at a valid offset → not a Minstore page → false.
        let not_msb = header_only_page(*b"SUPB", 7);
        assert!(!page_answers_block(&not_msb, 0, 7));
        // Right signature but a self-block that does not match the request → false.
        let msb = header_only_page(*b"MSB+", 7);
        assert!(!page_answers_block(&msb, 0, 8));
        // Right signature AND matching self-block → true.
        assert!(page_answers_block(&msb, 0, 7));
    }

    #[test]
    fn resolve_block_offset_uses_resident_heuristic_when_resolver_cannot_map() {
        // Place a Minstore page at cluster 8 (self-block 8) in an image whose only
        // resident page underflows the resolver's base (so the container resolver
        // learns NO base for band 0) — the resident heuristic must then land it.
        let mut image = vec![0u8; 64 * CLUSTER_SIZE];
        let page = header_only_page(*b"MSB+", 8);
        image[8 * CLUSTER_SIZE..8 * CLUSTER_SIZE + REFS_METADATA_PAGE_SIZE].copy_from_slice(&page);
        // A resolver with a zero band size has an empty base map, so
        // resolve_virtual always returns None — forcing the resident-heuristic
        // path (block 8 → cluster 8), which lands the page and round-trips.
        let empty_resolver = ContainerResolver::from_resident_image(&[], 0);
        let off = resolve_block_offset(&image, &empty_resolver, 8);
        assert_eq!(
            off,
            Some(8 * CLUSTER_SIZE),
            "resident heuristic lands block 8"
        );
    }

    #[test]
    fn resolve_block_offset_none_when_no_strategy_answers() {
        // No page anywhere answers block 8 → both strategies reject → None.
        let image = vec![0u8; 64 * CLUSTER_SIZE];
        let empty_resolver = ContainerResolver::from_resident_image(&[], 0);
        assert_eq!(resolve_block_offset(&image, &empty_resolver, 8), None);
    }

    #[test]
    fn descend_branch_row_with_short_value_is_skipped_not_panicked() {
        // A branch node whose row value is shorter than the 8-byte child block
        // number must be skipped (never over-read / panic). Build a branch page at
        // cluster 4 (self-block 4) with one row whose value is 4 bytes.
        let mut page = vec![0u8; REFS_METADATA_PAGE_SIZE];
        page[0..4].copy_from_slice(b"MSB+");
        page[SELF_BLOCK_OFFSET..SELF_BLOCK_OFFSET + 8].copy_from_slice(&4u64.to_le_bytes());
        let node_hdr = 0x100usize;
        page[0x50..0x54].copy_from_slice(&((node_hdr - 0x50) as u32).to_le_bytes());
        let rec = node_hdr + 32;
        let key = [0u8; 4];
        let value = [0u8; 4]; // < 8 bytes → the short-value guard fires
        let key_off = 16u16;
        let val_off = key_off + key.len() as u16;
        let rec_size = (val_off as usize + value.len()) as u32;
        page[rec..rec + 4].copy_from_slice(&rec_size.to_le_bytes());
        page[rec + 4..rec + 6].copy_from_slice(&key_off.to_le_bytes());
        page[rec + 6..rec + 8].copy_from_slice(&(key.len() as u16).to_le_bytes());
        page[rec + 10..rec + 12].copy_from_slice(&val_off.to_le_bytes());
        page[rec + 12..rec + 14].copy_from_slice(&(value.len() as u16).to_le_bytes());
        let roff_abs = node_hdr + 0x2000;
        page[roff_abs..roff_abs + 4]
            .copy_from_slice(&(0xffff_0000u32 | ((rec - node_hdr) as u32 & 0xffff)).to_le_bytes());
        page[node_hdr + 13] = 0x01; // branch
        page[node_hdr + 16..node_hdr + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        page[node_hdr + 20..node_hdr + 24].copy_from_slice(&1u32.to_le_bytes());

        let mut image = vec![0u8; 16 * CLUSTER_SIZE];
        image[4 * CLUSTER_SIZE..4 * CLUSTER_SIZE + REFS_METADATA_PAGE_SIZE].copy_from_slice(&page);
        // block 4 resolves via the resident heuristic (block==cluster); the branch
        // has one short-value row that is skipped, yielding an empty (not panicked)
        // listing.
        let entries =
            walk_directory(&image, 4).expect("walk does not panic on a short branch value");
        assert!(entries.is_empty(), "the short-value branch row was skipped");
    }
}
