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
//! # Reachability (real v3.14 oracle, Doer-Checker)
//!
//! In ReFS v3.x the object table stores **virtual** block numbers; the physical
//! location of a directory's B+tree page is reached only through container-table
//! virtual→physical translation (a later phase). On the minted oracle the root
//! directory (`0x600`) is behind a virtual block outside the 16 MiB partition
//! head, so [`list_dir`] over the real volume fails loud with
//! [`RefsError::UnresolvedVirtualBlock`] — it never fabricates a listing.
//! [`list_dir`] resolves an id to a *physically resident* page (the low band
//! present in the oracle) and parses it; the virtual band awaits the container
//! table.
//!
//! # Robustness
//!
//! Every field is read through bounds-checked helpers; a lying name length or
//! record offset (handled in the [`MinstorePage`] layer) yields only in-bounds
//! bytes, never an over-read. Filenames decode loss-tolerantly so an unpaired
//! surrogate or an odd trailing byte cannot panic.

use crate::bytes::{le_u16, le_u32, le_u64};
use crate::error::RefsError;
use crate::metablock::REFS_METADATA_PAGE_SIZE;
use crate::minstore::{MinstorePage, ObjectTable, REFS_ROOT_DIRECTORY_ID};

/// Directory record key record type: an **entry** record (name → child).
const RECORD_TYPE_ENTRY: u16 = 0x0030;

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
    for row in node.rows() {
        // Directory record key: +0 u16 record type.
        if le_u16(row.key, 0) != RECORD_TYPE_ENTRY {
            continue;
        }
        // Entry record: +2 entry type, +4.. UTF-16LE name.
        let entry_type = le_u16(row.key, 2);
        let name_bytes = row.key.get(4..).unwrap_or(&[]);
        let name = decode_utf16le(name_bytes);

        let is_directory = entry_type == ENTRY_TYPE_DIRECTORY;
        // Only File / Directory entries carry the metadata this phase models; a
        // type-0 FS-metadata file is listed by name with no metadata.
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

/// Resolve a directory object id to its physically-resident B+tree page bytes.
fn resolve_directory_page(image: &[u8], object_id: u64) -> Result<&[u8], RefsError> {
    let ot = object_table(image)?;
    let page_ref = ot
        .lookup(object_id)
        .ok_or(RefsError::ObjectIdNotFound { object_id })?;
    let off = resident_block_offset(page_ref.block_number, image.len()).ok_or(
        RefsError::UnresolvedVirtualBlock {
            block: page_ref.block_number,
        },
    )?;
    // The whole 16 KiB page is guaranteed in-bounds by resident_block_offset.
    image
        .get(off..off + REFS_METADATA_PAGE_SIZE)
        .ok_or(RefsError::Truncated {
            structure: "directory page",
            need: off + REFS_METADATA_PAGE_SIZE,
            have: image.len(),
        })
}

/// List the entries of the directory with object id `dir_object_id` over a whole
/// ReFS image.
///
/// Resolves `dir_object_id` through the object table to its B+tree root block,
/// translates that block to a physical offset, and parses the directory page.
///
/// # Errors
///
/// - [`RefsError::ObjectIdNotFound`] if the id is absent from the object table.
/// - [`RefsError::UnresolvedVirtualBlock`] if the id's tree-root block is a
///   virtual address outside the resident region (the real-volume situation for
///   `0x600` — resolving it needs the container table, a later phase). This is a
///   loud diagnostic, never a silent empty listing.
/// - [`RefsError::Truncated`] if the image is too small to hold the referenced
///   page or the object table.
pub fn list_dir(image: &[u8], dir_object_id: u64) -> Result<Vec<DirEntry>, RefsError> {
    let page = resolve_directory_page(image, dir_object_id)?;
    parse_directory(page)
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
