//! ReFS Minstore B+-tree page — the generic key→value index page every ReFS
//! table (object table, directories, allocators, schema) is built from — and
//! the object table that sits on top of it.
//!
//! Layout byte-verified against a real ReFS v3.14 volume and consistent with
//! libyal `libfsrefs`. After the 80-byte metadata-block header
//! ([`crate::MetaBlock`]) a Minstore page carries:
//!
//! ```text
//! block+0x50  4   node header offset (relative to THIS field) -> node header
//!  [optional 36-byte tree header + header data]
//!  Node header (32 bytes):
//!    0  4  data area start offset (relative to node header)
//!    4  4  data area end offset
//!    8  4  unused data size
//!    c  1  node level (0 = leaf)
//!    d  1  node type flags (0x01 branch/inner, 0x02 root, 0x04 stream)
//!    e  2  unknown
//!   10  4  record offsets start (relative to node header)
//!   14  4  number of record offsets
//!   18  4  record offsets end
//!  Record offsets: u32 each; the UPPER 16 bits are 0xffff in v3, the LOWER 16
//!    bits are the record offset relative to the node header.
//!  Node record (variable):
//!    0  4  record size (includes these 4 bytes)
//!    4  2  key data offset (relative to record)
//!    6  2  key data size
//!    8  2  flags (0x08 = value holds an embedded Minstore node)
//!    a  2  value data offset (relative to record)
//!    c  2  value data size
//! ```
//!
//! # Robustness
//!
//! A hostile page can lie about the record count, a record offset, or a
//! key/value offset/size. Every read is bounds-checked: a record whose offset
//! or key/value span falls outside the page is skipped, and the record count is
//! capped so a lying count cannot spin an unbounded loop or over-read (the
//! Paranoid Gatekeeper standard).

use crate::bytes::{le_u16, le_u32, le_u64};
use crate::error::RefsError;
use crate::metablock::REFS_METADATA_PAGE_SIZE;

/// The well-known ReFS root-directory object identifier (`REFS_ROOT_DIRECTORY_ID`
/// in libyal `libfsrefs`). Later phases resolve this through the object table to
/// reach the file tree.
pub const REFS_ROOT_DIRECTORY_ID: u64 = 0x0000_0600;

/// Offset of the node-header-offset field within a Minstore page (immediately
/// after the 80-byte metadata-block header).
const NODE_HEADER_OFFSET_FIELD: usize = 0x50;

/// Length of the Minstore node header.
const NODE_HEADER_LEN: usize = 32;

/// Absolute cap on record-offset entries, independent of the page's claimed
/// count: a page holds at most one 4-byte offset per possible record slot, so a
/// count beyond the page's own byte capacity is a lie. This caps allocation and
/// iteration regardless of the header's `number of record offsets`.
const MAX_RECORDS: usize = REFS_METADATA_PAGE_SIZE / 4;

/// One `(key, value)` Minstore node record, borrowing from the page buffer.
#[derive(Debug)]
#[non_exhaustive]
pub struct MinstoreRow<'a> {
    /// The record's key bytes.
    pub key: &'a [u8],
    /// The record's value bytes.
    pub value: &'a [u8],
    /// The record's flags word (`0x08` = value holds an embedded Minstore node).
    pub flags: u16,
}

/// A parsed Minstore B+-tree page (leaf or internal/branch node).
#[derive(Debug)]
#[non_exhaustive]
pub struct MinstorePage<'a> {
    /// The page bytes (a single 16 KiB metadata page).
    page: &'a [u8],
    /// Absolute offset of the node header within `page`.
    node_header: usize,
    /// Node level (`0` = leaf).
    level: u8,
    /// Node type flags (`0x01` = branch/inner, `0x02` = root, `0x04` = stream).
    flags: u8,
    /// Absolute offset of the record-offset array within `page`.
    record_offsets: usize,
    /// Number of record offsets, already clamped to what the page can hold.
    record_count: usize,
}

impl<'a> MinstorePage<'a> {
    /// Parse the Minstore node in `data` (a metadata page). `offset` is the
    /// page's absolute byte position, used only for diagnostics.
    ///
    /// # Errors
    ///
    /// - [`RefsError::Truncated`] if the page is too short to hold the
    ///   node-header-offset field or the node header it points at.
    pub fn parse(data: &'a [u8], offset: u64) -> Result<Self, RefsError> {
        let _ = offset;
        if data.len() < NODE_HEADER_OFFSET_FIELD + 4 {
            return Err(RefsError::Truncated {
                structure: "Minstore node-header-offset field",
                need: NODE_HEADER_OFFSET_FIELD + 4,
                have: data.len(),
            });
        }
        // The node-header-offset value is relative to the start of its own
        // field. Use a saturating/bounds-checked resolution so a hostile value
        // can never index out of the page.
        let rel = le_u32(data, NODE_HEADER_OFFSET_FIELD) as usize;
        let node_header = NODE_HEADER_OFFSET_FIELD.saturating_add(rel);
        if node_header
            .checked_add(NODE_HEADER_LEN)
            .is_none_or(|end| end > data.len())
        {
            return Err(RefsError::Truncated {
                structure: "Minstore node header",
                need: node_header.saturating_add(NODE_HEADER_LEN),
                have: data.len(),
            });
        }

        let level = data.get(node_header + 12).copied().unwrap_or(0);
        let flags = data.get(node_header + 13).copied().unwrap_or(0);
        let roff_rel = le_u32(data, node_header + 16) as usize;
        let claimed = le_u32(data, node_header + 20) as usize;
        let record_offsets = node_header.saturating_add(roff_rel);

        // Clamp the record count to what actually fits between the offset array
        // start and the end of the page — a lying count then yields only the
        // offsets the page can physically hold (never an over-read).
        let capacity = data.len().saturating_sub(record_offsets) / 4;
        let record_count = claimed.min(capacity).min(MAX_RECORDS);

        Ok(Self {
            page: data,
            node_header,
            level,
            flags,
            record_offsets,
            record_count,
        })
    }

    /// The node level (`0` = leaf; higher = internal).
    #[must_use]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// True for a leaf node (level `0` and not a branch).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.level == 0 && !self.is_branch()
    }

    /// True for an internal/branch node (node-type flag `0x01`).
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Iterate the node's `(key, value)` records, skipping any record whose
    /// offset or key/value span lies outside the page (never over-reads).
    pub fn rows(&self) -> impl Iterator<Item = MinstoreRow<'a>> + '_ {
        (0..self.record_count).filter_map(move |i| self.row(i))
    }

    /// Resolve record `i` to a bounds-checked `(key, value)` row, or `None` if
    /// any offset/length lies outside the page.
    fn row(&self, i: usize) -> Option<MinstoreRow<'a>> {
        let off_pos = self.record_offsets.checked_add(i.checked_mul(4)?)?;
        // Record offset: lower 16 bits (upper 16 are 0xffff in v3), relative to
        // the node header.
        let raw = le_u32(self.page, off_pos);
        let rec = self.node_header.checked_add((raw & 0xffff) as usize)?;
        // Need the 14-byte record header in bounds.
        if rec.checked_add(14)? > self.page.len() {
            return None;
        }
        let key_off = le_u16(self.page, rec + 4) as usize;
        let key_len = le_u16(self.page, rec + 6) as usize;
        let flags = le_u16(self.page, rec + 8);
        let val_off = le_u16(self.page, rec + 10) as usize;
        let val_len = le_u16(self.page, rec + 12) as usize;

        let key_start = rec.checked_add(key_off)?;
        let key_end = key_start.checked_add(key_len)?;
        let val_start = rec.checked_add(val_off)?;
        let val_end = val_start.checked_add(val_len)?;
        let key = self.page.get(key_start..key_end)?;
        let value = self.page.get(val_start..val_end)?;
        Some(MinstoreRow { key, value, flags })
    }
}

/// A resolved object-table entry: the metadata block number of an object's tree
/// root.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PageRef {
    /// The object's tree-root metadata block number (a virtual address in v3;
    /// later phases resolve it through the container table before reading).
    pub block_number: u64,
}

/// The ReFS object table: a Minstore B+-tree keyed by object identifier, whose
/// values point at each object's own Minstore tree root.
///
/// The object-record **key** is 16 bytes — `[0..8]` zero, `[8..16]` the object
/// identifier (little-endian). The **value** carries a v3 metadata block
/// reference whose first block number sits at value offset `0x20` (32).
#[derive(Debug)]
#[non_exhaustive]
pub struct ObjectTable<'a> {
    node: MinstorePage<'a>,
}

impl<'a> ObjectTable<'a> {
    /// Object-identifier position within the 16-byte object-record key.
    const KEY_ID_OFFSET: usize = 8;
    /// Offset of the first block number within the object-record value (the
    /// embedded v3 metadata block reference starts at value offset `0x20`).
    const VALUE_BLOCK_REF_OFFSET: usize = 0x20;

    /// Parse an object-table page (a Minstore B+-tree node).
    ///
    /// # Errors
    ///
    /// Any error from [`MinstorePage::parse`].
    pub fn parse(data: &'a [u8], offset: u64) -> Result<Self, RefsError> {
        Ok(Self {
            node: MinstorePage::parse(data, offset)?,
        })
    }

    /// Look up an object identifier, returning the block reference to its tree
    /// root, or `None` if the id is absent (or a matching record is malformed).
    #[must_use]
    pub fn lookup(&self, object_id: u64) -> Option<PageRef> {
        self.node.rows().find_map(|row| {
            // Key: 16 bytes, object id at [8..16].
            let id_bytes = row.key.get(Self::KEY_ID_OFFSET..Self::KEY_ID_OFFSET + 8)?;
            let id = le_u64(id_bytes, 0);
            if id != object_id {
                return None;
            }
            // Value: block reference first block number at value+0x20.
            let block = row
                .value
                .get(Self::VALUE_BLOCK_REF_OFFSET..Self::VALUE_BLOCK_REF_OFFSET + 8)
                .map(|b| le_u64(b, 0))?;
            Some(PageRef {
                block_number: block,
            })
        })
    }
}
