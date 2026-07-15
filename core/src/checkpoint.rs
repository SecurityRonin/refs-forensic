//! ReFS checkpoint (`CHKP`) — the level-1 metadata block the superblock points
//! at, which in turn carries the pointers to the system tables (object table,
//! allocator/container tables).
//!
//! # The superblock → checkpoint chain
//!
//! The superblock (`SUPB`, level 0) sits at a fixed cluster and holds, after its
//! 80-byte metadata-block header, a 48-byte superblock structure whose
//! **checkpoint references data** names the checkpoint block(s). Byte-verified
//! against the real v3.14 volume:
//!
//! ```text
//! block+0x50   superblock struct (48 bytes):
//!   +0x20  4  checkpoint references data offset (relative to the block)
//!   +0x24  4  number of checkpoint block numbers
//!   +0x28  4  self reference data offset
//!   +0x2c  4  self reference data size
//! checkpoint references data @ block+<offset>: number-of-entries × u64
//! ```
//!
//! On the real minted volume the two checkpoint block numbers are
//! `[157156, 1885500]` — **virtual addresses** (they lie far beyond the
//! physical partition, which is sparse). Resolving a virtual block number to a
//! physical one requires the container table (a later phase); parsing the CHKP
//! block itself and extracting the object-table pointer is likewise deferred to
//! a later phase because the checkpoint block was not physically resident in the
//! available oracle slice. P1 provides the located checkpoint block numbers so
//! that resolution has an anchor.

use crate::bytes::le_u32;
use crate::bytes::le_u64;
use crate::error::RefsError;

/// Length of the v3 metadata-block header preceding the superblock struct.
const V3_HEADER_LEN: usize = 80;

/// Offset of the superblock's "checkpoint references data offset" field, within
/// the superblock struct (which starts at `block + 0x50`).
const CHECKPOINT_REFS_OFFSET_FIELD: usize = V3_HEADER_LEN + 0x20;

/// Offset of the superblock's "number of checkpoint block numbers" field.
const CHECKPOINT_COUNT_FIELD: usize = V3_HEADER_LEN + 0x24;

/// A hard cap on the checkpoint-block-number count: even a maximal ReFS keeps a
/// tiny handful of checkpoints; a count beyond this is a hostile lie and is
/// clamped so a malformed superblock cannot drive an unbounded read.
const MAX_CHECKPOINTS: usize = 64;

/// The ReFS checkpoint.
///
/// P1 exposes the checkpoint *locations* named by the superblock; parsing the
/// `CHKP` block body (system-table pointers) is a later phase (the checkpoint
/// block is not physically resident in the current oracle slice).
#[derive(Debug)]
#[non_exhaustive]
pub struct Checkpoint;

impl Checkpoint {
    /// Return the checkpoint block numbers named by a superblock metadata block.
    ///
    /// `superblock` is the whole superblock page (starting at the `SUPB`
    /// signature). The checkpoint references data offset is relative to the
    /// start of the block.
    ///
    /// # Errors
    ///
    /// [`RefsError::Truncated`] if the buffer is too short to hold the
    /// checkpoint-references offset/count fields, or the referenced checkpoint
    /// references data.
    pub fn locations_from_superblock(superblock: &[u8]) -> Result<Vec<u64>, RefsError> {
        if superblock.len() < CHECKPOINT_COUNT_FIELD + 4 {
            return Err(RefsError::Truncated {
                structure: "superblock checkpoint-references header",
                need: CHECKPOINT_COUNT_FIELD + 4,
                have: superblock.len(),
            });
        }
        let refs_off = le_u32(superblock, CHECKPOINT_REFS_OFFSET_FIELD) as usize;
        let count = (le_u32(superblock, CHECKPOINT_COUNT_FIELD) as usize).min(MAX_CHECKPOINTS);

        // The checkpoint references data must lie fully within the buffer.
        let need = refs_off
            .checked_add(count.checked_mul(8).ok_or(RefsError::Truncated {
                structure: "checkpoint references data (count overflow)",
                need: usize::MAX,
                have: superblock.len(),
            })?)
            .ok_or(RefsError::Truncated {
                structure: "checkpoint references data (offset overflow)",
                need: usize::MAX,
                have: superblock.len(),
            })?;
        if need > superblock.len() {
            return Err(RefsError::Truncated {
                structure: "checkpoint references data",
                need,
                have: superblock.len(),
            });
        }

        Ok((0..count)
            .map(|i| le_u64(superblock, refs_off + i * 8))
            .collect())
    }
}
