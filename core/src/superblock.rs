//! ReFS superblock (`SUPB`) metadata block. (RED stub — see boot.rs test.)

use crate::error::RefsError;

/// The `SUPB` block signature for the ReFS superblock (metadata level 0).
pub const SUPB_SIGNATURE: &[u8; 4] = b"SUPB";

/// The fixed cluster at which the primary ReFS superblock lives. (RED stub.)
pub const REFS_SUPERBLOCK_CLUSTER: u64 = 0;

/// A ReFS v3 metadata block reference / self-describing block header. (RED stub.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetadataBlockRef {
    /// The four-byte block signature (`SUPB`/`CHKP`/`MSB+`).
    pub signature: [u8; 4],
    /// The block's own (first) block number — self-describing.
    pub block_number: u64,
}

impl MetadataBlockRef {
    /// Parse a metadata block header at `offset` in `data`. (RED stub.)
    pub fn parse(_data: &[u8], _expected: &'static str, _offset: u64) -> Result<Self, RefsError> {
        Err(RefsError::Truncated {
            structure: "metadata-block (stub)",
            need: 0,
            have: 0,
        })
    }
}

/// The parsed ReFS superblock. (RED stub.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// The self-describing metadata-block header.
    pub block: MetadataBlockRef,
}

impl Superblock {
    /// Parse the superblock at byte `offset` in `data`. (RED stub.)
    pub fn parse_at(_data: &[u8], _offset: u64) -> Result<Self, RefsError> {
        Err(RefsError::Truncated {
            structure: "superblock (stub)",
            need: 0,
            have: 0,
        })
    }
}
