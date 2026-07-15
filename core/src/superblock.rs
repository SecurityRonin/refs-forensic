//! ReFS superblock (`SUPB`) — the level-0 metadata block, and the generic
//! self-describing metadata-block header it shares with every v3 metadata block.
//!
//! ReFS stores metadata in fixed-size self-describing blocks. The block header
//! (verified against a real ReFS v3.14 volume — see tests/data/README.md, and
//! consistent with libyal `libfsrefs`) begins with a four-byte block signature,
//! and records its own block number at offset `0x20`:
//!
//! ```text
//! off  size  field                              (SUPB @ cluster 30)
//!   0    4   block signature "SUPB"/"CHKP"/"MSB+"
//!   4    4   header version/kind                 (2)
//!   c    4   metadata checksum (CRC64 low word)
//!  20    8   self-describing block number        (== 30 for this superblock)
//! ```
//!
//! P0 locates the superblock at the fixed cluster [`REFS_SUPERBLOCK_CLUSTER`],
//! validates its `SUPB` signature (fail-loud with the offending bytes), and
//! exposes the self-describing block number. Resolving the checkpoint (`CHKP`)
//! reference and walking the Minstore B+-tree are later phases: the v3 SUPB
//! internal layout beyond the header is not reliably documented in the
//! reverse-engineered references, so P0 does not guess at it.

use crate::bytes::{ascii, le_u64};
use crate::error::RefsError;

/// The `SUPB` block signature for the ReFS superblock (metadata level 0).
pub const SUPB_SIGNATURE: &[u8; 4] = b"SUPB";

/// The fixed cluster at which the primary ReFS superblock lives, counted from
/// the start of the volume. `30` is the well-known reverse-engineered
/// convention (byte offset `30 * cluster_size`; `0x1e000` at a 4096-byte
/// cluster), confirmed on the minted v3.14 volume.
pub const REFS_SUPERBLOCK_CLUSTER: u64 = 30;

/// Offset of the self-describing block number within a v3 metadata-block header.
const BLOCK_NUMBER_OFFSET: usize = 0x20;

/// Minimum bytes of a metadata-block header this parser reads (through the
/// self-describing block number at `0x20`, +8 = 40).
const BLOCK_HEADER_MIN_LEN: usize = 40;

/// A ReFS v3 self-describing metadata-block header: the four-byte block
/// signature plus the block's own block number.
///
/// `#[non_exhaustive]` so later phases add the checksum descriptor and the four
/// redundancy block numbers without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetadataBlockRef {
    /// The four-byte block signature (`SUPB`/`CHKP`/`MSB+`), validated against
    /// the caller's `expected` signature.
    pub signature: [u8; 4],
    /// The block's own (self-describing) block number, at header offset `0x20`.
    pub block_number: u64,
}

impl MetadataBlockRef {
    /// Parse and validate a metadata-block header at the start of `data`.
    ///
    /// `expected` is the signature the caller requires (e.g. `"SUPB"`); `offset`
    /// is the block's absolute byte position in the image, carried into the
    /// error so a mismatch names *what* was there and *where*.
    ///
    /// # Errors
    ///
    /// - [`RefsError::BadBlockSignature`] if the first four bytes are not
    ///   `expected` — the offending bytes and offset are carried in the error.
    /// - [`RefsError::Truncated`] if `data` is shorter than the header fields.
    pub fn parse(data: &[u8], expected: &'static str, offset: u64) -> Result<Self, RefsError> {
        // Validate the signature before length so a wrong-block error names the
        // offending bytes even on a short buffer (fail loud with the value).
        let mut signature = [0u8; 4];
        if let Some(s) = data.get(0..4) {
            signature.copy_from_slice(s);
        }
        if signature.as_slice() != expected.as_bytes() {
            return Err(RefsError::BadBlockSignature {
                found: signature,
                found_ascii: ascii(&signature),
                expected,
                offset,
            });
        }

        if data.len() < BLOCK_HEADER_MIN_LEN {
            return Err(RefsError::Truncated {
                structure: "metadata-block header",
                need: BLOCK_HEADER_MIN_LEN,
                have: data.len(),
            });
        }

        Ok(Self {
            signature,
            block_number: le_u64(data, BLOCK_NUMBER_OFFSET),
        })
    }
}

/// The parsed ReFS superblock (`SUPB`, metadata level 0).
///
/// P0 carries only the self-describing block header; the checkpoint reference
/// and the object/container-table pointers it holds are decoded in later phases.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// The self-describing metadata-block header (`SUPB`).
    pub block: MetadataBlockRef,
}

impl Superblock {
    /// Parse the superblock at byte `offset` in a whole-image buffer `data`.
    ///
    /// Slices from `offset` and validates the `SUPB` block header. The caller
    /// obtains `offset` from [`crate::BootSector::superblock_offset`].
    ///
    /// # Errors
    ///
    /// - [`RefsError::Truncated`] if `offset` lies past the end of `data`.
    /// - Any error from [`MetadataBlockRef::parse`] (bad signature, short
    ///   header).
    pub fn parse_at(data: &[u8], offset: u64) -> Result<Self, RefsError> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let slice = data.get(start..).ok_or(RefsError::Truncated {
            structure: "superblock (image slice)",
            need: start,
            have: data.len(),
        })?;
        let block = MetadataBlockRef::parse(slice, "SUPB", offset)?;
        Ok(Self { block })
    }
}
