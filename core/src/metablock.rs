//! ReFS v3 metadata-block (page) header and its checksum descriptor.
//!
//! Every ReFS metadata block is a self-describing 16 KiB page (four 4096-byte
//! clusters). The page begins with a **format-version-3 metadata block header**
//! (80 bytes), byte-verified against a real ReFS v3.14 volume and consistent
//! with libyal `libfsrefs`:
//!
//! ```text
//! off  size  field
//!   0    4   block signature ("SUPB"/"CHKP"/"MSB+")
//!   4    4   unknown (observed 2)
//!   c    4   volume signature
//!  10    8   virtual allocator clock
//!  18    8   tree update clock
//!  20    8   first block number  (== the block's SELF number)
//!  28    8   second block number  (redundancy copy)
//!  30    8   third block number
//!  38    8   fourth block number
//!  40   16   128-bit table identifier
//! ```
//!
//! # Checksums (CRC-32C and CRC-64/ECMA-182)
//!
//! ReFS protects each metadata block with a checksum recorded in the *metadata
//! block reference* that points to it (a 48-byte structure whose checksum
//! descriptor gives `type` — `1` = CRC-32C, `2` = CRC64-ECMA-182 — plus the
//! stored checksum bytes). This module exposes the two checksum **algorithms**
//! (validated against their published check values) and a range-explicit
//! [`MetaBlock::verify_crc32c`] verifier.
//!
//! **Honest limitation (Tier-2 reverse-engineering).** The exact byte *range*
//! ReFS runs the block checksum over is **not documented** in the
//! reverse-engineered references, and an empirical search over the real v3.14
//! volume did not reproduce the stored value from any obvious contiguous range
//! (starts `{0, 80, 208}` × every end, checksum-field zeroed or not, both CRC
//! init conventions). Rather than guess a range and fabricate a
//! `Some(false)` "corruption" verdict on every clean block (the LZNT1 trap),
//! this crate exposes the checksum *descriptor* and the checksum *algorithms*,
//! and verifies only over a **caller-supplied explicit range** — so a future
//! phase that pins the range (against `libfsrefs`/Prade or a larger corpus) can
//! call [`MetaBlock::verify_crc32c`] with the correct bounds. Automatic
//! whole-block verification stays deliberately absent until the range is
//! confirmed.

use crc::{Crc, CRC_32_ISCSI, CRC_64_ECMA_182};

use crate::bytes::{ascii, le_u64};
use crate::error::RefsError;

/// The ReFS v3 metadata page (block) size in bytes: 16 KiB (four 4096-byte
/// clusters), verified on the real v3.14 volume.
pub const REFS_METADATA_PAGE_SIZE: usize = 16384;

/// Length of the format-version-3 metadata block header.
const V3_HEADER_LEN: usize = 80;

/// Offset of the first (self) block number within the v3 header.
const SELF_BLOCK_NUMBER_OFFSET: usize = 0x20;

/// CRC-32C engine (iSCSI / Castagnoli, polynomial `0x1edc6f41`), the ReFS
/// checksum type `1`.
const CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

/// CRC-64/ECMA-182 engine, the ReFS checksum type `2`.
const CRC64: Crc<u64> = Crc::<u64>::new(&CRC_64_ECMA_182);

/// ReFS metadata-block checksum type `1`: CRC-32C (Castagnoli).
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    CRC32C.checksum(data)
}

/// ReFS metadata-block checksum type `2`: CRC-64/ECMA-182.
#[must_use]
pub fn crc64_ecma(data: &[u8]) -> u64 {
    CRC64.checksum(data)
}

/// A ReFS v3 self-describing metadata-block header.
///
/// Carries the four-byte block signature and the block's own (self) block
/// number. `#[non_exhaustive]` so later phases add the redundancy block numbers,
/// table identifier, and clocks without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetaBlock {
    /// The four-byte block signature (`SUPB`/`CHKP`/`MSB+`), validated against
    /// the caller's `expected` signature.
    pub signature: [u8; 4],
    /// The block's own (self) block number, at header offset `0x20`.
    pub block_number: u64,
}

impl MetaBlock {
    /// Parse and validate a v3 metadata-block header at the start of `data`.
    ///
    /// `expected` is the signature the caller requires (`"SUPB"`, `"CHKP"`, or
    /// `"MSB+"`); `offset` is the block's absolute byte position, carried into
    /// the error so a mismatch names *what* was there and *where* (fail loud
    /// with the value).
    ///
    /// # Errors
    ///
    /// - [`RefsError::BadBlockSignature`] if the first four bytes are not
    ///   `expected`.
    /// - [`RefsError::Truncated`] if `data` is shorter than the 80-byte header.
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

        if data.len() < V3_HEADER_LEN {
            return Err(RefsError::Truncated {
                structure: "v3 metadata-block header",
                need: V3_HEADER_LEN,
                have: data.len(),
            });
        }

        Ok(Self {
            signature,
            block_number: le_u64(data, SELF_BLOCK_NUMBER_OFFSET),
        })
    }

    /// Verify a CRC-32C over the explicit byte range `data[start..end]` against
    /// a `stored` value.
    ///
    /// Returns `Some(true)`/`Some(false)` when the range is in bounds, or
    /// `None` when it is not (out-of-range never panics — the Paranoid
    /// Gatekeeper standard). The **range is the caller's responsibility**: ReFS's
    /// own block-checksum coverage range is undetermined from the available
    /// reverse-engineered references (see the module docs), so this crate does
    /// not guess it.
    #[must_use]
    pub fn verify_crc32c(data: &[u8], start: usize, end: usize, stored: u32) -> Option<bool> {
        if start > end {
            return None;
        }
        let slice = data.get(start..end)?;
        Some(crc32c(slice) == stored)
    }
}
