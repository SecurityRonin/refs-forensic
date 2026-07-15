//! ReFS v3 metadata-block (page) header + checksum handling — P1 stub (RED).
//!
//! Real implementation lands in the GREEN commit.

/// The ReFS v3 metadata page (block) size in bytes — placeholder for RED.
pub const REFS_METADATA_PAGE_SIZE: usize = 0;

/// CRC-32C — placeholder for RED.
#[must_use]
pub fn crc32c(_data: &[u8]) -> u32 {
    0
}

/// CRC-64/ECMA-182 — placeholder for RED.
#[must_use]
pub fn crc64_ecma(_data: &[u8]) -> u64 {
    0
}

/// A ReFS v3 self-describing metadata-block header — P1 stub (RED).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MetaBlock {
    /// Four-byte block signature.
    pub signature: [u8; 4],
    /// Self block number.
    pub block_number: u64,
}

impl MetaBlock {
    /// Parse — stub for RED (always errors).
    ///
    /// # Errors
    /// Always, until the GREEN implementation lands.
    pub fn parse(
        _data: &[u8],
        _expected: &'static str,
        _offset: u64,
    ) -> Result<Self, crate::RefsError> {
        Err(crate::RefsError::Truncated {
            structure: "MetaBlock (stub)",
            need: 0,
            have: 0,
        })
    }

    /// Verify a CRC-32C — stub for RED.
    #[must_use]
    pub fn verify_crc32c(_data: &[u8], _start: usize, _end: usize, _stored: u32) -> Option<bool> {
        None
    }
}
