//! ReFS boot sector / Volume Boot Record (VBR) — the file-system recognition
//! structure at **offset 0** of the volume. (RED stub — see boot.rs test.)

use crate::error::RefsError;

/// The ReFS file-system signature `"ReFS\0\0\0\0"` at boot offset 3.
pub const REFS_SIGNATURE: &[u8; 8] = b"ReFS\x00\x00\x00\x00";

/// The file-system recognition-structure identifier `"FSRS"` at boot offset 16.
pub const REFS_FSRS: &[u8; 4] = b"FSRS";

/// Parsed ReFS boot VBR / FS-recognition structure. (RED stub.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootSector {
    /// FS signature at offset 3 (`"ReFS\0\0\0\0"`).
    pub signature: [u8; 8],
    /// FS-recognition-structure identifier at offset 16 (`"FSRS"`).
    pub fsrs: [u8; 4],
    /// Number of sectors (offset 24).
    pub num_sectors: u64,
    /// Bytes per sector (offset 32).
    pub bytes_per_sector: u32,
    /// Sectors per cluster block (offset 36).
    pub sectors_per_cluster: u32,
    /// Major format version (offset 40).
    pub major_version: u8,
    /// Minor format version (offset 41).
    pub minor_version: u8,
    /// Volume serial number (offset 56).
    pub volume_serial: u64,
    /// Container / band size (offset 64).
    pub container_size: u64,
}

impl BootSector {
    /// Parse the boot VBR from the start of `data`. (RED stub — returns Err.)
    pub fn parse(_data: &[u8]) -> Result<Self, RefsError> {
        Err(RefsError::Truncated {
            structure: "boot (stub)",
            need: 0,
            have: 0,
        })
    }

    /// Cluster size in bytes. (RED stub.)
    #[must_use]
    pub fn cluster_size(&self) -> u64 {
        0
    }

    /// True for a ReFS v3.x volume. (RED stub.)
    #[must_use]
    pub fn is_v3(&self) -> bool {
        false
    }

    /// Byte offset of the primary superblock. (RED stub.)
    #[must_use]
    pub fn superblock_offset(&self) -> u64 {
        0
    }

    /// Reject any non-v3.x volume. (RED stub — returns Err always.)
    pub fn require_v3(&self) -> Result<(), RefsError> {
        Err(RefsError::UnsupportedVersion {
            major: self.major_version,
            minor: self.minor_version,
        })
    }
}
