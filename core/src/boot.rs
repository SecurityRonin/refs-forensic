//! ReFS boot sector / Volume Boot Record (VBR) — the file-system recognition
//! structure at **offset 0** of the volume.
//!
//! Field offsets follow libyal's `libfsrefs` documentation of the ReFS
//! `FILE_SYSTEM_RECOGNITION_STRUCTURE` (reverse-engineered — no official
//! Microsoft spec). Every offset here was additionally byte-verified against a
//! real ReFS v3.14 volume minted on Windows 11 (see tests/data/README.md):
//!
//! ```text
//! off  size  field
//!   0    3   boot entry point / JMP (0x00 on a data-only ReFS volume)
//!   3    8   file-system signature "ReFS\0\0\0\0"
//!  16    4   FS recognition-structure identifier "FSRS"
//!  24    8   number of sectors
//!  32    4   bytes per sector
//!  36    4   sectors per cluster block (allocation unit)
//!  40    1   major format version
//!  41    1   minor format version
//!  56    8   volume serial number
//!  64    8   container / band size
//! ```
//!
//! ReFS is little-endian.

use crate::bytes::{ascii, le_u32, le_u64, u8_at};
use crate::error::RefsError;
use crate::superblock::REFS_SUPERBLOCK_CLUSTER;

/// The ReFS file-system signature `"ReFS\0\0\0\0"` at boot offset 3.
pub const REFS_SIGNATURE: &[u8; 8] = b"ReFS\x00\x00\x00\x00";

/// The file-system recognition-structure identifier `"FSRS"` at boot offset 16.
pub const REFS_FSRS: &[u8; 4] = b"FSRS";

/// Minimum bytes required to read every field this parser extracts (through the
/// container size at offset 64, +8 = 72).
const BOOT_MIN_LEN: usize = 72;

/// Parsed ReFS boot VBR / FS-recognition structure.
///
/// `#[non_exhaustive]` so later phases add fields (flags, the FSRS checksum)
/// without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootSector {
    /// FS signature at offset 3 — validated to equal [`REFS_SIGNATURE`].
    pub signature: [u8; 8],
    /// FS-recognition-structure identifier at offset 16 — validated to equal
    /// [`REFS_FSRS`].
    pub fsrs: [u8; 4],
    /// `Number of sectors` (offset 24).
    pub num_sectors: u64,
    /// `Bytes per sector` (offset 32).
    pub bytes_per_sector: u32,
    /// `Sectors per cluster block` / allocation unit (offset 36).
    pub sectors_per_cluster: u32,
    /// `Major format version` (offset 40) — `3` for the v3.x line this reader
    /// targets, `1` for the legacy Server 2012 / 8.1 layout.
    pub major_version: u8,
    /// `Minor format version` (offset 41).
    pub minor_version: u8,
    /// `Volume serial number` (offset 56).
    pub volume_serial: u64,
    /// `Container` / band size (offset 64).
    pub container_size: u64,
}

impl BootSector {
    /// Parse the boot VBR from the start of `data`.
    ///
    /// # Errors
    ///
    /// - [`RefsError::BadSignature`] if bytes 3..11 are not `"ReFS\0\0\0\0"` —
    ///   the eight offending bytes are carried in the error.
    /// - [`RefsError::BadFsrs`] if bytes 16..20 are not `"FSRS"`.
    /// - [`RefsError::Truncated`] if `data` is shorter than the fields read.
    ///
    /// The version is **not** checked here (a v1 volume still has a valid
    /// signature); call [`Self::require_v3`] to gate on version.
    pub fn parse(data: &[u8]) -> Result<Self, RefsError> {
        // Validate identity (signature, then FSRS) before length so a
        // wrong-image error names the offending bytes even on a short buffer.
        let mut signature = [0u8; 8];
        if let Some(s) = data.get(3..11) {
            signature.copy_from_slice(s);
        }
        if &signature != REFS_SIGNATURE {
            return Err(RefsError::BadSignature { found: signature });
        }

        let mut fsrs = [0u8; 4];
        if let Some(s) = data.get(16..20) {
            fsrs.copy_from_slice(s);
        }
        if &fsrs != REFS_FSRS {
            return Err(RefsError::BadFsrs {
                found: fsrs,
                found_ascii: ascii(&fsrs),
            });
        }

        // All parsed fields lie within the first BOOT_MIN_LEN bytes; range-check
        // once so a short buffer that passed the signature check still fails
        // loud rather than reading zeroes for real geometry.
        if data.len() < BOOT_MIN_LEN {
            return Err(RefsError::Truncated {
                structure: "boot VBR",
                need: BOOT_MIN_LEN,
                have: data.len(),
            });
        }

        Ok(Self {
            signature,
            fsrs,
            num_sectors: le_u64(data, 24),
            bytes_per_sector: le_u32(data, 32),
            sectors_per_cluster: le_u32(data, 36),
            major_version: u8_at(data, 40),
            minor_version: u8_at(data, 41),
            volume_serial: le_u64(data, 56),
            container_size: le_u64(data, 64),
        })
    }

    /// Cluster (allocation-unit) size in bytes: `bytes_per_sector *
    /// sectors_per_cluster`.
    ///
    /// Saturating so absurd geometry from a hostile image yields a clamped value
    /// rather than an overflow panic (the Paranoid Gatekeeper standard).
    #[must_use]
    pub fn cluster_size(&self) -> u64 {
        u64::from(self.bytes_per_sector).saturating_mul(u64::from(self.sectors_per_cluster))
    }

    /// True for a ReFS **v3.x** volume (`major_version == 3`) — the format this
    /// reader targets.
    #[must_use]
    pub fn is_v3(&self) -> bool {
        self.major_version == 3
    }

    /// Byte offset of the primary superblock: [`REFS_SUPERBLOCK_CLUSTER`] × the
    /// cluster size.
    ///
    /// Saturating so a hostile cluster size cannot overflow.
    #[must_use]
    pub fn superblock_offset(&self) -> u64 {
        REFS_SUPERBLOCK_CLUSTER.saturating_mul(self.cluster_size())
    }

    /// Reject any non-v3.x volume, naming the actual version bytes.
    ///
    /// This is the fail-loud version gate RESEARCH.md mandates: a v1 volume
    /// (Server 2012 / 8.1) has a materially different on-disk layout, so parsing
    /// it as v3 would silently misparse. Callers gate on this before trusting
    /// any structure beyond the boot VBR.
    ///
    /// # Errors
    ///
    /// [`RefsError::UnsupportedVersion`] if `major_version != 3`.
    pub fn require_v3(&self) -> Result<(), RefsError> {
        if self.is_v3() {
            Ok(())
        } else {
            Err(RefsError::UnsupportedVersion {
                major: self.major_version,
                minor: self.minor_version,
            })
        }
    }
}
