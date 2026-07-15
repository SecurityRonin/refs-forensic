//! Error types for the ReFS reader.

use thiserror::Error;

/// Errors surfaced while parsing ReFS on-disk structures.
///
/// Every variant names the offending value so an "unknown/invalid" report hands
/// the investigator the evidence (raw bytes / offset / version), never a bare
/// "invalid" (the fail-loud, show-the-unrecognized-value standard).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefsError {
    /// The buffer was too small to hold the structure being parsed.
    #[error("buffer too small for {structure}: need {need} bytes, have {have}")]
    Truncated {
        /// Name of the structure that could not be read.
        structure: &'static str,
        /// Minimum byte length required.
        need: usize,
        /// Byte length actually available.
        have: usize,
    },

    /// The ReFS file-system signature at boot offset 3 was not
    /// `"ReFS\0\0\0\0"`. Carries the eight bytes actually found so the caller
    /// can identify what the image really is (fail-loud with the offending
    /// value).
    #[error("bad ReFS signature at offset 3: found {found:02x?}, expected \"ReFS\\0\\0\\0\\0\"")]
    BadSignature {
        /// The eight raw bytes at boot offset 3.
        found: [u8; 8],
    },

    /// The file-system recognition-structure identifier at boot offset 16 was
    /// not `"FSRS"`. Carries the four bytes actually found.
    #[error("bad FSRS identifier at offset 16: found {found:02x?} (\"{found_ascii}\"), expected \"FSRS\"")]
    BadFsrs {
        /// The four raw bytes at boot offset 16.
        found: [u8; 4],
        /// Best-effort ASCII rendering of `found` (non-printables as `.`).
        found_ascii: String,
    },

    /// A ReFS metadata block did not carry the expected block signature
    /// (`SUPB` superblock, `CHKP` checkpoint, `MSB+` ministore).
    ///
    /// Carries the offending four bytes and the byte offset where they were
    /// found, so the investigator sees *what* was there and *where* — never a
    /// silently-skipped block.
    #[error("bad metadata-block signature at offset {offset:#x}: found {found:02x?} (\"{found_ascii}\"), expected \"{expected}\"")]
    BadBlockSignature {
        /// The four raw bytes at the block's signature position.
        found: [u8; 4],
        /// Best-effort ASCII rendering of `found` (non-printables as `.`).
        found_ascii: String,
        /// The signature that was expected (e.g. `"SUPB"`).
        expected: &'static str,
        /// Absolute byte offset of the signature in the image/buffer.
        offset: u64,
    },

    /// The ReFS major format version is not one this reader supports.
    ///
    /// This reader targets **ReFS v3.x** (Server 2016+/Win10 1803+/Win11). A v1
    /// volume (Server 2012 / 8.1) has a materially different on-disk layout and
    /// is deliberately rejected rather than silently misparsed. Carries the
    /// actual major/minor bytes so the investigator sees the real version (the
    /// fail-loud gate RESEARCH.md mandates: "never silently misparse").
    #[error("unsupported ReFS format version {major}.{minor}: this reader supports v3.x only (major == 3)")]
    UnsupportedVersion {
        /// The `Major format version` byte at boot offset 40.
        major: u8,
        /// The `Minor format version` byte at boot offset 41.
        minor: u8,
    },
}
