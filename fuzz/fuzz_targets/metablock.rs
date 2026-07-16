#![no_main]
//! A ReFS metadata block (`MSB+`-family self-describing page) is parsed at an
//! attacker-controlled offset, and its CRC-32C / CRC-64 verifiers are driven with
//! attacker-controlled coverage ranges — the parse and the checksum math must
//! never panic or read out of bounds.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) offset; the rest is the block.
    let (off, block) = if data.len() >= 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(b), &data[8..])
    } else {
        (0u64, data)
    };
    // Drive both the superblock ("SUPB") and the MSB+ metadata-page signatures.
    let _ = refs_core::MetaBlock::parse(block, "SUPB", off);
    let _ = refs_core::MetaBlock::parse(block, "MSB+", off);
    // The checksum primitives over the whole arbitrary block.
    let _ = refs_core::crc32c(block);
    let _ = refs_core::crc64_ecma(block);
    // The range-checked verifier with attacker-chosen [start, end) bounds.
    let (start, end) = if block.len() >= 4 {
        (
            usize::from(block[0]) | (usize::from(block[1]) << 8),
            usize::from(block[2]) | (usize::from(block[3]) << 8),
        )
    } else {
        (0, block.len())
    };
    let _ = refs_core::MetaBlock::verify_crc32c(block, start, end, 0);
});
