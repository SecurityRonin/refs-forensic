#![no_main]
//! The primary `SUPB` superblock block is read from an attacker-controlled
//! offset — `Superblock::parse_at`, the raw `MetadataBlockRef::parse`, and the
//! checkpoint-location extraction driven from a superblock must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) offset the superblock is parsed at.
    let (off, block) = if data.len() >= 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(b), &data[8..])
    } else {
        (0u64, data)
    };
    let _ = refs_core::Superblock::parse_at(block, off);
    let _ = refs_core::MetadataBlockRef::parse(block, "SUPB", off);
    // A superblock names its checkpoint copies — the extraction must be panic-free
    // over the arbitrary block too.
    let _ = refs_core::Checkpoint::locations_from_superblock(block);
});
