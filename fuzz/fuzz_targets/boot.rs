#![no_main]
//! The boot Volume Boot Record is the fully attacker-controlled front of a ReFS
//! volume — `BootSector::parse` and every geometry/version helper driven from it
//! must never panic on any byte string, and the fail-loud v3 gate must not either.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(boot) = refs_core::BootSector::parse(data) {
        // Drive every geometry/version accessor over the arbitrary VBR.
        let _ = boot.cluster_size();
        let _ = boot.is_v3();
        let _ = boot.superblock_offset();
        let _ = boot.require_v3();
        std::hint::black_box((boot.major_version, boot.minor_version, boot.volume_serial));
    }
});
