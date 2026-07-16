#![no_main]
//! Directory parsing/walking over an attacker-controlled ReFS image. The
//! page-level `parse_directory`, the whole-image `walk_directory` / `list_dir`,
//! and `find_by_path` (with an attacker-controlled path string) must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) root block / object id for the
    // whole-image walkers; the rest is the image (also used as a single page).
    let (arg, image) = if data.len() >= 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(b), &data[8..])
    } else {
        (0u64, data)
    };

    let _ = refs_core::parse_directory(image);
    let _ = refs_core::walk_directory(image, arg);
    let _ = refs_core::list_dir(image, arg);
    // Derive an arbitrary path string from the tail bytes (lossy UTF-8 is fine —
    // find_by_path must tolerate any &str).
    let path = String::from_utf8_lossy(image);
    let _ = refs_core::find_by_path(image, &path);
});
