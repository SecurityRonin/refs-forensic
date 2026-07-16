#![no_main]
//! A Minstore B+-tree page (`MinstorePage`) and its rows are read straight from
//! an attacker-controlled image — `parse`, the level/leaf/branch discriminators,
//! and full row iteration (key + value slices) must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) offset; the rest is the page.
    let (off, page) = if data.len() >= 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(b), &data[8..])
    } else {
        (0u64, data)
    };
    if let Ok(mp) = refs_core::MinstorePage::parse(page, off) {
        let _ = mp.level();
        let _ = mp.is_leaf();
        let _ = mp.is_branch();
        for row in mp.rows() {
            std::hint::black_box((row.key, row.value));
        }
    }
});
