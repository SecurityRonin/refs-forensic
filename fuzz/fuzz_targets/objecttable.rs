#![no_main]
//! The object table is a Minstore page mapping object ids → tree-root page
//! references. `ObjectTable::parse` and `lookup` over an attacker-controlled page
//! and an attacker-controlled object id must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) offset, next 8 the lookup object id.
    let (off, oid, page) = if data.len() >= 16 {
        let mut o = [0u8; 8];
        o.copy_from_slice(&data[..8]);
        let mut i = [0u8; 8];
        i.copy_from_slice(&data[8..16]);
        (u64::from_le_bytes(o), u64::from_le_bytes(i), &data[16..])
    } else {
        (0u64, refs_core::REFS_ROOT_DIRECTORY_ID, data)
    };
    if let Ok(ot) = refs_core::ObjectTable::parse(page, off) {
        let _ = ot.lookup(oid);
        let _ = ot.lookup(refs_core::REFS_ROOT_DIRECTORY_ID);
    }
});
