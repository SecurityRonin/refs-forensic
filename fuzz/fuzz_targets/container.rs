#![no_main]
//! The container tree maps virtual → physical blocks. `ContainerTable::parse` +
//! record iteration and the resident-image `ContainerResolver` (built by scanning
//! attacker bytes, then resolving attacker-chosen virtual blocks) must never
//! panic, and the virtual-block decomposition must be arithmetic-safe.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes select the (untrusted) band-clusters size + resolve target,
    // splitting the rest as the image scanned for resident container pages.
    let (band_clusters, vblock, image) = if data.len() >= 16 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&data[..8]);
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[8..16]);
        (u64::from_le_bytes(a), u64::from_le_bytes(b), &data[16..])
    } else {
        (0u64, 0u64, data)
    };

    // Pure arithmetic decomposition must never panic (div/mod by zero-guarded).
    let _ = refs_core::decompose_virtual_block(vblock, band_clusters);

    if let Ok(ct) = refs_core::ContainerTable::parse(image, 0) {
        for rec in ct.records() {
            std::hint::black_box(rec);
        }
        let _ = ct.physical_base(vblock);
        let _ = ct.cluster_count(vblock);
    }

    // The resident-image resolver scans arbitrary bytes and resolves an arbitrary
    // virtual block — both must stay panic-free and bounds-safe.
    let resolver = refs_core::ContainerResolver::from_resident_image(image, band_clusters);
    let _ = resolver.resolve_virtual(vblock);
    let _ = resolver.resolve_virtual_checked(vblock);
});
