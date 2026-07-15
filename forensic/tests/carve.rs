//! F-CARVE tests — CoW metadata-residue recovery over ReFS.
//!
//! ReFS is **allocate-on-write**: when a metadata page is updated a NEW page is
//! written and the object table re-points at it, leaving the OLD `MSB+` page in
//! place until its space is reused. F-CARVE scans for `MSB+` pages whose
//! self-block-number is NOT the current object-table mapping (= stale/old
//! versions) and surfaces the directory-entry rows found in them (potential
//! deleted / renamed / superseded entries).
//!
//! # Provenance and tiering (honest oracle limitation)
//!
//! ReFS is undocumented; every structural fact is reverse-engineered (see
//! tests/data/README.md). The **real-bytes** F-CARVE result validated here is a
//! genuine stale CoW page on the 256 MiB v3.14 oracle: the object table maps the
//! `0x600` root directory to CURRENT tree-root block `80_384` (cluster 14848),
//! while an OLDER CoW copy of the same directory (self-block `70_656`, cluster
//! 5120) still carries the `System Volume Information` directory entry that the
//! current page no longer holds. That is a real, resident stale-page recovery.
//!
//! The MINTED USER files (`dir_a` / `known1.txt` / `nested` / `big.bin`) live in
//! a non-resident band beyond the 256 MiB slice and the source VHD is lost, so
//! their deleted-recovery end-to-end is **oracle-blocked** — validated instead on
//! synthetic stale pages + the resident `System Volume Information` entry, and
//! documented (never fabricated).

use refs_forensic::recover_residue;

const CLUSTER: usize = 4096;
const PAGE: usize = 16384;

// ── Synthetic: a stale MSB+ page is carved; a current one is not ─────────────

/// Build a minimal valid `MSB+` Minstore leaf page carrying one `0x30`
/// directory-entry row with the given name (UTF-16LE) and the given self-block
/// number, mirroring the verified libfsrefs directory-object layout.
fn build_dir_page(self_block: u64, table_id: u64, entry_name: &str) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    page[0..4].copy_from_slice(b"MSB+");
    page[0x20..0x28].copy_from_slice(&self_block.to_le_bytes());
    page[72..80].copy_from_slice(&table_id.to_le_bytes());

    let node_hdr = 0x100usize;
    let nho_field = 0x50usize;
    page[nho_field..nho_field + 4].copy_from_slice(&((node_hdr - nho_field) as u32).to_le_bytes());

    // Key: 0x30 entry record — record type (0x0030) + entry type (2 = directory)
    // + UTF-16LE name.
    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(&0x0030u16.to_le_bytes());
    key.extend_from_slice(&2u16.to_le_bytes()); // entry type: directory
    for u in entry_name.encode_utf16() {
        key.extend_from_slice(&u.to_le_bytes());
    }
    // Value: a directory value (72 bytes) — object id at +0, timestamps, attrs.
    let value = vec![0u8; 72];

    let rec = node_hdr + 32;
    let key_off = 16u16;
    let val_off = key_off + key.len() as u16;
    let rec_size = (val_off as usize + value.len()) as u32;
    page[rec..rec + 4].copy_from_slice(&rec_size.to_le_bytes());
    page[rec + 4..rec + 6].copy_from_slice(&key_off.to_le_bytes());
    page[rec + 6..rec + 8].copy_from_slice(&(key.len() as u16).to_le_bytes());
    page[rec + 8..rec + 10].copy_from_slice(&0u16.to_le_bytes());
    page[rec + 10..rec + 12].copy_from_slice(&val_off.to_le_bytes());
    page[rec + 12..rec + 14].copy_from_slice(&(value.len() as u16).to_le_bytes());
    page[rec + key_off as usize..rec + key_off as usize + key.len()].copy_from_slice(&key);
    page[rec + val_off as usize..rec + val_off as usize + value.len()].copy_from_slice(&value);

    let roff_start_abs = node_hdr + 0x2000;
    page[roff_start_abs..roff_start_abs + 4]
        .copy_from_slice(&(0xffff_0000u32 | ((rec - node_hdr) as u32 & 0xffff)).to_le_bytes());
    page[node_hdr + 16..node_hdr + 20]
        .copy_from_slice(&((roff_start_abs - node_hdr) as u32).to_le_bytes());
    page[node_hdr + 20..node_hdr + 24].copy_from_slice(&1u32.to_le_bytes());
    page
}

/// Build a minimal object-table `MSB+` page mapping `object_id` → current
/// tree-root `block` (value's block reference at +0x20), so the carver knows
/// which self-block is CURRENT (and everything else for that table is stale).
fn build_object_table(self_block: u64, object_id: u64, current_block: u64) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    page[0..4].copy_from_slice(b"MSB+");
    page[0x20..0x28].copy_from_slice(&self_block.to_le_bytes());
    page[72..80].copy_from_slice(&2u64.to_le_bytes()); // object table = table id 2

    let node_hdr = 0x100usize;
    page[0x50..0x54].copy_from_slice(&((node_hdr - 0x50) as u32).to_le_bytes());

    // Object-record key: 16 bytes, object id at [8..16].
    let mut key = vec![0u8; 16];
    key[8..16].copy_from_slice(&object_id.to_le_bytes());
    // Value: block reference; first block number at value+0x20.
    let mut value = vec![0u8; 0x28];
    value[0x20..0x28].copy_from_slice(&current_block.to_le_bytes());

    let rec = node_hdr + 32;
    let key_off = 16u16;
    let val_off = key_off + key.len() as u16;
    let rec_size = (val_off as usize + value.len()) as u32;
    page[rec..rec + 4].copy_from_slice(&rec_size.to_le_bytes());
    page[rec + 4..rec + 6].copy_from_slice(&key_off.to_le_bytes());
    page[rec + 6..rec + 8].copy_from_slice(&(key.len() as u16).to_le_bytes());
    page[rec + 10..rec + 12].copy_from_slice(&val_off.to_le_bytes());
    page[rec + 12..rec + 14].copy_from_slice(&(value.len() as u16).to_le_bytes());
    page[rec + key_off as usize..rec + key_off as usize + key.len()].copy_from_slice(&key);
    page[rec + val_off as usize..rec + val_off as usize + value.len()].copy_from_slice(&value);

    let roff = node_hdr + 0x2000;
    page[roff..roff + 4]
        .copy_from_slice(&(0xffff_0000u32 | ((rec - node_hdr) as u32 & 0xffff)).to_le_bytes());
    page[node_hdr + 16..node_hdr + 20].copy_from_slice(&((roff - node_hdr) as u32).to_le_bytes());
    page[node_hdr + 20..node_hdr + 24].copy_from_slice(&1u32.to_le_bytes());
    page
}

#[test]
fn synthetic_stale_directory_page_is_carved() {
    // Assemble an image with:
    //   cluster 56 : object table mapping 0x600 -> CURRENT block 80384
    //   cluster 5  : CURRENT 0x600 page (self-block 80384) — empty of the entry
    //   cluster 3  : STALE  0x600 page (self-block 70656) carrying "GhostDir"
    // The carver must surface the stale page + its carved directory entry, and
    // must NOT surface the current page.
    let mut image = vec![0u8; 64 * CLUSTER];
    let place = |img: &mut [u8], cl: usize, page: &[u8]| {
        img[cl * CLUSTER..cl * CLUSTER + page.len()].copy_from_slice(page);
    };
    place(&mut image, 56, &build_object_table(56, 0x600, 80_384));
    place(&mut image, 5, &build_dir_page(80_384, 0x600, "CurrentOnly"));
    place(&mut image, 3, &build_dir_page(70_656, 0x600, "GhostDir"));

    let residue = recover_residue(&image);
    // The stale page (self-block 70656) is surfaced.
    let stale = residue
        .iter()
        .find(|r| r.self_block == 70_656)
        .expect("the stale CoW 0x600 page must be surfaced");
    assert_eq!(stale.table_id, 0x600);
    // Its carved directory entry is recovered.
    assert!(
        stale.entries.iter().any(|e| e == "GhostDir"),
        "the stale page's carved directory entry must be recovered, got {:?}",
        stale.entries
    );
    // The CURRENT page (self-block 80384) is NOT surfaced as stale.
    assert!(
        !residue.iter().any(|r| r.self_block == 80_384),
        "the current object-table mapping must not be carved as stale"
    );
}

#[test]
fn clean_current_only_image_yields_nothing_false() {
    // An image whose only 0x600 page IS the current object-table mapping has no
    // stale residue — the carver must return nothing (no false positive).
    let mut image = vec![0u8; 64 * CLUSTER];
    let place = |img: &mut [u8], cl: usize, page: &[u8]| {
        img[cl * CLUSTER..cl * CLUSTER + page.len()].copy_from_slice(page);
    };
    place(&mut image, 56, &build_object_table(56, 0x600, 80_384));
    place(&mut image, 5, &build_dir_page(80_384, 0x600, "CurrentOnly"));
    let residue = recover_residue(&image);
    assert!(
        residue.is_empty(),
        "no stale page → no residue, got {residue:?}"
    );
}

// ── Robustness ───────────────────────────────────────────────────────────────

#[test]
fn recover_residue_never_panics_on_malformed_input() {
    for size in [0usize, 4, 80, 4096, PAGE, PAGE + 1, 3 * PAGE] {
        let garbage = vec![0xC3u8; size];
        let _ = recover_residue(&garbage); // must not panic
    }
}

// ── Env-gated real-volume F-CARVE (the crux, real resident stale page) ───────

/// Point `REFS_TIER2_ORACLE256` at the 256 MiB container-head slice to prove
/// F-CARVE on the REAL v3.14 volume: the object table maps `0x600` to CURRENT
/// block `80_384` (cluster 14848), and an OLDER CoW copy (self-block `70_656`,
/// cluster 5120) still carries the `System Volume Information` directory entry
/// the current page dropped. The carver must surface that stale page + entry —
/// a real, resident CoW-residue recovery (not synthetic).
///
/// The minted USER files stay non-resident (beyond the slice, source VHD gone),
/// so their deleted-recovery is oracle-blocked — asserted here as the honest,
/// documented wall (the carver must NOT fabricate them).
#[test]
fn real_volume_stale_directory_page_carved_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE256") else {
        eprintln!("REFS_TIER2_ORACLE256 not set — skipping real-volume F-CARVE check");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE256");

    let residue = recover_residue(&data);

    // The stale CoW 0x600 page (self-block 70656) is surfaced with its carved
    // "System Volume Information" entry — a genuine resident stale-page recovery.
    let stale = residue
        .iter()
        .find(|r| r.self_block == 70_656)
        .expect("the real stale CoW 0x600 page (self-block 70656) must be carved");
    assert_eq!(
        stale.table_id, 0x600,
        "the stale page is a 0x600 directory page"
    );
    assert!(
        stale
            .entries
            .iter()
            .any(|e| e == "System Volume Information"),
        "the real stale page's carved directory entry must be recovered, got {:?}",
        stale.entries
    );

    // The CURRENT mapping (self-block 80384) must NOT be surfaced as stale.
    assert!(
        !residue.iter().any(|r| r.self_block == 80_384),
        "the current object-table mapping must not be carved as stale"
    );

    // Honest wall: the minted user files are NOT resident — the carver must never
    // fabricate them from thin air.
    assert!(
        !residue
            .iter()
            .flat_map(|r| r.entries.iter())
            .any(|e| e == "known1.txt" || e == "big.bin"),
        "the non-resident minted files must NOT appear — never fabricate the oracle-blocked band"
    );
}
