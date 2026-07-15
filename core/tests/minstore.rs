//! P1 tests — ReFS v3 metadata-block header, checkpoint, object table, and the
//! Minstore B+-tree page, driven over synthetic pages built to the verified
//! layout (always-on, committed) and the real minted volume (env-gated).
//!
//! # Provenance and tiering
//!
//! ReFS is undocumented; every structural fact is reverse-engineered (libyal
//! `libfsrefs` + the real v3.14 volume, see tests/data/README.md). Structural
//! metadata is **Tier-2 at best**.
//!
//! The verified layout (real ReFS v3.14 volume + libfsrefs, cross-checked byte
//! for byte in P1) is:
//!
//! * **Metadata block (page) = 16384 bytes** (four 4096-byte clusters).
//! * **Metadata block header (v3, 80 bytes):** signature @0, volume signature
//!   @12, four block numbers @32/40/48/56 (the *first* is the self block
//!   number), 128-bit table identifier @64.
//! * **Metadata block reference (v3, 48 bytes):** four block numbers @0, then a
//!   checksum descriptor — type @34 (`1` = CRC-32C, `2` = CRC64-ECMA-182),
//!   data offset @35 (relative to the descriptor), data size @36, and the stored
//!   checksum @40.
//! * **Superblock struct @ block+80:** checkpoint-refs offset @32, count @36,
//!   self-ref offset @40. The checkpoint block numbers are *virtual* addresses.
//! * **Minstore page:** node-header-offset @block+80 → node header (32 bytes:
//!   data area start/end, unused size, node level @12, node type flags @13,
//!   record-offsets start @16, count @20). Record offsets are `u32` with the
//!   **upper 16 bits set to `0xffff`** in v3; the lower 16 bits are the record
//!   offset relative to the node header. Each node record: size @0, key offset
//!   @4, key size @6, flags @8, value offset @10, value size @12.
//! * **Object tree:** a Minstore tree whose keys are 16-byte object-record keys
//!   (`[0..8]` zero, `[8..16]` the object identifier) and whose values carry a
//!   metadata block reference @value+32. Well-known id `0x600` is the root
//!   directory (`REFS_ROOT_DIRECTORY_ID`).

use refs_core::{
    Checkpoint, MetaBlock, MinstorePage, ObjectTable, REFS_METADATA_PAGE_SIZE,
    REFS_ROOT_DIRECTORY_ID,
};

/// The committed always-on fixture (boot VBR + SUPB, 128 KiB) — reaches the
/// superblock at cluster 30 but *not* the Minstore pages at cluster 36+.
const BOOT_SB: &[u8] = include_bytes!("../../tests/data/refs_boot_superblock.bin");

const CLUSTER: usize = 4096;
const PAGE: usize = 16384;

// ── Synthetic Minstore page builder (Tier-3 fixture, verified layout) ────────

/// Build a synthetic v3 metadata-block header (80 bytes) with `signature` and
/// self block number `block_number`, writing into `page`.
fn write_header(page: &mut [u8], signature: &[u8; 4], block_number: u64) {
    page[0..4].copy_from_slice(signature);
    page[4..8].copy_from_slice(&2u32.to_le_bytes());
    page[12..16].copy_from_slice(&0xf890_ec89u32.to_le_bytes());
    page[32..40].copy_from_slice(&block_number.to_le_bytes());
}

/// Build a synthetic Minstore B+-tree page to the verified v3 layout.
///
/// `level` 0 = leaf; `is_branch` sets the branch node-type flag. `rows` are
/// `(key, value)` pairs packed as node records. Returns the 16 KiB page.
fn build_minstore_page(level: u8, is_branch: bool, rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    write_header(&mut page, b"MSB+", 42);

    // Node header offset field @ block+80 (value relative to this field).
    let node_hdr = 0x100usize; // absolute offset of the node header within page
    let nho_field = 80usize;
    page[nho_field..nho_field + 4].copy_from_slice(&((node_hdr - nho_field) as u32).to_le_bytes());

    // Pack records after the node header (32 bytes).
    let mut cursor = node_hdr + 32;
    let mut record_offsets: Vec<u32> = Vec::new();
    for (key, value) in rows {
        let rec = cursor;
        record_offsets.push((rec - node_hdr) as u32);
        let key_off = 16u16;
        let val_off = key_off + key.len() as u16;
        let rec_size = (val_off as usize + value.len()) as u32;
        page[rec..rec + 4].copy_from_slice(&rec_size.to_le_bytes());
        page[rec + 4..rec + 6].copy_from_slice(&key_off.to_le_bytes());
        page[rec + 6..rec + 8].copy_from_slice(&(key.len() as u16).to_le_bytes());
        page[rec + 8..rec + 10].copy_from_slice(&0u16.to_le_bytes());
        page[rec + 10..rec + 12].copy_from_slice(&val_off.to_le_bytes());
        page[rec + 12..rec + 14].copy_from_slice(&(value.len() as u16).to_le_bytes());
        page[rec + key_off as usize..rec + key_off as usize + key.len()].copy_from_slice(key);
        page[rec + val_off as usize..rec + val_off as usize + value.len()].copy_from_slice(value);
        cursor = rec + rec_size as usize;
    }

    // Record-offset array (placed well after the records).
    let roff_start_abs = node_hdr + 0x2000;
    let roff_start_rel = (roff_start_abs - node_hdr) as u32;
    for (i, ro) in record_offsets.iter().enumerate() {
        // v3: upper 16 bits set to 0xffff.
        let raw = 0xffff_0000u32 | (*ro & 0xffff);
        let at = roff_start_abs + i * 4;
        page[at..at + 4].copy_from_slice(&raw.to_le_bytes());
    }

    // Node header (32 bytes).
    let nh = node_hdr;
    page[nh..nh + 4].copy_from_slice(&32u32.to_le_bytes()); // data area start
    page[nh + 4..nh + 8].copy_from_slice(&((cursor - node_hdr) as u32).to_le_bytes()); // data area end
    page[nh + 8..nh + 12].copy_from_slice(&0u32.to_le_bytes()); // unused
    page[nh + 12] = level;
    page[nh + 13] = if is_branch { 0x01 } else { 0x00 };
    page[nh + 16..nh + 20].copy_from_slice(&roff_start_rel.to_le_bytes());
    page[nh + 20..nh + 24].copy_from_slice(&(record_offsets.len() as u32).to_le_bytes());
    page[nh + 24..nh + 28].copy_from_slice(
        &((roff_start_abs + record_offsets.len() * 4 - node_hdr) as u32).to_le_bytes(),
    );
    page
}

/// A synthetic object-tree leaf whose rows are `(object_id, root_block_number)`.
fn build_object_tree(entries: &[(u64, u64)]) -> Vec<u8> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .map(|(oid, root)| {
            let mut key = vec![0u8; 16];
            key[8..16].copy_from_slice(&oid.to_le_bytes());
            // Object record value v3: block reference @ value+32; first block# @+32.
            let mut val = vec![0u8; 48 + 32];
            val[32..40].copy_from_slice(&root.to_le_bytes());
            (key, val)
        })
        .collect();
    build_minstore_page(0, false, &rows)
}

// ── MetaBlock header ─────────────────────────────────────────────────────────

#[test]
fn metablock_validates_supb_on_real_superblock() {
    // The committed fixture reaches the SUPB page at cluster 30.
    let page = &BOOT_SB[30 * CLUSTER..];
    let mb = MetaBlock::parse(page, "SUPB", (30 * CLUSTER) as u64).expect("SUPB metadata block");
    assert_eq!(&mb.signature, b"SUPB");
    assert_eq!(mb.block_number, 30, "self block number @0x20 == 30");
}

#[test]
fn metablock_bad_signature_names_bytes_and_offset() {
    let mut page = BOOT_SB[30 * CLUSTER..].to_vec();
    page[0..4].copy_from_slice(b"CHKP");
    let err = MetaBlock::parse(&page, "SUPB", 0x1e000).unwrap_err();
    match err {
        refs_core::RefsError::BadBlockSignature {
            found,
            expected,
            offset,
            ..
        } => {
            assert_eq!(&found, b"CHKP", "offending bytes surfaced");
            assert_eq!(expected, "SUPB");
            assert_eq!(offset, 0x1e000, "offset surfaced");
        }
        other => panic!("expected BadBlockSignature, got {other:?}"),
    }
}

#[test]
fn metablock_page_size_is_16384() {
    assert_eq!(
        REFS_METADATA_PAGE_SIZE, PAGE,
        "ReFS v3 metadata page = 16 KiB"
    );
}

// ── CRC (algorithm oracle = published CRC-32C / CRC-64 check values) ─────────

#[test]
fn crc32c_matches_published_check_value() {
    // CRC-32C (CRC_32_ISCSI) check value over "123456789" is 0xE3069283
    // (the RustCrypto/`crc` crate catalog / RFC 3720 test vector — Tier-1
    // independent answer key).
    assert_eq!(
        refs_core::crc32c(b"123456789"),
        0xE306_9283,
        "CRC-32C published check value"
    );
}

#[test]
fn crc64_ecma_matches_published_check_value() {
    // CRC-64/ECMA-182 check value over "123456789" is 0x6C40DF5F0B497347.
    assert_eq!(
        refs_core::crc64_ecma(b"123456789"),
        0x6C40_DF5F_0B49_7347,
        "CRC-64/ECMA-182 published check value"
    );
}

#[test]
fn metablock_crc_verify_true_then_false_on_byteflip() {
    // A synthetic block whose checksum descriptor covers a KNOWN range (the
    // whole page up to the checksum field) lets us prove verify() returns
    // Some(true) on a clean block and Some(false) after a byte flip — testing
    // the verifier plumbing, not ReFS's (undetermined) coverage range.
    let mut page = build_minstore_page(0, false, &[(vec![1, 2, 3], vec![9, 9])]);
    // Install a self-consistent CRC-32C over page[0..len-4] into the last 4 bytes.
    let len = page.len();
    let crc = refs_core::crc32c(&page[..len - 4]);
    page[len - 4..].copy_from_slice(&crc.to_le_bytes());
    // Verify over the explicit range [0, len-4) with the stored 4-byte CRC-32C.
    assert_eq!(
        MetaBlock::verify_crc32c(&page, 0, len - 4, crc),
        Some(true),
        "clean block verifies"
    );
    page[100] ^= 0xff;
    let crc2 = refs_core::crc32c(&page[..len - 4]);
    assert_eq!(
        MetaBlock::verify_crc32c(&page, 0, len - 4, crc),
        Some(false),
        "a byte flip fails verification"
    );
    // sanity: the recomputed CRC differs
    assert_ne!(crc, crc2);
}

#[test]
fn metablock_crc_out_of_range_is_none_never_panics() {
    let page = vec![0u8; 64];
    // A range past the buffer must yield None, not panic.
    assert_eq!(MetaBlock::verify_crc32c(&page, 0, 10_000, 0), None);
    assert_eq!(MetaBlock::verify_crc32c(&page, 5_000, 6_000, 0), None);
}

// ── Minstore B+-tree page ────────────────────────────────────────────────────

#[test]
fn minstore_leaf_rows_iterate_with_correct_keys_and_values() {
    let rows = vec![
        (vec![0xAA, 0xBB], vec![0x01, 0x02, 0x03]),
        (vec![0xCC], vec![0x04]),
        (b"key3".to_vec(), b"value-three".to_vec()),
    ];
    let page = build_minstore_page(0, false, &rows);
    let mp = MinstorePage::parse(&page, 0).expect("minstore page parses");
    assert_eq!(mp.level(), 0, "leaf node");
    assert!(mp.is_leaf());
    assert!(!mp.is_branch());
    let got: Vec<(Vec<u8>, Vec<u8>)> = mp
        .rows()
        .map(|r| (r.key.to_vec(), r.value.to_vec()))
        .collect();
    assert_eq!(got.len(), rows.len(), "row count matches");
    for (i, (k, v)) in rows.iter().enumerate() {
        assert_eq!(&got[i].0, k, "row {i} key");
        assert_eq!(&got[i].1, v, "row {i} value");
    }
}

#[test]
fn minstore_internal_node_is_branch() {
    let page = build_minstore_page(1, true, &[(vec![1], vec![2; 48])]);
    let mp = MinstorePage::parse(&page, 0).expect("internal page parses");
    assert_eq!(mp.level(), 1);
    assert!(mp.is_branch(), "level-1 node with branch flag");
    assert!(!mp.is_leaf());
}

#[test]
fn minstore_lying_record_count_yields_only_inbounds_rows() {
    // Corrupt the node header's record count to a huge value; iteration must
    // never over-read the page and must yield only rows that fit.
    let mut page = build_minstore_page(0, false, &[(vec![1], vec![2])]);
    // node header @0x100, count @ +20.
    let nh = 0x100usize;
    page[nh + 20..nh + 24].copy_from_slice(&5_000_000u32.to_le_bytes());
    let mp = MinstorePage::parse(&page, 0).expect("parses despite lying count");
    // Must not panic; every yielded row lies within the page.
    let mut n = 0usize;
    for r in mp.rows() {
        assert!(r.key.len() <= PAGE && r.value.len() <= PAGE);
        n += 1;
        assert!(n < 100_000, "iteration is bounded");
    }
}

#[test]
fn minstore_lying_record_offset_does_not_over_read() {
    let mut page = build_minstore_page(0, false, &[(vec![1, 2], vec![3, 4])]);
    // Point the first record offset far past the page.
    let nh = 0x100usize;
    let roff_start_rel = u32::from_le_bytes(page[nh + 16..nh + 20].try_into().unwrap()) as usize;
    let roff_abs = nh + roff_start_rel;
    page[roff_abs..roff_abs + 4].copy_from_slice(&(0xffff_0000u32 | 0xfff0).to_le_bytes());
    let mp = MinstorePage::parse(&page, 0).expect("parses");
    // Iterating must not panic; a lying offset yields no bytes past the page.
    for r in mp.rows() {
        let _ = (r.key, r.value);
    }
}

#[test]
fn minstore_truncated_page_never_panics() {
    let page = build_minstore_page(0, false, &[(vec![1], vec![2])]);
    for len in [0usize, 4, 80, 84, 0x100, 0x110, 0x120, 0x2000, PAGE - 1] {
        let _ = MinstorePage::parse(&page[..len.min(page.len())], 0);
    }
}

// ── Object table ─────────────────────────────────────────────────────────────

#[test]
fn object_table_lookup_resolves_ids_to_page_refs() {
    // Well-known ids observed on the real volume (0x7..0x501) plus the root
    // directory id constant.
    let entries = [
        (0x7u64, 65616u64),
        (0x8, 65612),
        (0x600, 4242), // REFS_ROOT_DIRECTORY_ID → some tree root
    ];
    let page = build_object_tree(&entries);
    let ot = ObjectTable::parse(&page, 0).expect("object tree parses");
    for (oid, root) in entries {
        let r = ot
            .lookup(oid)
            .unwrap_or_else(|| panic!("object id {oid:#x} must resolve"));
        assert_eq!(r.block_number, root, "object {oid:#x} → root block");
    }
    // The root-directory well-known id resolves.
    assert_eq!(REFS_ROOT_DIRECTORY_ID, 0x600, "root directory object id");
    assert!(ot.lookup(REFS_ROOT_DIRECTORY_ID).is_some());
    // A missing id returns None (not a panic).
    assert!(ot.lookup(0xDEAD_BEEF).is_none());
}

// ── Checkpoint ───────────────────────────────────────────────────────────────

#[test]
fn checkpoint_locations_come_from_superblock() {
    // The superblock's checkpoint references point at the checkpoint blocks. On
    // the real volume these are [157156, 1885500] (virtual addresses).
    let sb = &BOOT_SB[30 * CLUSTER..];
    let cps = Checkpoint::locations_from_superblock(sb).expect("checkpoint locations");
    assert_eq!(
        cps,
        vec![157156, 1885500],
        "checkpoint block numbers from the real SUPB"
    );
}

#[test]
fn checkpoint_superblock_truncated_never_panics() {
    for len in [0usize, 80, 112, 192, 200] {
        let short = &BOOT_SB[30 * CLUSTER..30 * CLUSTER + len.min(CLUSTER)];
        let _ = Checkpoint::locations_from_superblock(short);
    }
}

// ── Env-gated real-volume cross-check (Tier-2, structural) ───────────────────

/// Point `REFS_TIER2_ORACLE` at the 16 MiB partition head to cross-check the
/// Minstore + object-table parsing against the real minted v3.14 volume.
#[test]
fn real_volume_object_tree_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE") else {
        eprintln!("REFS_TIER2_ORACLE not set — skipping real-volume Minstore cross-check");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE");
    // The object tree is the MSB+ page at cluster 56 (table id 0x2), byte 0x38000.
    let page = &data[56 * CLUSTER..56 * CLUSTER + PAGE];
    let mb = MetaBlock::parse(page, "MSB+", (56 * CLUSTER) as u64).expect("MSB+ header");
    assert_eq!(&mb.signature, b"MSB+");

    let ot = ObjectTable::parse(page, 0).expect("real object tree parses");
    // Real well-known object ids present in this leaf node.
    for oid in [0x7u64, 0x8, 0x9, 0xa, 0xd, 0x500, 0x501] {
        assert!(
            ot.lookup(oid).is_some(),
            "well-known object id {oid:#x} present on the real volume"
        );
    }

    // A generic Minstore parse of the same page yields the same 7 rows.
    let mp = MinstorePage::parse(page, 0).expect("real minstore page");
    assert_eq!(mp.level(), 0, "object tree leaf");
    assert_eq!(mp.rows().count(), 7, "7 object records on the real volume");
}

#[test]
fn real_volume_internal_node_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE") else {
        return;
    };
    let data = std::fs::read(&path).expect("read oracle");
    // Cluster 40 is a level-1 internal (branch) node on the real volume.
    let page = &data[40 * CLUSTER..40 * CLUSTER + PAGE];
    let mp = MinstorePage::parse(page, 0).expect("internal node parses");
    assert_eq!(mp.level(), 1, "real internal node is level 1");
    assert!(mp.is_branch(), "real internal node carries the branch flag");
}
