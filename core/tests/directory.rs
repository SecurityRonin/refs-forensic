//! P2 tests — ReFS directory index + file records: directory-entry rows
//! (record type `0x0030`), the file/directory value metadata (FILETIME
//! timestamps, logical/allocated size, attribute flags), and path resolution.
//!
//! # Provenance and tiering
//!
//! ReFS is undocumented; every structural fact is reverse-engineered (libyal
//! `libfsrefs` directory-object documentation + the real v3.14 volume, see
//! tests/data/README.md). Structural metadata is **Tier-2 at best**.
//!
//! **P2 reachability wall (real-volume Doer-Checker, 2026-07-15).** The minted
//! files live in the **root directory (object id `0x600`)** B+tree. On the real
//! oracle the object tree's branch node (cluster 40/44) points every child at
//! **virtual block `34_494_087_168`** — a virtual address ~132 TiB into the
//! volume, far outside the sparse physical partition. A full scan of the 16 MiB
//! partition head finds **zero** directory-index rows and **zero** occurrences
//! of the minted filenames (`dir_a`, `nested`, `known1.txt`, `big.bin`): the
//! root-directory pages are **not physically resident**. Resolving virtual →
//! physical needs the container table (a later phase). So the real-volume
//! directory *listing* cannot be produced here; the env-gated test asserts the
//! honest wall (a loud [`RefsError::UnresolvedVirtualBlock`], never a faked
//! listing), and the directory/file-record *parsing* is validated Tier-3
//! against synthetic pages built to the exact libfsrefs directory-object layout:
//!
//! Directory record key (`libfsrefs` "Directory record key"):
//! * `+0` u16 record type — `0x0010` base, `0x0020` name, `0x0030` entry.
//! * Entry record (`0x0030`): `+2` u16 directory-entry-type
//!   (`0` = FS-metadata file, `1` = File, `2` = Directory), `+4..` the name in
//!   **UTF-16LE without a terminator** (unpaired surrogates allowed).
//!
//! Directory value (entry type `2`, 72 bytes): `+0` u64 directory object id,
//! `+16/24/32/40` FILETIME creation/modification/metadata-change/access,
//! `+64` u32 file-attribute flags.
//!
//! File value (entry type `1`, embedded Ministore node, 128-byte header):
//! `+0/8/16/24` FILETIME creation/modification/metadata-change/access,
//! `+32` u32 file-attribute flags, `+64` u64 data size, `+72` u64 allocated size.

use refs_core::{
    find_by_path, list_dir, parse_directory, DirEntry, FileMetadata, ObjectTable, RefsError,
    REFS_ROOT_DIRECTORY_ID,
};

const CLUSTER: usize = 4096;
const PAGE: usize = 16384;

// ── Synthetic directory-page builders (Tier-3, verified libfsrefs layout) ────

/// Build a synthetic v3 metadata-block header (80 bytes) — mirrors the P1
/// builder so the directory page is a well-formed Minstore page.
fn write_header(page: &mut [u8], signature: [u8; 4], block_number: u64) {
    page[0..4].copy_from_slice(&signature);
    page[4..8].copy_from_slice(&2u32.to_le_bytes());
    page[12..16].copy_from_slice(&0xf890_ec89u32.to_le_bytes());
    page[32..40].copy_from_slice(&block_number.to_le_bytes());
}

/// Build a synthetic Minstore page (the P1 layout) from `(key, value)` rows.
fn build_minstore_page(level: u8, is_branch: bool, rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    write_header(&mut page, *b"MSB+", 42);
    let node_hdr = 0x100usize;
    let nho_field = 80usize;
    page[nho_field..nho_field + 4].copy_from_slice(&((node_hdr - nho_field) as u32).to_le_bytes());

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

    let roff_start_abs = node_hdr + 0x2000;
    let roff_start_rel = (roff_start_abs - node_hdr) as u32;
    for (i, ro) in record_offsets.iter().enumerate() {
        let raw = 0xffff_0000u32 | (*ro & 0xffff);
        let at = roff_start_abs + i * 4;
        page[at..at + 4].copy_from_slice(&raw.to_le_bytes());
    }

    let nh = node_hdr;
    page[nh..nh + 4].copy_from_slice(&32u32.to_le_bytes());
    page[nh + 4..nh + 8].copy_from_slice(&((cursor - node_hdr) as u32).to_le_bytes());
    page[nh + 8..nh + 12].copy_from_slice(&0u32.to_le_bytes());
    page[nh + 12] = level;
    page[nh + 13] = u8::from(is_branch);
    page[nh + 16..nh + 20].copy_from_slice(&roff_start_rel.to_le_bytes());
    page[nh + 20..nh + 24].copy_from_slice(&(record_offsets.len() as u32).to_le_bytes());
    page[nh + 24..nh + 28].copy_from_slice(
        &((roff_start_abs + record_offsets.len() * 4 - node_hdr) as u32).to_le_bytes(),
    );
    page
}

/// A directory entry-record **key** (record type `0x0030`): entry type + name.
fn dir_entry_key(entry_type: u16, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + name.len() * 2);
    k.extend_from_slice(&0x0030u16.to_le_bytes());
    k.extend_from_slice(&entry_type.to_le_bytes());
    for u in name.encode_utf16() {
        k.extend_from_slice(&u.to_le_bytes());
    }
    k
}

/// A directory **value** (entry type `2`, 72 bytes).
fn dir_value(object_id: u64, cre: u64, modi: u64, mch: u64, acc: u64, attr: u32) -> Vec<u8> {
    let mut v = vec![0u8; 72];
    v[0..8].copy_from_slice(&object_id.to_le_bytes());
    v[16..24].copy_from_slice(&cre.to_le_bytes());
    v[24..32].copy_from_slice(&modi.to_le_bytes());
    v[32..40].copy_from_slice(&mch.to_le_bytes());
    v[40..48].copy_from_slice(&acc.to_le_bytes());
    v[64..68].copy_from_slice(&attr.to_le_bytes());
    v
}

/// A file **value** (entry type `1`, 128-byte embedded-node header).
#[allow(clippy::too_many_arguments)]
fn file_value(
    cre: u64,
    modi: u64,
    mch: u64,
    acc: u64,
    attr: u32,
    size: u64,
    alloc: u64,
) -> Vec<u8> {
    let mut v = vec![0u8; 128];
    v[0..8].copy_from_slice(&cre.to_le_bytes());
    v[8..16].copy_from_slice(&modi.to_le_bytes());
    v[16..24].copy_from_slice(&mch.to_le_bytes());
    v[24..32].copy_from_slice(&acc.to_le_bytes());
    v[32..36].copy_from_slice(&attr.to_le_bytes());
    v[64..72].copy_from_slice(&size.to_le_bytes());
    v[72..80].copy_from_slice(&alloc.to_le_bytes());
    v
}

// FILETIME constants (100-ns ticks since 1601-01-01); the exact epoch is not
// interpreted by P2 — the values round-trip verbatim.
const FT_CRE: u64 = 133_931_520_000_000_000;
const FT_MOD: u64 = 133_931_520_100_000_000;
const FT_MCH: u64 = 133_931_520_200_000_000;
const FT_ACC: u64 = 133_931_520_300_000_000;

/// The minted directory as a synthetic page: `dir_a` (dir, obj id 0x701),
/// `known1.txt` (file, 13 bytes) and `nested` (dir). Mirrors the on-volume
/// root-directory listing (the reachability wall keeps this synthetic).
fn minted_root_page() -> Vec<u8> {
    let rows = vec![
        (
            dir_entry_key(2, "dir_a"),
            dir_value(0x701, FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x10),
        ),
        (
            dir_entry_key(1, "known1.txt"),
            file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 13, 4096),
        ),
        (
            dir_entry_key(2, "nested"),
            dir_value(0x702, FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x10),
        ),
    ];
    build_minstore_page(0, false, &rows)
}

// ── Directory-index row parsing ──────────────────────────────────────────────

#[test]
fn parse_directory_lists_names_and_kinds() {
    let page = minted_root_page();
    let entries: Vec<DirEntry> = parse_directory(&page).expect("directory page parses");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"dir_a"), "dir_a listed");
    assert!(names.contains(&"known1.txt"), "known1.txt listed");
    assert!(names.contains(&"nested"), "nested listed");

    let dir_a = entries.iter().find(|e| e.name == "dir_a").unwrap();
    assert!(dir_a.is_directory, "dir_a is a directory");
    assert_eq!(dir_a.object_id, Some(0x701), "dir_a child object id");

    let known1 = entries.iter().find(|e| e.name == "known1.txt").unwrap();
    assert!(!known1.is_directory, "known1.txt is a file");
    assert_eq!(known1.object_id, None, "a file has no child object id");
}

#[test]
fn parse_directory_decodes_utf16_names_including_non_ascii() {
    // A Unicode name (é and a CJK codepoint) must decode via UTF-16LE.
    let rows = vec![(
        dir_entry_key(1, "café_文書.txt"),
        file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 1, 4096),
    )];
    let page = build_minstore_page(0, false, &rows);
    let entries = parse_directory(&page).expect("parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "café_文書.txt", "UTF-16LE name decoded");
}

#[test]
fn parse_directory_skips_base_and_name_records() {
    // Base (0x0010) and name (0x0020) records are not directory *entries* — only
    // 0x0030 entry records list children. A page mixing them yields only the
    // entry rows.
    let rows = vec![
        (0x0010u16.to_le_bytes().to_vec(), vec![0u8; 8]), // base record
        (
            {
                let mut k = 0x0020u16.to_le_bytes().to_vec();
                k.extend_from_slice(&[0u8; 22]);
                k
            },
            vec![0u8; 16],
        ), // name record
        (
            dir_entry_key(1, "only.txt"),
            file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 5, 4096),
        ),
    ];
    let page = build_minstore_page(0, false, &rows);
    let entries = parse_directory(&page).expect("parses");
    assert_eq!(entries.len(), 1, "only the entry record is a DirEntry");
    assert_eq!(entries[0].name, "only.txt");
}

// ── File / directory metadata ────────────────────────────────────────────────

#[test]
fn file_metadata_carries_size_timestamps_and_flags() {
    let page = minted_root_page();
    let entries = parse_directory(&page).expect("parses");
    let known1 = entries.iter().find(|e| e.name == "known1.txt").unwrap();
    let md: &FileMetadata = known1.metadata.as_ref().expect("file has metadata");
    assert!(!md.is_directory);
    assert_eq!(md.size, 13, "logical size (bytes written)");
    assert_eq!(md.allocated, 4096, "allocated size (one cluster)");
    assert_eq!(md.created, FT_CRE, "creation FILETIME");
    assert_eq!(md.modified, FT_MOD, "modification FILETIME");
    assert_eq!(md.changed, FT_MCH, "metadata-change FILETIME");
    assert_eq!(md.accessed, FT_ACC, "access FILETIME");
}

#[test]
fn directory_metadata_has_no_data_size_but_carries_timestamps() {
    let page = minted_root_page();
    let entries = parse_directory(&page).expect("parses");
    let dir_a = entries.iter().find(|e| e.name == "dir_a").unwrap();
    let md = dir_a.metadata.as_ref().expect("dir has metadata");
    assert!(md.is_directory);
    assert_eq!(md.size, 0, "a directory has no data size");
    assert_eq!(md.created, FT_CRE);
    assert_eq!(md.modified, FT_MOD);
}

// ── Image-level list_dir over an object table (resident-region resolution) ───

#[test]
fn list_dir_resolves_object_id_through_object_table_to_a_resident_page() {
    // Assemble a tiny in-memory image: an object table whose 0x600 entry points
    // at a resident block, and the directory page at that block. Proves the
    // list_dir(image, object_id) path end to end (object table -> block ->
    // resident offset -> directory rows), independent of the (unreachable)
    // real-volume virtual addressing.
    let dir_page = minted_root_page();
    // Place the directory page at cluster 8 of the image; its resident block
    // number therefore equals 8 (low band: block N < 65536 maps to cluster N).
    let dir_cluster = 8u64;
    let image_len = (dir_cluster as usize + 4) * CLUSTER; // room for the 16 KiB page
    let mut image = vec![0u8; image_len.max(64 * CLUSTER)];
    // Object table at cluster 56 (the real-volume convention), mapping 0x600 ->
    // block 8.
    let ot_page = build_object_tree(&[(REFS_ROOT_DIRECTORY_ID, dir_cluster)]);
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);
    let d_off = dir_cluster as usize * CLUSTER;
    image[d_off..d_off + PAGE].copy_from_slice(&dir_page);

    let entries =
        list_dir(&image, REFS_ROOT_DIRECTORY_ID).expect("list_dir resolves the resident directory");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"dir_a"));
    assert!(names.contains(&"known1.txt"));
    assert!(names.contains(&"nested"));
}

#[test]
fn list_dir_unresolved_virtual_block_is_a_loud_named_error() {
    // If the object table points 0x600 at a block that is NOT physically
    // resident (the real-volume situation — a virtual address), list_dir must
    // fail LOUD with the offending block number, never a silent empty listing.
    let virtual_block = 34_494_087_168u64;
    let ot_page = build_object_tree(&[(REFS_ROOT_DIRECTORY_ID, virtual_block)]);
    let mut image = vec![0u8; 64 * CLUSTER];
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);

    let err = list_dir(&image, REFS_ROOT_DIRECTORY_ID).unwrap_err();
    match err {
        RefsError::UnresolvedVirtualBlock { block } => {
            assert_eq!(block, virtual_block, "the offending virtual block is named");
        }
        other => panic!("expected UnresolvedVirtualBlock, got {other:?}"),
    }
}

#[test]
fn list_dir_missing_object_id_is_a_loud_named_error() {
    // An object id absent from the object table is a named error, not a silent
    // empty listing (fail-loud, show the missing id).
    let ot_page = build_object_tree(&[(0x777, 8)]);
    let mut image = vec![0u8; 64 * CLUSTER];
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);
    let err = list_dir(&image, REFS_ROOT_DIRECTORY_ID).unwrap_err();
    match err {
        RefsError::ObjectIdNotFound { object_id } => {
            assert_eq!(object_id, REFS_ROOT_DIRECTORY_ID, "the missing id is named");
        }
        other => panic!("expected ObjectIdNotFound, got {other:?}"),
    }
}

// ── Path resolution ──────────────────────────────────────────────────────────

#[test]
fn find_by_path_resolves_a_nested_path() {
    // Build an image with: root (0x600) -> dir_a (0x701) -> known1.txt (file).
    // find_by_path("/dir_a/known1.txt") must descend the directory B+trees and
    // return the file metadata.
    let mut image = vec![0u8; 128 * CLUSTER];

    // Root directory page at cluster 8: contains dir_a (-> obj 0x701).
    let root_rows = vec![(
        dir_entry_key(2, "dir_a"),
        dir_value(0x701, FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x10),
    )];
    let root_page = build_minstore_page(0, false, &root_rows);
    let root_cluster = 8u64;
    let ro = root_cluster as usize * CLUSTER;
    image[ro..ro + PAGE].copy_from_slice(&root_page);

    // dir_a directory page at cluster 12: contains known1.txt (file, 13 bytes).
    let dira_rows = vec![(
        dir_entry_key(1, "known1.txt"),
        file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 13, 4096),
    )];
    let dira_page = build_minstore_page(0, false, &dira_rows);
    let dira_cluster = 12u64;
    let do_ = dira_cluster as usize * CLUSTER;
    image[do_..do_ + PAGE].copy_from_slice(&dira_page);

    // Object table at cluster 56: 0x600 -> block 8 (root), 0x701 -> block 12.
    let ot_page = build_object_tree(&[
        (REFS_ROOT_DIRECTORY_ID, root_cluster),
        (0x701, dira_cluster),
    ]);
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);

    let (obj_ref, md) = find_by_path(&image, "/dir_a/known1.txt").expect("nested path resolves");
    assert_eq!(md.size, 13, "resolved file size");
    assert!(!md.is_directory);
    // The object_ref is the id of the containing directory (0x701) — a stable
    // handle into the object table for a follow-on read.
    assert_eq!(obj_ref, 0x701, "object ref = containing directory id");
}

#[test]
fn find_by_path_unknown_component_returns_none() {
    let mut image = vec![0u8; 64 * CLUSTER];
    let root_page = minted_root_page();
    let ro = 8 * CLUSTER;
    image[ro..ro + PAGE].copy_from_slice(&root_page);
    let ot_page = build_object_tree(&[(REFS_ROOT_DIRECTORY_ID, 8)]);
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);
    // "does_not_exist" is not in the root listing.
    assert!(find_by_path(&image, "/does_not_exist").is_none());
}

#[test]
fn find_by_path_root_metadata_is_none() {
    // "/" has no file record (it is the tree root itself) — None, not a panic.
    let mut image = vec![0u8; 64 * CLUSTER];
    let ot_page = build_object_tree(&[(REFS_ROOT_DIRECTORY_ID, 8)]);
    let ot_off = 56 * CLUSTER;
    image[ot_off..ot_off + PAGE].copy_from_slice(&ot_page);
    assert!(find_by_path(&image, "/").is_none());
}

// ── Robustness (Paranoid Gatekeeper) ─────────────────────────────────────────

#[test]
fn lying_name_length_never_over_reads() {
    // An entry record whose key claims a huge name must yield only in-bounds
    // bytes (the Minstore layer clamps the key span) and never panic.
    let mut page = build_minstore_page(
        0,
        false,
        &[(
            dir_entry_key(1, "a.txt"),
            file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 1, 4096),
        )],
    );
    // Corrupt the first record's key length to a huge value (record header key
    // size @ rec+6). The record starts at node_hdr+32 = 0x120.
    let rec = 0x120usize;
    page[rec + 6..rec + 8].copy_from_slice(&0xfff0u16.to_le_bytes());
    // Must not panic; parse_directory returns whatever fits.
    let _ = parse_directory(&page);
}

#[test]
fn truncated_directory_page_never_panics() {
    let page = minted_root_page();
    for len in [0usize, 4, 80, 0x100, 0x120, 0x2000, PAGE - 1] {
        let _ = parse_directory(&page[..len.min(page.len())]);
    }
}

#[test]
fn odd_length_utf16_name_does_not_panic() {
    // A name whose byte length is odd (a truncated final code unit) must decode
    // losslessly-or-lossily without panicking.
    let mut k = 0x0030u16.to_le_bytes().to_vec();
    k.extend_from_slice(&1u16.to_le_bytes()); // file
    k.extend_from_slice(&[0x41, 0x00, 0x42]); // "A" then a dangling 0x42
    let rows = vec![(k, file_value(FT_CRE, FT_MOD, FT_MCH, FT_ACC, 0x20, 1, 4096))];
    let page = build_minstore_page(0, false, &rows);
    let entries = parse_directory(&page).expect("parses");
    assert_eq!(entries.len(), 1, "the entry is still listed");
    assert!(entries[0].name.starts_with('A'), "the valid prefix decodes");
}

// ── Object-tree builder (shared with the P1 layout) ──────────────────────────

/// A synthetic object-tree leaf whose rows are `(object_id, root_block_number)`
/// — identical to the P1 test builder so list_dir consumes a faithful table.
fn build_object_tree(entries: &[(u64, u64)]) -> Vec<u8> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .map(|(oid, root)| {
            let mut key = vec![0u8; 16];
            key[8..16].copy_from_slice(&oid.to_le_bytes());
            let mut val = vec![0u8; 48 + 32];
            val[32..40].copy_from_slice(&root.to_le_bytes());
            (key, val)
        })
        .collect();
    build_minstore_page(0, false, &rows)
}

// ── Env-gated real-volume cross-check: the honest reachability wall ──────────

/// On the real minted v3.14 volume the root directory (`0x600`) tree is **not**
/// physically resident in the 16 MiB partition head — its object-tree branch
/// points at a virtual block outside the physical partition. `list_dir(0x600)`
/// must therefore fail LOUD with [`RefsError::UnresolvedVirtualBlock`] (or, if
/// the leaf object table lacks 0x600 in the resident band,
/// [`RefsError::ObjectIdNotFound`]) — never a faked listing. This is the
/// container-table phase's job; P2 reports the wall.
#[test]
fn real_volume_root_directory_is_unreachable_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE") else {
        eprintln!("REFS_TIER2_ORACLE not set — skipping real-volume directory reachability check");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE");

    // The resident leaf object table (cluster 56) does NOT contain 0x600; the
    // 0x600 mapping lives in the object-tree branch (cluster 40) whose children
    // are virtual blocks. Either way, no resident directory page exists for the
    // root, so list_dir must fail loud (not return an empty Vec).
    let ot_page = &data[56 * CLUSTER..56 * CLUSTER + PAGE];
    let ot = ObjectTable::parse(ot_page, 0).expect("real object table parses");
    // Doer-Checker: 0x600 is genuinely absent from the resident leaf table.
    assert!(
        ot.lookup(REFS_ROOT_DIRECTORY_ID).is_none(),
        "0x600 is not in the resident leaf object table (it is behind the virtual branch)"
    );

    match list_dir(&data, REFS_ROOT_DIRECTORY_ID) {
        Ok(entries) => panic!(
            "expected the root directory to be unreachable on the real oracle, \
             got a listing of {} entries — a faked listing must never be produced",
            entries.len()
        ),
        Err(RefsError::UnresolvedVirtualBlock { .. } | RefsError::ObjectIdNotFound { .. }) => {
            // The honest wall: the container table is needed to resolve 0x600's
            // virtual block to a physical location (a later phase).
        }
        Err(other) => panic!("expected the reachability wall, got {other:?}"),
    }
}
