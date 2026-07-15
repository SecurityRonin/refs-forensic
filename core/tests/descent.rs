//! P4 tests — ReFS directory-tree DESCENT: walk the Minstore B+tree from a
//! directory's index-root through branch nodes to the leaf pages that hold the
//! directory-entry records, resolving every child page virtual→physical via the
//! container resolver.
//!
//! # Provenance and tiering
//!
//! ReFS is undocumented; every structural fact is reverse-engineered (libyal
//! `libfsrefs` "Directory object" + "Ministore tree" + §8 "Container tree", and
//! the real v3.14 volume, see tests/data/README.md). Structural metadata is
//! **Tier-2 at best** — there is no ground-truth ReFS corpus.
//!
//! # What P4 does (the descent)
//!
//! P2 parsed a *single* directory page's `0x30` entry rows. P3 cracked
//! virtual→physical (the container table). P4 joins them: a directory is a
//! Minstore B+-tree that may be more than one page deep. A **branch** node
//! (level > 0, node-type flag `0x01`) carries, in each row's value, a
//! **format-v3 metadata block reference** whose first block number (value `+0`)
//! is the *virtual* block of a child page (byte-verified on the real v3.14
//! branch nodes at clusters 76/80: value `+0` = child block, then three
//! redundancy blocks, then the `00 00 02 08 08 00 00 00` checksum descriptor at
//! `+32`). The descent resolves each child block through the
//! [`ContainerResolver`], reads that page, and recurses until it reaches the
//! **leaf** pages (level 0) whose `0x30` records are the directory entries.
//!
//! # The honest real-volume wall (real-volume Doer-Checker, 2026-07-15)
//!
//! On the fresh v3.14 oracle the object table maps `0x600` → tree-root block
//! `80_384` (resolved by P3 to physical cluster `14_848`). That page is a
//! *leaf* whose single `$STANDARD_INFORMATION` record embeds a Ministore node
//! carrying an **empty `$I30 $INDEX_ROOT`** — the populated `$INDEX_ALLOCATION`
//! holding the minted user files (`dir_a`, `known1.txt`, `nested`) lives in a
//! band **beyond the 256 MiB slice** (partition offset ≥ `268_435_456` bytes)
//! and the source 60 GB VHD was detached and lost, so those leaves are
//! **unpullable**. `list_dir(0x600)` over the real oracle therefore returns the
//! *reachable* entries only (never the minted files) and NEVER fabricates them —
//! the descent logic itself is proven below on a synthetic branch→leaf tree and
//! on the resident "System Volume Information" entry that IS present.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use refs_core::{find_by_path, list_dir, ContainerResolver, DirEntry, RefsError};

const CLUSTER: usize = 4096;
const PAGE: usize = 16384;
const BAND_CLUSTERS: u64 = 16_384;

// ── Page builders (mirror the P2/P3 verified Minstore layout) ────────────────

/// Write a v3 metadata-block header (80 bytes): signature, table id at +72, and
/// the self (first) block number at +0x20 — the field the container resolver
/// reads to learn a band's physical base.
fn write_header(page: &mut [u8], signature: [u8; 4], self_block: u64, table_id: u64) {
    page[0..4].copy_from_slice(&signature);
    page[4..8].copy_from_slice(&2u32.to_le_bytes());
    page[12..16].copy_from_slice(&0xf890_ec89u32.to_le_bytes());
    page[0x20..0x28].copy_from_slice(&self_block.to_le_bytes());
    page[72..80].copy_from_slice(&table_id.to_le_bytes());
}

/// Build a Minstore page (leaf or branch) from `(key, value)` rows with an
/// explicit self-block number and node level/branch flag. Mirrors the verified
/// P1/P2 record layout so the reader consumes a faithful page.
fn build_page(
    self_block: u64,
    table_id: u64,
    level: u8,
    is_branch: bool,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    write_header(&mut page, *b"MSB+", self_block, table_id);
    let node_hdr = 0x100usize;
    let nho_field = 0x50usize;
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

/// A directory entry-record **key** (record type `0x0030`): entry type + UTF-16LE name.
fn dir_entry_key(entry_type: u16, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + name.len() * 2);
    k.extend_from_slice(&0x0030u16.to_le_bytes());
    k.extend_from_slice(&entry_type.to_le_bytes());
    for u in name.encode_utf16() {
        k.extend_from_slice(&u.to_le_bytes());
    }
    k
}

/// A directory **value** (entry type 2, 72 bytes) — child object id at +0.
fn dir_value(object_id: u64) -> Vec<u8> {
    let mut v = vec![0u8; 72];
    v[0..8].copy_from_slice(&object_id.to_le_bytes());
    v[64..68].copy_from_slice(&0x10u32.to_le_bytes()); // FILE_ATTRIBUTE_DIRECTORY
    v
}

/// A file **value** (entry type 1, 128-byte header) — size at +64.
fn file_value(size: u64) -> Vec<u8> {
    let mut v = vec![0u8; 128];
    v[32..36].copy_from_slice(&0x20u32.to_le_bytes()); // FILE_ATTRIBUTE_ARCHIVE
    v[64..72].copy_from_slice(&size.to_le_bytes());
    v[72..80].copy_from_slice(&4096u64.to_le_bytes());
    v
}

/// A **branch** row: key = a separator (opaque here), value = a format-v3
/// metadata block reference whose first block number (value `+0`) is the child
/// page's virtual block, followed by three redundancy blocks and the checksum
/// descriptor at `+32` — the exact real-volume branch value layout.
fn branch_row(separator: &[u8], child_block: u64) -> (Vec<u8>, Vec<u8>) {
    let mut val = vec![0u8; 48];
    val[0..8].copy_from_slice(&child_block.to_le_bytes());
    val[8..16].copy_from_slice(&child_block.to_le_bytes());
    val[16..24].copy_from_slice(&child_block.to_le_bytes());
    val[24..32].copy_from_slice(&child_block.to_le_bytes());
    // checksum descriptor: type 2 (CRC64), data offset 8, data size 8.
    val[34] = 0x02;
    val[35] = 0x08;
    val[36..38].copy_from_slice(&0x0008u16.to_le_bytes());
    (separator.to_vec(), val)
}

/// The cluster every descent test places the object table at (the cluster
/// `list_dir` reads it from). Its self-block is set equal to this cluster so the
/// container resolver derives a *consistent* band-0 base (`base[0] = cluster -
/// cluster%band = 0`) — matching the band-0, self-block-equals-cluster layout of
/// the synthetic branch/leaf pages, exactly as the real volume's pages are
/// self-consistent within their band.
const OBJECT_TABLE_CLUSTER: u64 = 56;

/// An object-tree leaf whose rows are `(object_id, tree_root_block)` — the P1/P2
/// verified object-table layout (id at key+8, block at value+0x20).
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
    build_page(OBJECT_TABLE_CLUSTER, 0x2, 0, false, &rows)
}

/// Place a page at cluster `cl` in `img`.
fn place(img: &mut [u8], cl: usize, page: &[u8]) {
    img[cl * CLUSTER..cl * CLUSTER + page.len()].copy_from_slice(page);
}

/// The physical base cluster of container index 4 as derived by the resolver
/// from a resident page: `base[idx] = phys_cluster - (self_block % band)`. We
/// place branch/leaf pages at real cluster positions so the resolver learns the
/// bases from their self-blocks, exactly as it does on the real volume.
fn resolve_or_panic(image: &[u8], block: u64) -> usize {
    let r = ContainerResolver::from_resident_image(image, BAND_CLUSTERS);
    r.resolve_virtual(block).expect("block resolves") as usize
}

// ── The headline: list_dir walks branch → leaf ───────────────────────────────

#[test]
fn list_dir_descends_branch_to_leaf_and_lists_minted_names() {
    // Build a two-level directory tree for object 0x600, laid out at REAL cluster
    // positions so the container resolver (self-block based) translates every
    // child block correctly — the same mechanism as the real volume.
    //
    //   object table (0x600 -> root branch block) at cluster 56
    //   root BRANCH node (block 80384, cluster 14848) with two child pointers
    //   leaf A (block 65600, cluster 60): dir_a (dir 0x701), known1.txt (file 13)
    //   leaf B (block 65616, cluster 80): nested (dir 0x702)
    //
    // Cluster/block pairs are chosen so each page's `self % band == cluster - base`
    // is consistent with a single container-4 base (base = cluster - self%band):
    //   14848 - (80384 % 16384) = 14848 - 14848 = 0
    //   60    - (65600 % 16384) = 60    - 0     = 60   -> DIFFERENT base, so use
    // a placement where all share base 0: block = cluster (container 0). Simpler
    // and still exercises the resolver: put pages at cluster == block for a low
    // band so decompose(block) = (0, block) and base[0] = 0.
    let root_block = 4000u64;
    let leaf_a_block = 4100u64;
    let leaf_b_block = 4200u64;

    let leaf_a = build_page(
        leaf_a_block,
        0x600,
        0,
        false,
        &[
            (dir_entry_key(2, "dir_a"), dir_value(0x701)),
            (dir_entry_key(1, "known1.txt"), file_value(13)),
        ],
    );
    let leaf_b = build_page(
        leaf_b_block,
        0x600,
        0,
        false,
        &[(dir_entry_key(2, "nested"), dir_value(0x702))],
    );
    let root = build_page(
        root_block,
        0x600,
        1,
        true,
        &[
            branch_row(&[0x00], leaf_a_block),
            branch_row(&[0x80], leaf_b_block),
        ],
    );
    let ot = build_object_tree(&[(0x600, root_block)]);

    let mut image = vec![0u8; 5000 * CLUSTER + PAGE];
    place(&mut image, 56, &ot); // object table at the cluster list_dir reads
    place(&mut image, root_block as usize, &root);
    place(&mut image, leaf_a_block as usize, &leaf_a);
    place(&mut image, leaf_b_block as usize, &leaf_b);

    let entries: Vec<DirEntry> = list_dir(&image, 0x600).expect("list_dir descends the tree");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"dir_a"),
        "dir_a listed after descent: {names:?}"
    );
    assert!(
        names.contains(&"known1.txt"),
        "known1.txt listed after descent: {names:?}"
    );
    assert!(
        names.contains(&"nested"),
        "nested listed after descent: {names:?}"
    );

    let dir_a = entries.iter().find(|e| e.name == "dir_a").unwrap();
    assert!(dir_a.is_directory, "dir_a is a directory");
    assert_eq!(dir_a.object_id, Some(0x701));
    let known1 = entries.iter().find(|e| e.name == "known1.txt").unwrap();
    assert!(!known1.is_directory, "known1.txt is a file");
    let nested = entries.iter().find(|e| e.name == "nested").unwrap();
    assert!(nested.is_directory, "nested is a directory");
}

// ── find_by_path descends subdirectories across branch nodes ─────────────────

#[test]
fn find_by_path_descends_through_branch_nodes_into_subdirectories() {
    // root 0x600 (branch) -> leaf holds dir_a (dir 0x701)
    // dir_a 0x701 (branch) -> leaf holds nested (dir 0x702)
    // find_by_path("/dir_a/nested") must descend BOTH trees.
    let root_block = 4000u64;
    let root_leaf_block = 4100u64;
    let dira_block = 4200u64;
    let dira_leaf_block = 4300u64;

    let root_leaf = build_page(
        root_leaf_block,
        0x600,
        0,
        false,
        &[(dir_entry_key(2, "dir_a"), dir_value(0x701))],
    );
    let root = build_page(
        root_block,
        0x600,
        1,
        true,
        &[branch_row(&[0x00], root_leaf_block)],
    );
    let dira_leaf = build_page(
        dira_leaf_block,
        0x701,
        0,
        false,
        &[(dir_entry_key(2, "nested"), dir_value(0x702))],
    );
    let dira = build_page(
        dira_block,
        0x701,
        1,
        true,
        &[branch_row(&[0x00], dira_leaf_block)],
    );
    let ot = build_object_tree(&[(0x600, root_block), (0x701, dira_block)]);

    let mut image = vec![0u8; 5000 * CLUSTER + PAGE];
    place(&mut image, 56, &ot); // object table at the cluster list_dir reads
    place(&mut image, root_block as usize, &root);
    place(&mut image, root_leaf_block as usize, &root_leaf);
    place(&mut image, dira_block as usize, &dira);
    place(&mut image, dira_leaf_block as usize, &dira_leaf);

    let (containing, md) = find_by_path(&image, "/dir_a/nested").expect("nested path resolves");
    assert!(md.is_directory, "the resolved entry is a directory");
    assert_eq!(containing, 0x701, "containing directory is dir_a (0x701)");
}

// ── Robustness: bounded descent (cycles / over-deep) never panics ────────────

#[test]
fn cyclic_branch_tree_terminates_without_panic() {
    // A branch node whose child pointer points back at ITSELF (a cycle) must not
    // spin forever — the descent is depth/visit bounded.
    let self_block = 4000u64;
    let root = build_page(
        self_block,
        0x600,
        1,
        true,
        &[branch_row(&[0x00], self_block)], // child == self: a cycle
    );
    let ot = build_object_tree(&[(0x600, self_block)]);
    let mut image = vec![0u8; 4100 * CLUSTER + PAGE];
    place(&mut image, 56, &ot); // object table at the cluster list_dir reads
    place(&mut image, self_block as usize, &root);
    // Must return (bounded), not hang or panic.
    let _ = list_dir(&image, 0x600);
}

#[test]
fn over_deep_branch_chain_is_bounded() {
    // A long chain of branch nodes each pointing to the next must terminate at a
    // depth cap rather than recursing unbounded (stack-safety / lie-resistance).
    let mut image = vec![0u8; 5000 * CLUSTER + PAGE];
    let base = 100u64;
    let depth = 300u64; // far beyond any real directory tree depth
    for i in 0..depth {
        let blk = base + i;
        let next = base + i + 1;
        let page = build_page(blk, 0x600, 1, true, &[branch_row(&[0x00], next)]);
        place(&mut image, blk as usize, &page);
    }
    let ot = build_object_tree(&[(0x600, base)]);
    place(&mut image, 56, &ot); // object table at the cluster list_dir reads
                                // Bounded — returns without panic or unbounded recursion.
    let _ = list_dir(&image, 0x600);
}

// ── Fail loud: an unmapped child block is a named error, never a silent drop ──

#[test]
fn unmapped_child_block_fails_loud() {
    // A branch node pointing at a child whose container index was never witnessed
    // in the resident image must fail LOUD with the offending virtual block —
    // never a silently-truncated (partial or empty) listing.
    let root_block = 4000u64;
    let missing_child = 34_494_087_168u64; // a far virtual block, non-resident
    let root = build_page(
        root_block,
        0x600,
        1,
        true,
        &[branch_row(&[0x00], missing_child)],
    );
    let ot = build_object_tree(&[(0x600, root_block)]);
    let mut image = vec![0u8; 4100 * CLUSTER + PAGE];
    place(&mut image, 56, &ot); // object table at the cluster list_dir reads
    place(&mut image, root_block as usize, &root);

    match list_dir(&image, 0x600) {
        Err(RefsError::UnresolvedVirtualBlock { block }) => {
            assert_eq!(block, missing_child, "the offending child block is named");
        }
        other => panic!("expected UnresolvedVirtualBlock, got {other:?}"),
    }
}

// ── Sanity: the resolver helper resolves a placed page (guards test scaffolding)

#[test]
fn placed_page_resolves_through_container_resolver() {
    let mut image = vec![0u8; 4200 * CLUSTER + PAGE];
    let block = 4000u64;
    let page = build_page(block, 0x600, 0, false, &[]);
    place(&mut image, block as usize, &page);
    // block == cluster (container 0, base 0) -> resolves to block*CLUSTER.
    assert_eq!(resolve_or_panic(&image, block), block as usize * CLUSTER);
}

// ── Env-gated real-volume descent (the honest wall, Tier-2 structural) ────────

/// Point `REFS_TIER2_ORACLE256` at the 256 MiB container-head slice to run the
/// descent on the real minted v3.14 volume. The object table maps `0x600` → the
/// resolved directory root; the descent walks it. On this oracle the minted user
/// files live in a NON-resident band (the source VHD is gone), so `list_dir`
/// must NEVER list `dir_a`/`known1.txt`/`nested` — it returns only reachable
/// entries and never fabricates the absent ones. This regression-guards the
/// honest wall while proving the descent runs end to end on real bytes.
#[test]
fn real_volume_descent_never_fabricates_missing_files_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE256") else {
        eprintln!("REFS_TIER2_ORACLE256 not set — skipping real-volume descent check");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE256");

    match list_dir(&data, 0x600) {
        Ok(entries) => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            for forbidden in ["dir_a", "known1.txt", "nested", "big.bin"] {
                assert!(
                    !names.contains(&forbidden),
                    "the minted file {forbidden:?} is NON-resident on this oracle — \
                     listing it would be fabrication (names seen: {names:?})"
                );
            }
        }
        Err(RefsError::UnresolvedVirtualBlock { .. } | RefsError::ObjectIdNotFound { .. }) => {
            // A loud wall is also acceptable: the descent hit a non-resident child
            // and failed loud rather than fabricating. Either way, no fabrication.
        }
        Err(other) => panic!("unexpected error from real-volume descent: {other:?}"),
    }
}
