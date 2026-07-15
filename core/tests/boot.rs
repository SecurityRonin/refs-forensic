//! P0 tests for the ReFS boot VBR + superblock + version detection, driven over
//! the committed always-on fixture and (env-gated) the full 16 MiB partition
//! head.
//!
//! Fixture provenance (Tier-2 self-mint — see tests/data/README.md): a ReFS
//! v3.14 Dev Drive minted on a Parallels Windows 11 Pro VM (build 26200).
//! Ground truth is `fsutil fsinfo refsinfo` on the live Windows driver:
//!   REFS Volume Version : 3.14
//!   REFS Volume Serial  : 0x4e32fc4432fc3317
//!   Bytes Per Sector    : 512
//!   Bytes Per Cluster   : 4096  (=> 8 sectors per cluster)
//!
//! ReFS is undocumented (no official Microsoft on-disk spec); every structural
//! fact is reverse-engineered (libyal libfsrefs, Prade). Structural metadata is
//! **Tier-2 at best** — there is no ground-truth forensic corpus.

use refs_core::{
    BootSector, MetadataBlockRef, Superblock, REFS_FSRS, REFS_SIGNATURE, REFS_SUPERBLOCK_CLUSTER,
    SUPB_SIGNATURE,
};

/// The committed always-on fixture: boot VBR (cluster 0) through the SUPB
/// superblock (cluster 30), 128 KiB. Excluded from the published tarball.
const BOOT_SB: &[u8] = include_bytes!("../../tests/data/refs_boot_superblock.bin");

// ── Boot VBR / FS-recognition structure ─────────────────────────────────────

#[test]
fn boot_signature_and_fsrs_validate() {
    let boot = BootSector::parse(BOOT_SB).expect("valid ReFS boot VBR must parse");
    assert_eq!(&boot.signature, REFS_SIGNATURE, "FS signature at offset 3");
    assert_eq!(&boot.fsrs, REFS_FSRS, "FSRS identifier at offset 16");
}

#[test]
fn boot_geometry_matches_fsutil_ground_truth() {
    let boot = BootSector::parse(BOOT_SB).expect("parse");
    // Bytes-per-sector 512, sectors-per-cluster 8 => cluster 4096 (fsutil).
    assert_eq!(boot.bytes_per_sector, 512, "Bytes Per Sector (fsutil)");
    assert_eq!(
        boot.sectors_per_cluster, 8,
        "sectors/cluster => 4096-byte cluster"
    );
    assert_eq!(boot.cluster_size(), 4096, "Bytes Per Cluster (fsutil)");
    // Number of sectors read directly from the minted volume.
    assert_eq!(boot.num_sectors, 125_698_048, "Number Sectors");
    // Volume serial number must equal fsutil's 0x4e32fc4432fc3317 exactly.
    assert_eq!(
        boot.volume_serial, 0x4e32_fc44_32fc_3317,
        "REFS Volume Serial Number (fsutil)"
    );
}

#[test]
fn boot_version_is_3_14() {
    let boot = BootSector::parse(BOOT_SB).expect("parse");
    assert_eq!(boot.major_version, 3, "Major format version (fsutil 3.x)");
    assert_eq!(boot.minor_version, 14, "Minor format version (fsutil 3.14)");
    assert!(boot.is_v3(), "3.14 is a v3.x volume");
}

// ── Fail-loud gates (the RESEARCH.md "never silently misparse" mandate) ──────

#[test]
fn bad_signature_names_the_bytes() {
    let mut bad = BOOT_SB.to_vec();
    bad[3..11].copy_from_slice(b"NTFS\x00\x00\x00\x00");
    let err = BootSector::parse(&bad).unwrap_err();
    match err {
        refs_core::RefsError::BadSignature { found } => {
            assert_eq!(
                &found, b"NTFS\x00\x00\x00\x00",
                "error carries the offending bytes"
            );
        }
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn bad_fsrs_names_the_bytes() {
    let mut bad = BOOT_SB.to_vec();
    bad[16..20].copy_from_slice(b"XXXX");
    let err = BootSector::parse(&bad).unwrap_err();
    match err {
        refs_core::RefsError::BadFsrs { found, .. } => {
            assert_eq!(&found, b"XXXX", "error carries the offending FSRS bytes");
        }
        other => panic!("expected BadFsrs, got {other:?}"),
    }
}

#[test]
fn unsupported_v1_major_is_rejected_with_the_version_bytes() {
    // Rewrite the major version to 1 (Server 2012 / 8.1 legacy layout).
    let mut v1 = BOOT_SB.to_vec();
    v1[40] = 1;
    v1[41] = 2;
    let boot = BootSector::parse(&v1).expect("boot still parses; version check is separate");
    let err = boot.require_v3().unwrap_err();
    match err {
        refs_core::RefsError::UnsupportedVersion { major, minor } => {
            assert_eq!(major, 1, "the real major version is surfaced");
            assert_eq!(minor, 2, "the real minor version is surfaced");
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn truncated_boot_never_panics() {
    // A hostile/truncated image must fail loud, never panic.
    for len in [0usize, 1, 3, 10, 16, 40, 41, 63, 71] {
        let short = &BOOT_SB[..len.min(BOOT_SB.len())];
        let _ = BootSector::parse(short); // must return Err, must not panic
    }
    // A garbage buffer of boot length must also be handled.
    let garbage = vec![0xAAu8; 512];
    let _ = BootSector::parse(&garbage);
}

// ── Superblock (SUPB) location + metadata-block header ───────────────────────

#[test]
fn superblock_locates_at_cluster_30() {
    let boot = BootSector::parse(BOOT_SB).expect("parse");
    // ReFS places the primary superblock at a fixed cluster (30) from the start
    // of the volume — the well-known reverse-engineered convention.
    assert_eq!(REFS_SUPERBLOCK_CLUSTER, 30);
    let sb_off = boot.superblock_offset();
    assert_eq!(
        sb_off,
        30 * 4096,
        "superblock byte offset = cluster 30 * 4096"
    );
    assert_eq!(sb_off, 0x1e000);
}

#[test]
fn superblock_parses_and_is_self_describing() {
    let boot = BootSector::parse(BOOT_SB).expect("parse");
    let sb = Superblock::parse_at(BOOT_SB, boot.superblock_offset())
        .expect("SUPB superblock must parse at cluster 30");
    assert_eq!(&sb.block.signature, SUPB_SIGNATURE, "SUPB block signature");
    // The v3 metadata block header is self-describing: it records its own block
    // number. For the superblock at cluster 30 that first block number is 30.
    assert_eq!(
        sb.block.block_number, 30,
        "self-describing block number == 30"
    );
}

#[test]
fn superblock_bad_signature_is_fail_loud() {
    let mut bad = BOOT_SB.to_vec();
    // Corrupt the SUPB signature at cluster 30.
    bad[0x1e000..0x1e000 + 4].copy_from_slice(b"ZZZZ");
    let err = Superblock::parse_at(&bad, 0x1e000).unwrap_err();
    match err {
        refs_core::RefsError::BadBlockSignature {
            found,
            expected,
            offset,
            ..
        } => {
            assert_eq!(&found, b"ZZZZ");
            assert_eq!(expected, "SUPB");
            assert_eq!(offset, 0x1e000);
        }
        other => panic!("expected BadBlockSignature, got {other:?}"),
    }
}

#[test]
fn metadata_block_ref_truncated_never_panics() {
    for len in [0usize, 4, 32, 47] {
        let short = &BOOT_SB[0x1e000..0x1e000 + len.min(48)];
        let _ = MetadataBlockRef::parse(short, "SUPB", 0x1e000);
    }
}

// ── Env-gated full-image cross-check (Tier-2, structural) ────────────────────

/// Point `REFS_TIER2_ORACLE` at the full 16 MiB partition head
/// (`tests/data/refs_partition_head.bin`, gitignored) to re-run the boot +
/// superblock parse against the whole minted region.
#[test]
fn full_partition_head_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE") else {
        eprintln!("REFS_TIER2_ORACLE not set — skipping full-image cross-check");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE image");
    let boot = BootSector::parse(&data).expect("full-image boot parse");
    assert_eq!(boot.major_version, 3);
    assert_eq!(boot.minor_version, 14);
    assert_eq!(boot.volume_serial, 0x4e32_fc44_32fc_3317);
    let sb = Superblock::parse_at(&data, boot.superblock_offset()).expect("full-image SUPB");
    assert_eq!(sb.block.block_number, 30);
}
