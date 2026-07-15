//! F-INTEGRITY tests — ReFS structural-anomaly auditing over real resident v3.14
//! metadata plus crafted corruption.
//!
//! # Provenance and tiering
//!
//! ReFS is undocumented; every structural fact is reverse-engineered (libyal
//! `libfsrefs`, Prade + the real v3.14 volume, see tests/data/README.md).
//! Structural metadata is **Tier-2 at best** — there is no ground-truth forensic
//! corpus. Findings are **observations** ("consistent with …"), never verdicts.
//!
//! # Honest CRC scope (the LZNT1-trap the fleet standards warn against)
//!
//! ReFS's whole-block checksum *coverage range* is undocumented in the
//! reverse-engineered references and was not reproduced empirically from the real
//! SUPB (see `refs-core`'s `metablock` docs + tests/data/README.md). So
//! `REFS-METADATA-CRC-MISMATCH` is emitted **only** over a caller-supplied
//! explicit range where the coverage is known/derivable — never auto-fabricated
//! on a clean block. These tests exercise it with a KNOWN range (a self-contained
//! CRC-32C over an explicit span), never by guessing ReFS's own range.

use refs_forensic::{audit_findings, audit_image, AnomalyKind};

/// The committed always-on fixture: boot VBR (cluster 0) through the SUPB
/// superblock (cluster 30), 128 KiB (Tier-2 self-mint).
const BOOT_SB: &[u8] = include_bytes!("../../tests/data/refs_boot_superblock.bin");

// ── Clean-input: a valid resident region emits nothing false ─────────────────

#[test]
fn clean_boot_and_superblock_emit_no_false_anomalies() {
    // The real minted boot VBR + SUPB is a clean region: no bad signature, no
    // impossible geometry. A clean image must yield an empty audit (never a
    // fabricated corruption verdict — the whole point of the CRC-range honesty).
    let anomalies = audit_image(BOOT_SB);
    assert!(
        anomalies.is_empty(),
        "a clean real ReFS region must emit nothing false, got {anomalies:?}"
    );
}

// ── REFS-BOOT-SIGNATURE-INVALID (fail-loud value) ────────────────────────────

#[test]
fn bad_boot_signature_is_detected_with_the_offending_bytes() {
    let mut bad = BOOT_SB.to_vec();
    bad[3..11].copy_from_slice(b"NTFS\x00\x00\x00\x00");
    let anomalies = audit_image(&bad);
    let hit = anomalies
        .iter()
        .find(|a| a.code == "REFS-BOOT-SIGNATURE-INVALID")
        .expect("a corrupt ReFS boot signature must be flagged");
    // The offending bytes are carried in the anomaly (show the value).
    match &hit.kind {
        AnomalyKind::BootSignatureInvalid { found } => {
            assert_eq!(
                found, b"NTFS\x00\x00\x00\x00",
                "the offending bytes are named"
            );
        }
        other => panic!("expected BootSignatureInvalid, got {other:?}"),
    }
    assert_eq!(hit.severity, refs_forensic::Severity::High);
}

// ── REFS-SELF-BLOCK-MISMATCH (relocated / tampered / misparsed page) ─────────

#[test]
fn relocated_self_block_is_detected() {
    // The SUPB at cluster 30 self-records block number 30. Rewrite its
    // self-block-number to a value that no longer equals its actual location →
    // consistent with a relocated/tampered page.
    let mut tampered = BOOT_SB.to_vec();
    let supb = 0x1e000usize; // cluster 30
    tampered[supb + 0x20..supb + 0x28].copy_from_slice(&999u64.to_le_bytes());
    let anomalies = audit_image(&tampered);
    let hit = anomalies
        .iter()
        .find(|a| a.code == "REFS-SELF-BLOCK-MISMATCH")
        .expect("a self-block that disagrees with the block's location must be flagged");
    match &hit.kind {
        AnomalyKind::SelfBlockMismatch {
            recorded, expected, ..
        } => {
            assert_eq!(*recorded, 999, "the recorded (wrong) self-block is named");
            assert_eq!(*expected, 30, "the block's actual location is named");
        }
        other => panic!("expected SelfBlockMismatch, got {other:?}"),
    }
    assert_eq!(hit.severity, refs_forensic::Severity::High);
}

#[test]
fn genuine_superblock_self_block_is_not_flagged() {
    // The real SUPB records self-block 30 at cluster 30 — the self-block matches
    // its location, so it must NOT be flagged as relocated (no false positive).
    let anomalies = audit_image(BOOT_SB);
    assert!(
        !anomalies
            .iter()
            .any(|a| a.code == "REFS-SELF-BLOCK-MISMATCH"),
        "a genuine, matching self-block must not be flagged"
    );
}

// ── REFS-METADATA-CRC-MISMATCH (only over a KNOWN range; never fabricated) ───

#[test]
fn crc_mismatch_flagged_only_over_a_known_range() {
    // Build a self-contained block: bytes [0..N] with a CRC-32C stored so the
    // KNOWN range verifies. audit_crc_range is the range-explicit entry: it flags
    // a mismatch ONLY when the caller pins the coverage range (here we do), and
    // returns None-equivalent (no anomaly) when the range is clean.
    let mut block = vec![0xABu8; 256];
    let good = refs_core::crc32c(&block[0..200]);

    // Clean: the stored CRC matches the range → no anomaly (never fabricated).
    let clean =
        refs_forensic::audit_crc_range(&block, 0, 0, 200, refs_core::crc32c(&block[0..200]));
    assert!(
        clean.is_none(),
        "a verifying CRC range must emit no anomaly"
    );

    // Corrupt: flip a byte inside the covered range → the stored (old) CRC no
    // longer verifies → REFS-METADATA-CRC-MISMATCH over the KNOWN range.
    block[10] ^= 0xFF;
    let dirty = refs_forensic::audit_crc_range(&block, 0, 0, 200, good)
        .expect("a broken CRC over a known range must be flagged");
    assert_eq!(dirty.code, "REFS-METADATA-CRC-MISMATCH");
    assert_eq!(dirty.severity, refs_forensic::Severity::High);
    match dirty.kind {
        AnomalyKind::MetadataCrcMismatch { offset, .. } => assert_eq!(offset, 0),
        other => panic!("expected MetadataCrcMismatch, got {other:?}"),
    }
}

#[test]
fn crc_range_out_of_bounds_never_panics_and_emits_nothing() {
    // An out-of-range coverage span must NOT panic and must NOT fabricate a
    // verdict (the range is unverifiable, so no anomaly — never a false positive).
    let block = vec![0u8; 16];
    assert!(refs_forensic::audit_crc_range(&block, 0, 0, 9_999, 0).is_none());
    assert!(refs_forensic::audit_crc_range(&block, 0, 100, 50, 0).is_none());
}

// ── REFS-IMPOSSIBLE-GEOMETRY (allocation-bomb guard) ─────────────────────────

#[test]
fn impossible_geometry_is_flagged() {
    // Rewrite the boot sector's sectors-per-cluster to an absurd value so the
    // cluster size blows past any sane bound — an allocation-bomb / corruption
    // guard.
    let mut bad = BOOT_SB.to_vec();
    bad[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sectors/cluster
    let anomalies = audit_image(&bad);
    let hit = anomalies
        .iter()
        .find(|a| a.code == "REFS-IMPOSSIBLE-GEOMETRY")
        .expect("absurd geometry must be flagged");
    assert_eq!(hit.severity, refs_forensic::Severity::High);
    match &hit.kind {
        AnomalyKind::ImpossibleGeometry { field, .. } => {
            assert!(!field.is_empty(), "the offending field is named");
        }
        other => panic!("expected ImpossibleGeometry, got {other:?}"),
    }
}

// ── REFS-CHECKPOINT-DIVERGENCE (torn / tampered checkpoint) ──────────────────

#[test]
fn checkpoint_divergence_is_flagged_when_copies_disagree() {
    // The SUPB names its checkpoint block numbers (P1: [157156, 1885500]). ReFS
    // keeps two checkpoint copies; when the two named checkpoint block numbers
    // disagree with an internal-consistency expectation (here: a crafted image
    // where the count field claims copies that do not round-trip) the auditor
    // surfaces REFS-CHECKPOINT-DIVERGENCE. This test drives the synthetic seam:
    // an image whose superblock names ZERO checkpoints is torn (a live volume
    // always keeps at least one).
    let mut torn = BOOT_SB.to_vec();
    let supb = 0x1e000usize;
    // count-of-checkpoint-block-numbers field = block+0x50+0x24 (per checkpoint.rs)
    let count_field = supb + 80 + 0x24;
    torn[count_field..count_field + 4].copy_from_slice(&0u32.to_le_bytes());
    let anomalies = audit_image(&torn);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "REFS-CHECKPOINT-DIVERGENCE"),
        "a superblock naming zero checkpoints is torn — must be flagged, got {anomalies:?}"
    );
}

// ── audit_findings mirrors the fleet: emits forensicnomicon Findings ─────────

#[test]
fn audit_findings_emits_forensicnomicon_findings_with_source() {
    use forensicnomicon::report::Severity;
    let mut bad = BOOT_SB.to_vec();
    bad[3..11].copy_from_slice(b"NTFS\x00\x00\x00\x00");
    let findings = audit_findings(&bad, "volume: REFSTEST");
    let f = findings
        .iter()
        .find(|f| f.code == "REFS-BOOT-SIGNATURE-INVALID")
        .expect("a Finding is emitted");
    assert_eq!(f.severity, Some(Severity::High));
    // The finding is tagged with the producing source (analyzer + scope).
    let src = f.source.as_ref().expect("finding carries its source");
    assert_eq!(src.analyzer, "refs-forensic");
    assert_eq!(src.scope, "volume: REFSTEST");
    // It reads as an observation ("consistent with"), never a verdict.
    assert!(
        f.note.to_lowercase().contains("consistent with")
            || f.note.to_lowercase().contains("not recognized")
            || f.note.to_lowercase().contains("signature"),
        "note is observational: {}",
        f.note
    );
}

// ── Robustness (Paranoid Gatekeeper): malformed input never panics ───────────

#[test]
fn malformed_input_never_panics() {
    for len in [0usize, 1, 3, 10, 16, 40, 72, 0x1e000, 0x1e000 + 40] {
        let short = &BOOT_SB[..len.min(BOOT_SB.len())];
        let _ = audit_image(short); // must not panic
        let _ = audit_findings(short, "scope"); // must not panic
    }
    // Pure garbage of various sizes.
    for size in [0usize, 7, 128, 4096, 20000] {
        let garbage = vec![0xA5u8; size];
        let _ = audit_image(&garbage);
    }
}

// ── Env-gated real-volume sweep (Tier-2 structural, the crux) ────────────────

/// Point `REFS_TIER2_ORACLE` at the full 16 MiB partition head to sweep the
/// whole resident region: the auditor must emit **nothing false** on the clean
/// real volume (no fabricated CRC/self-block/geometry verdicts across 39 real
/// `MSB+` pages) — the anti-LZNT1-trap regression guard on real bytes.
#[test]
fn real_volume_clean_sweep_emits_nothing_false_env_gated() {
    let Ok(path) = std::env::var("REFS_TIER2_ORACLE") else {
        eprintln!("REFS_TIER2_ORACLE not set — skipping real-volume clean sweep");
        return;
    };
    let data = std::fs::read(&path).expect("read REFS_TIER2_ORACLE image");
    let anomalies = audit_image(&data);
    assert!(
        anomalies.is_empty(),
        "the clean real v3.14 volume must emit no structural anomaly, got {anomalies:?}"
    );
}
