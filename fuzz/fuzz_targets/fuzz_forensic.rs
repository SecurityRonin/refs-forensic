#![no_main]
//! Full audit + carve pipeline over an arbitrary "image": the F-INTEGRITY
//! auditor (`audit_image` / `audit_findings`) and the F-CARVE CoW
//! metadata-residue recovery (`recover_residue`) must never panic on any byte
//! string — this is the end-to-end forensic front door driven by
//! attacker-controlled ReFS volume bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural anomaly audit (typed anomalies + graded findings).
    let _ = refs_forensic::audit_image(data);
    let _ = refs_forensic::audit_findings(data, "fuzz");
    // CoW metadata-residue recovery — carves stale directory pages.
    let _ = refs_forensic::recover_residue(data);
});
