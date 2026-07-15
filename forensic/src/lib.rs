//! `refs-forensic` — anomaly auditor for ReFS filesystems (P0 scaffold).
//!
//! Will emit graded [`forensicnomicon::report::Finding`]s for ReFS-specific
//! forensic signals — page/integrity-stream checksum mismatches, CoW stale
//! metadata pages (deleted-file/old-version carving), USN Change Journal — over
//! `refs-core` (or the raw page level, per the reader/analyzer-split principle).
//!
//! This is a **P0 scaffold**: the audit surface is not yet implemented. It
//! re-exports the report vocabulary so downstream wiring can compile against the
//! intended shape while the reader (`refs-core`) matures.
//!
//! # Reverse-engineered format
//!
//! ReFS has no official Microsoft on-disk spec; every structural fact is
//! reverse-engineered (Tier-2 at best). Findings will be **observations**
//! ("consistent with …"); the examiner draws the conclusions.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::{Finding, Severity};
pub use refs_core::{BootSector, RefsError, Superblock};
