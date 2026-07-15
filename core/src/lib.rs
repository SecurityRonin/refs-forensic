//! `refs-core` — a pure-Rust, from-scratch ReFS (Resilient File System) reader.
//!
//! Parses the ReFS on-disk structures a forensic tool needs, starting from the
//! boot Volume Boot Record (VBR) and superblock. Imports as `refs_core` (the
//! bare `refs` crate name is taken by an unrelated third party on crates.io):
//! `use refs_core::BootSector;`.
//!
//! # Reverse-engineered format — no official specification
//!
//! ReFS is **undocumented**: Microsoft publishes no on-disk specification. Every
//! structural fact this reader encodes comes from third-party **reverse
//! engineering** — primarily libyal's `libfsrefs` and Prade's academic work.
//! Correctness is therefore **Tier-2 at best** for structural metadata (there is
//! no ground-truth forensic corpus); only *file content* can reach Tier-1, by
//! hashing against the live Windows ReFS driver. ReFS is also
//! **version-fragmented** — the layout differs materially between v1.x (Server
//! 2012 / 8.1) and v3.x (Server 2016+/Win10+/Win11), and each Windows release
//! tweaks it. This reader targets **v3.x** and **fails loud** (naming the
//! version bytes) on any other major version rather than silently misparsing.
//!
//! # Safety and robustness
//!
//! This crate parses untrusted, attacker-controllable disk images. It is
//! `#![forbid(unsafe_code)]` and every integer is read through bounds-checked
//! little-endian helpers that yield `0`/`None` out of range rather than panic
//! (the Paranoid Gatekeeper standard). ReFS is little-endian.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod boot;
pub mod bytes;
mod checkpoint;
mod container;
mod directory;
mod error;
mod metablock;
mod minstore;
mod superblock;

pub use boot::{BootSector, REFS_FSRS, REFS_SIGNATURE};
pub use checkpoint::Checkpoint;
pub use container::{decompose_virtual_block, ContainerRecord, ContainerResolver, ContainerTable};
pub use directory::{
    find_by_path, list_dir, parse_directory, walk_directory, DirEntry, FileMetadata,
};
pub use error::RefsError;
pub use metablock::{crc32c, crc64_ecma, MetaBlock, REFS_METADATA_PAGE_SIZE};
pub use minstore::{MinstorePage, MinstoreRow, ObjectTable, PageRef, REFS_ROOT_DIRECTORY_ID};
pub use superblock::{MetadataBlockRef, Superblock, REFS_SUPERBLOCK_CLUSTER, SUPB_SIGNATURE};
