//! ReFS checkpoint (`CHKP`) location + parsing — P1 stub (RED).

/// The ReFS checkpoint — P1 stub (RED).
#[derive(Debug)]
#[non_exhaustive]
pub struct Checkpoint;

impl Checkpoint {
    /// The checkpoint block numbers named by a superblock — stub for RED.
    ///
    /// # Errors
    /// Always, until GREEN.
    pub fn locations_from_superblock(_superblock: &[u8]) -> Result<Vec<u64>, crate::RefsError> {
        Err(crate::RefsError::Truncated {
            structure: "Checkpoint (stub)",
            need: 0,
            have: 0,
        })
    }
}
