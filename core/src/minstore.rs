//! ReFS Minstore B+-tree page + object table — P1 stub (RED).

/// Well-known ReFS root-directory object identifier — placeholder for RED.
pub const REFS_ROOT_DIRECTORY_ID: u64 = 0;

/// One `(key, value)` Minstore node record — stub for RED.
#[derive(Debug)]
#[non_exhaustive]
pub struct MinstoreRow<'a> {
    /// Key bytes.
    pub key: &'a [u8],
    /// Value bytes.
    pub value: &'a [u8],
}

/// A parsed Minstore B+-tree page — P1 stub (RED).
#[derive(Debug)]
#[non_exhaustive]
pub struct MinstorePage<'a> {
    _data: &'a [u8],
}

impl<'a> MinstorePage<'a> {
    /// Parse — stub for RED (always errors).
    ///
    /// # Errors
    /// Always, until GREEN.
    pub fn parse(_data: &'a [u8], _offset: u64) -> Result<Self, crate::RefsError> {
        Err(crate::RefsError::Truncated {
            structure: "MinstorePage (stub)",
            need: 0,
            have: 0,
        })
    }

    /// Node level — stub.
    #[must_use]
    pub fn level(&self) -> u8 {
        255
    }

    /// Is a leaf — stub.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        false
    }

    /// Is a branch — stub.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        false
    }

    /// Row iterator — stub (empty).
    pub fn rows(&self) -> impl Iterator<Item = MinstoreRow<'a>> {
        core::iter::empty()
    }
}

/// A resolved object-table entry — stub for RED.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PageRef {
    /// Target metadata block number.
    pub block_number: u64,
}

/// The ReFS object table (a Minstore B+-tree) — P1 stub (RED).
#[derive(Debug)]
#[non_exhaustive]
pub struct ObjectTable<'a> {
    _data: &'a [u8],
}

impl<'a> ObjectTable<'a> {
    /// Parse — stub for RED (always errors).
    ///
    /// # Errors
    /// Always, until GREEN.
    pub fn parse(_data: &'a [u8], _offset: u64) -> Result<Self, crate::RefsError> {
        Err(crate::RefsError::Truncated {
            structure: "ObjectTable (stub)",
            need: 0,
            have: 0,
        })
    }

    /// Lookup — stub (always None).
    #[must_use]
    pub fn lookup(&self, _object_id: u64) -> Option<PageRef> {
        None
    }
}
