/// A trait representing a cache for a trie structure.
///
/// # Type Parameters
/// - `AK`: The type of the account key.
/// - `AV`: The type of the account value.
/// - `SK`: The type of the storage key.
/// - `SV`: The type of the storage value.
pub trait TrieCache<AK, AV, SK, SV>: Send + Sync {
    /// Retrieves an account value associated with the given key.
    ///
    /// # Parameters
    /// - `k`: A reference to the account key.
    ///
    /// # Returns
    /// An `Option` containing the account value if it exists, or `None` if it does not.
    fn get_account(&self, k: &AK) -> Option<AV>;

    /// Retrieves a storage value associated with the given key.
    ///
    /// # Parameters
    /// - `k`: A reference to the storage key.
    ///
    /// # Returns
    /// An `Option` containing the storage value if it exists, or `None` if it does not.
    fn get_storage(&self, k: &SK) -> Option<SV>;
}
