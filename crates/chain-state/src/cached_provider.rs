use reth_errors::ProviderResult;
use reth_primitives::{
    Account, Address, BlockNumber, Bytecode, Bytes, StorageKey, StorageValue, B256, U256,
};
use reth_storage_api::{
    AccountReader, BlockHashReader, StateProofProvider, StateProvider, StateProviderBox,
    StateRootProvider, StorageRootProvider,
};
use reth_trie::{
    cache::TrieCache, prefix_set::TriePrefixSetsMut, updates::TrieUpdates, AccountProof,
    BranchNodeCompact, HashedPostState, HashedStorage, Nibbles,
};
use std::collections::HashMap;

/// Trait for caching state data
pub trait StateCache<AK, AV, SK, SV, CK, CV>: Send + Sync {
    /// Get account from cache
    fn get_account(&self, k: &AK) -> Option<AV>;

    /// Get storage from cache
    fn get_storage(&self, k: &SK) -> Option<SV>;

    /// Get code from cache
    fn get_code(&self, k: &CK) -> Option<CV>;

    /// Insert code into cache
    fn insert_code(&self, k: CK, v: CV);
}

/// Cached state provider struct
#[allow(missing_debug_implementations)]
pub struct CachedStateProvider {
    pub(crate) underlying: Box<dyn StateProvider>,
}

impl CachedStateProvider {
    /// Create a new `CachedStateProvider`
    pub fn new(underlying: Box<dyn StateProvider>) -> Self {
        Self { underlying }
    }

    /// Turn this state provider into a [`StateProviderBox`]
    pub fn boxed(self) -> StateProviderBox {
        Box::new(self)
    }
}

impl BlockHashReader for CachedStateProvider {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        self.underlying.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        let hashes = self.underlying.canonical_hashes_range(start, end)?;
        Ok(hashes)
    }
}

impl AccountReader for CachedStateProvider {
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        // Check cache first
        if let Some(v) = crate::cache::CACHED_PLAIN_STATES.get_account(&address) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        self.underlying.basic_account(address)
    }
}

impl StateRootProvider for CachedStateProvider {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        let prefix_sets = hashed_state.construct_prefix_sets();
        self.state_root_from_nodes(TrieUpdates::default(), hashed_state, prefix_sets)
    }

    fn state_root_from_nodes(
        &self,
        nodes: TrieUpdates,
        state: HashedPostState,
        prefix_sets: TriePrefixSetsMut,
    ) -> ProviderResult<B256> {
        self.underlying.state_root_from_nodes(nodes, state, prefix_sets)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let prefix_sets = hashed_state.construct_prefix_sets();
        self.state_root_from_nodes_with_updates(TrieUpdates::default(), hashed_state, prefix_sets)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        nodes: TrieUpdates,
        state: HashedPostState,
        prefix_sets: TriePrefixSetsMut,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.state_root_from_nodes_caches_with_updates(nodes, state, prefix_sets)
    }

    fn state_root_from_nodes_caches_with_updates(
        &self,
        nodes: TrieUpdates,
        state: HashedPostState,
        prefix_sets: TriePrefixSetsMut,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.underlying.state_root_from_nodes_caches_with_updates(nodes, state, prefix_sets)
    }
}

impl StorageRootProvider for CachedStateProvider {
    fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256> {
        self.underlying.storage_root(address, storage)
    }
}

impl StateProofProvider for CachedStateProvider {
    fn proof(
        &self,
        state: HashedPostState,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.underlying.proof(state, address, slots)
    }

    fn witness(
        &self,
        state: HashedPostState,
        target: HashedPostState,
    ) -> ProviderResult<HashMap<B256, Bytes>> {
        self.underlying.witness(state, target)
    }
}

impl StateProvider for CachedStateProvider {
    fn storage(
        &self,
        address: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let key = (address, storage_key);
        // Check cache first
        if let Some(v) = crate::cache::CACHED_PLAIN_STATES.get_storage(&key) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        self.underlying.storage(address, storage_key)
    }

    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        // Check cache first
        if let Some(v) = crate::cache::CACHED_PLAIN_STATES.get_code(&code_hash) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        if let Some(value) = self.underlying.bytecode_by_hash(code_hash)? {
            crate::cache::CACHED_PLAIN_STATES.insert_code(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}
