use reth_errors::ProviderResult;
use reth_primitives::{
    Account, Address, BlockNumber, Bytecode, Bytes, StorageKey, StorageValue, B256, U256,
};
use reth_revm::database::EvmStateProvider;
use reth_storage_api::{
    AccountReader, BlockHashReader, StateProofProvider, StateProvider, StateProviderBox,
    StateRootProvider, StorageRootProvider,
};
use reth_trie::{
    prefix_set::TriePrefixSetsMut, updates::TrieUpdates, AccountProof, BranchNodeCompact,
    HashedPostState, HashedStorage, MultiProof, Nibbles, TrieInput,
};
use std::collections::{HashMap, HashSet};
/*
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
*/

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
        BlockHashReader::block_hash(&self.underlying, number)
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
        if let Some(v) = crate::cache::get_account(&address) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        if let Some(value) = AccountReader::basic_account(&self.underlying, address)? {
            crate::cache::insert_account(address, value);
            return Ok(Some(value))
        }
        Ok(None)
    }
}

impl StateRootProvider for CachedStateProvider {
    fn state_root(&self, state: HashedPostState) -> ProviderResult<B256> {
        self.state_root_from_nodes(TrieInput::from_state(state))
    }

    fn state_root_from_nodes(&self, mut input: TrieInput) -> ProviderResult<B256> {
        self.underlying.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.state_root_from_nodes_with_updates(TrieInput::from_state(state))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        mut input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.underlying.state_root_from_nodes_caches_with_updates(input)
    }

    fn state_root_from_nodes_caches_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.underlying.state_root_from_nodes_caches_with_updates(input)
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
        mut input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.underlying.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        mut input: TrieInput,
        targets: HashMap<B256, HashSet<B256>>,
    ) -> ProviderResult<MultiProof> {
        self.underlying.multiproof(input, targets)
    }

    fn witness(
        &self,
        mut input: TrieInput,
        target: HashedPostState,
    ) -> ProviderResult<HashMap<B256, Bytes>> {
        self.underlying.witness(input, target)
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
        if let Some(v) = crate::cache::get_storage(&key) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        if let Some(value) = StateProvider::storage(&self.underlying, address, storage_key)? {
            crate::cache::insert_storage(key, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        // Check cache first
        if let Some(v) = crate::cache::get_code(&code_hash) {
            return Ok(Some(v))
        }
        // Fallback to underlying provider
        if let Some(value) = StateProvider::bytecode_by_hash(&self.underlying, code_hash)? {
            crate::cache::insert_code(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}
