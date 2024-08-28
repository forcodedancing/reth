use lazy_static::lazy_static;
use parking_lot::RwLock;
use quick_cache::sync::Cache;
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{Account, Address, BlockNumber, Bytecode, StorageKey, StorageValue, B256};
use reth_provider::{
    AccountReader, BlockHashReader, ExecutionDataProvider, StateProofProvider, StateProvider,
    StateRootProvider,
};
use reth_revm::db::BundleState;
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{updates::TrieUpdates, AccountProof, HashedPostState};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

type AddressStorageKey = (Address, StorageKey);

/// The size of cache, counted by the number of accounts.
const CACHE_SIZE: usize = 1000000;

/// The safe interval from the canonical height for committing [`OUTCOME_CACHE`] to the
/// quick cache.
const SAFE_INTERVAL: u64 = 32;

/// Tracking the committed (to the quick cache) execution outcome.
static COMMITTED_OUTCOME_HEIGHT: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    /// Execution outcome for the recent blocks, which states have not been moved to quick cache.
    static ref OUTCOME_CACHE: RwLock<ExecutionOutcome> = RwLock::new(ExecutionOutcome::default());

    /// Account cache
    static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::new(CACHE_SIZE/10);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::new(CACHE_SIZE*10);

    /// Block hash cache
    static ref BLOCK_HASH_CACHE: Cache<u64, B256> = Cache::new(CACHE_SIZE/10);
}

/// Apply committed execution outcome to canonical cache.
pub(crate) fn apply_execution_outcome(outcome: ExecutionOutcome) {
    let committed = COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed);
    if committed == 0 {
        COMMITTED_OUTCOME_HEIGHT.store(outcome.first_block, Ordering::Relaxed);
        debug!(target: "canonical_cache", ?committed, ?outcome.first_block, "Extend execution outcome");
        OUTCOME_CACHE.write().clone_from(&outcome);
        return;
    }

    debug!(target: "canonical_cache", ?committed, ?outcome.first_block, "Extend execution outcome");
    OUTCOME_CACHE.write().extend(outcome.clone());

    if outcome.first_block <= committed + SAFE_INTERVAL {
        return;
    }

    // The two splits ([..at], [at..]) will include the split height both.
    let (lower, higher) =
        OUTCOME_CACHE.read().clone().split_at(outcome.first_block - SAFE_INTERVAL);

    if let Some(outcome) = lower {
        // Only keep the higher outcome
        OUTCOME_CACHE.write().clone_from(&higher);
        COMMITTED_OUTCOME_HEIGHT.store(higher.first_block, Ordering::Relaxed);

        debug!(target: "canonical_cache", ?committed, ?higher.first_block, "Commit split execution outcome");
        // Commit the lower outcome
        let change_set = outcome.bundle.into_plain_state(reth_provider::OriginalValuesKnown::Yes);

        for (address, account_info) in &change_set.accounts {
            match account_info {
                None => {
                    ACCOUNT_CACHE.remove(address);
                }
                Some(acc) => {
                    ACCOUNT_CACHE.insert(
                        *address,
                        Account {
                            nonce: acc.nonce,
                            balance: acc.balance,
                            bytecode_hash: Some(acc.code_hash),
                        },
                    );
                }
            }
        }

        let mut to_wipe = false;
        for storage in &change_set.storage {
            if storage.wipe_storage {
                to_wipe = true;
                break;
            } else {
                for (k, v) in storage.storage.clone() {
                    STORAGE_CACHE.insert((storage.address, StorageKey::from(k)), v);
                }
            }
        }
        if to_wipe {
            STORAGE_CACHE.clear();
        }
    }
}

/// Revert cached accounts and storages. The states in `block_number` will be reserved.
pub fn revert_states(block_number: Option<u64>) {
    let should_clear = match block_number {
        None => true,
        Some(block_number) => {
            let committed = COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed);
            debug!(target: "canonical_cache", ?committed, ?block_number, "Prepare revert states");
            // Revert to a height which has been committed
            committed > block_number
        }
    };

    // Clear account and storage cache.
    if should_clear {
        debug!(target: "canonical_cache", ?block_number, "Clear canonical cache");
        OUTCOME_CACHE.write().clone_from(&ExecutionOutcome::default());
        COMMITTED_OUTCOME_HEIGHT.store(0, Ordering::Relaxed);
        ACCOUNT_CACHE.clear();
        STORAGE_CACHE.clear();
    } else {
        let outcome = OUTCOME_CACHE.read().clone();
        let outcome_tip = (outcome.first_block + outcome.len() as u64).checked_sub(1).or(Some(0));
        if outcome_tip.unwrap() >= block_number.unwrap() {
            // Revert outcome cache
            debug!(target: "canonical_cache", ?block_number, ?outcome_tip, "Revert execution outcome");
            OUTCOME_CACHE.write().revert_to(block_number.unwrap());
        } else {
            // Reset outcome for missing some state
            debug!(target: "canonical_cache", ?block_number, ?outcome_tip, "Reset execution outcome");
            OUTCOME_CACHE.write().clone_from(&ExecutionOutcome::default());
            COMMITTED_OUTCOME_HEIGHT.store(0, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
pub(crate) struct CachedBundleStateProvider<SP: StateProvider, EDP: ExecutionDataProvider> {
    /// The inner state provider.
    pub(crate) state_provider: SP,
    /// Block execution data.
    pub(crate) block_execution_data_provider: EDP,
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> CachedBundleStateProvider<SP, EDP> {
    /// Create new cached bundle state provider
    pub(crate) const fn new(state_provider: SP, block_execution_data_provider: EDP) -> Self {
        Self { state_provider, block_execution_data_provider }
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> BlockHashReader
    for CachedBundleStateProvider<SP, EDP>
{
    fn block_hash(&self, block_number: BlockNumber) -> ProviderResult<Option<B256>> {
        let block_hash = self.block_execution_data_provider.block_hash(block_number);
        if block_hash.is_some() {
            return Ok(block_hash)
        }

        if let Some(v) = BLOCK_HASH_CACHE.get(&block_number) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.block_hash(block_number)? {
            BLOCK_HASH_CACHE.insert(block_number, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn canonical_hashes_range(
        &self,
        _start: BlockNumber,
        _end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        unimplemented!()
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> AccountReader
    for CachedBundleStateProvider<SP, EDP>
{
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        if let Some(account) =
            self.block_execution_data_provider.execution_outcome().account(&address)
        {
            return Ok(account)
        }

        if let Some(account) = OUTCOME_CACHE.read().account(&address) {
            return Ok(account)
        }
        if let Some(v) = ACCOUNT_CACHE.get(&address) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.basic_account(address)? {
            ACCOUNT_CACHE.insert(address, value);
            return Ok(Some(value))
        }
        Ok(None)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateRootProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn state_root(&self, bundle_state: &BundleState) -> ProviderResult<B256> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.state_root(&state)
    }

    fn hashed_state_root(&self, hashed_state: &reth_trie::HashedPostState) -> ProviderResult<B256> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_state_root(&state)
    }

    fn state_root_with_updates(
        &self,
        bundle_state: &BundleState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.state_root_with_updates(&state)
    }

    fn hashed_state_root_with_updates(
        &self,
        hashed_state: &HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_state_root_with_updates(&state)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateProofProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn hashed_proof(
        &self,
        hashed_state: &HashedPostState,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_proof(&state, address, slots)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let u256_storage_key = storage_key.into();
        if let Some(value) = self
            .block_execution_data_provider
            .execution_outcome()
            .storage(&account, u256_storage_key)
        {
            return Ok(Some(value))
        }

        if let Some(value) = OUTCOME_CACHE.read().storage(&account, u256_storage_key) {
            return Ok(Some(value))
        }
        let cache_key = (account, storage_key);
        if let Some(v) = STORAGE_CACHE.get(&cache_key) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.storage(account, storage_key)? {
            STORAGE_CACHE.insert(cache_key, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(bytecode) =
            self.block_execution_data_provider.execution_outcome().bytecode(&code_hash)
        {
            return Ok(Some(bytecode))
        }

        if let Some(bytecode) = OUTCOME_CACHE.read().bytecode(&code_hash) {
            return Ok(Some(bytecode))
        }
        if let Some(v) = CONTRACT_CACHE.get(&code_hash) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.bytecode_by_hash(code_hash)? {
            CONTRACT_CACHE.insert(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives::{Receipt, Receipts};

    #[serial_test::serial]
    #[test]
    fn test_append_execution_outcomes() {
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 0);

        apply_execution_outcome(ExecutionOutcome::new(
            BundleState::default(),
            Receipts::from(vec![Receipt::default()]),
            1,
            vec![],
        ));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 1);

        // States are still in execution outcome
        for height in 2..34 {
            apply_execution_outcome(ExecutionOutcome::new(
                BundleState::default(),
                Receipts::from(vec![Receipt::default()]),
                height,
                vec![],
            ));
            assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 1);
        }

        // first outcome to trigger moving outcome to quick cache
        apply_execution_outcome(ExecutionOutcome::new(
            BundleState::default(),
            Receipts::from(vec![Receipt::default()]),
            34,
            vec![],
        ));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 2);

        // second outcome to trigger moving outcome to quick cache
        apply_execution_outcome(ExecutionOutcome::new(
            BundleState::default(),
            Receipts::from(vec![Receipt::default()]),
            35,
            vec![],
        ));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 3);

        revert_states(None);
    }

    #[serial_test::serial]
    #[test]
    fn test_revert_states_without_height() {
        revert_states(None);
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 0);
        assert_eq!(OUTCOME_CACHE.read().first_block, 0);

        apply_execution_outcome(ExecutionOutcome::new(
            BundleState::default(),
            Receipts::from(vec![Receipt::default()]),
            10,
            vec![],
        ));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 10);
        assert_eq!(OUTCOME_CACHE.read().first_block, 10);

        revert_states(None);
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 0);
        assert_eq!(OUTCOME_CACHE.read().first_block, 0);
    }

    #[serial_test::serial]
    #[test]
    fn test_revert_states_with_height() {
        for height in 10..100 {
            apply_execution_outcome(ExecutionOutcome::new(
                BundleState::default(),
                Receipts::from(vec![Receipt::default()]),
                height,
                vec![],
            ));
        }
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 67);

        // revert outcome only
        revert_states(Some(80));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 67); // no influence on committed
        assert_eq!(OUTCOME_CACHE.read().len(), 80 - 67 + 1); // 80 should be kept

        // revert outcome only
        revert_states(Some(67));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 67); // no influence on committed
        assert_eq!(OUTCOME_CACHE.read().len(), 1); // only 67 is kept

        // clear cache
        for height in 68..88 {
            apply_execution_outcome(ExecutionOutcome::new(
                BundleState::default(),
                Receipts::from(vec![Receipt::default()]),
                height,
                vec![],
            ));
        }

        revert_states(Some(66));
        assert_eq!(COMMITTED_OUTCOME_HEIGHT.load(Ordering::Relaxed), 0);
        assert_eq!(OUTCOME_CACHE.read().len(), 0);
    }
}
