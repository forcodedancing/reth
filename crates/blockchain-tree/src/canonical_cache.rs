use std::{collections::HashSet, sync::atomic::AtomicU64, time::Instant};

use lazy_static::lazy_static;
use metrics::counter;
use parking_lot::RwLock;
use tracing::info;

use quick_cache::sync::Cache;
use reth_primitives::{Account, Address, BlockNumber, Bytecode, StorageKey, StorageValue, B256};
use reth_provider::{
    AccountReader, BlockHashReader, ExecutionDataProvider, StateProofProvider, StateProvider,
    StateRootProvider,
};
use reth_revm::db::BundleState;
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{updates::TrieUpdates, AccountProof};
/// The size of cache, counted by the number of accounts.
const CACHE_SIZE: usize = 200000;

type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(CACHE_SIZE*5);

    /// Contract cache
    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::new(CACHE_SIZE*5);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::new(CACHE_SIZE*50);

    /// Block hash cache
    static ref BLOCK_HASH_CACHE: Cache<u64, B256> = Cache::new(CACHE_SIZE*5);


    static ref TOTAL_TIME: RwLock<AtomicU64> = RwLock::new(AtomicU64::new(0));
    static ref CHANGE_SET_TOTAL_TIME: RwLock<AtomicU64> = RwLock::new(AtomicU64::new(0));
}

pub(crate) fn update_total(block: u64, inc: u128) {
    let mut binding = TOTAL_TIME.write();

    let current = binding.get_mut();
    let new = *current + inc as u64;
    *current = new;

    if block % 100 == 0 {
        let mut binding = CHANGE_SET_TOTAL_TIME.write();
        let change_set_time = *binding.get_mut();
        let total = new + change_set_time;
        info!(target: "blockchain_tree", total = ?total, execution = ?new, change_set = ?change_set_time, block = ?block, "Total execution time");
    }
}

pub(crate) fn apply_bundle_state_to_cache(bundle: BundleState) {
    let execute_start = Instant::now();
    let change_set = bundle.into_plain_state(reth_provider::OriginalValuesKnown::Yes);

    for (address, account_info) in change_set.accounts.iter() {
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
    for storage in change_set.storage.iter() {
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

    let mut binding = CHANGE_SET_TOTAL_TIME.write();

    let current = binding.get_mut();
    let new = *current + execute_start.elapsed().as_micros() as u64;
    *current = new;
}

#[derive(Debug)]
pub(crate) struct CachedBundleStateProvider<SP: StateProvider, EDP: ExecutionDataProvider> {
    /// The inner state provider.
    pub state_provider: SP,
    /// Block execution data.
    pub block_execution_data_provider: EDP,
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> CachedBundleStateProvider<SP, EDP> {
    /// Create new cached bundle state provider
    pub(crate) fn new(state_provider: SP, block_execution_data_provider: EDP) -> Self {
        Self { state_provider, block_execution_data_provider }
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> BlockHashReader
    for CachedBundleStateProvider<SP, EDP>
{
    fn block_hash(&self, block_number: BlockNumber) -> ProviderResult<Option<B256>> {
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
        if let Some(v) = ACCOUNT_CACHE.get(&address) {
            counter!("blockchain.tree.cache.account.canonical.hit").increment(1);
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

    fn state_root_with_updates(
        &self,
        bundle_state: &BundleState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.state_root_with_updates(&state)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateProofProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn proof(
        &self,
        bundle_state: &BundleState,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.proof(&state, address, slots)
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
        let cache_key = (account, storage_key);
        if let Some(v) = STORAGE_CACHE.get(&cache_key) {
            counter!("blockchain.tree.cache.storage.canonical.hit").increment(1);
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.storage(account, storage_key)? {
            STORAGE_CACHE.insert(cache_key, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
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
