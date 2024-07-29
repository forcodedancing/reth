use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU128, AtomicU64},
        Mutex,
    },
    time::Instant,
};

use lazy_static::lazy_static;
use lru::LruCache;
use metrics::{Counter, CounterFn, GaugeFn};
use parking_lot::RwLock;
use tracing::{debug, info};

use moka::sync::Cache;
use reth_metrics::Metrics;
use reth_primitives::{Account, Address, BlockNumber, Bytecode, StorageKey, StorageValue, B256};
use reth_provider::{
    AccountReader, BlockHashReader, ExecutionDataProvider, StateProofProvider, StateProvider,
    StateRootProvider,
};
use reth_revm::db::BundleState;
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{updates::TrieUpdates, AccountProof};
/// The size of cache, counted by the number of accounts.
const CACHE_SIZE: u64 = 10240;

type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::builder().max_capacity(CACHE_SIZE).build();

    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::builder().max_capacity(CACHE_SIZE).build();

    static ref HASH_CACHE: Cache<u64, B256> = Cache::builder().max_capacity(CACHE_SIZE).build();

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::builder().max_capacity(CACHE_SIZE).build();

    static ref TOTAL_TIME: RwLock<AtomicU128> = RwLock::new(AtomicU128::new(0));
    static ref CHANGE_SET_TOTAL_TIME: RwLock<AtomicU128> = RwLock::new(AtomicU128::new(0));
}

pub(crate) fn update_total(block: u64, inc: u128) {
    let mut binding = TOTAL_TIME.write();

    let current = binding.get_mut();
    let new = *current + inc;
    *current = new;

    if block % 500 == 0 {
        info!(target: "blockchain_tree", total = ?new , "Total execution time");
        let mut binding = CHANGE_SET_TOTAL_TIME.write();
        info!(target: "blockchain_tree", total = ?binding.get_mut() , "Total changeset time");
    }
    if block == 420001 {
        panic!("reach height")
    }
}

/// Metrics for cache.
#[derive(Metrics)]
#[metrics(scope = "blockchain_tree.cache")]
pub(crate) struct CacheMetrics {
    /// Total account access count
    pub(crate) account_access_total: Counter,
    /// Total account access cache hit count
    pub(crate) account_cache_hit_total: Counter,
    /// Total storage access count
    pub(crate) storage_access_total: Counter,
    /// Total storage access cache hit count
    pub(crate) storage_cache_hit_total: Counter,
}

pub(crate) fn apply_bundle_state_to_cache(bundle: BundleState) {
    let execute_start = Instant::now();
    let change_set = bundle.into_plain_state(reth_provider::OriginalValuesKnown::Yes);

    for (address, account_info) in change_set.accounts.iter() {
        match account_info {
            None => {
                ACCOUNT_CACHE.invalidate(address);
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

    for storage in change_set.storage.iter() {
        if storage.wipe_storage {
            // invalidate_entries_if needs `static
            // let _ = STORAGE_CACHE.invalidate_entries_if(move |k, _v| {
            //     let (address, _) = k;
            //     if address.eq(&storage.address) {
            //         return true;
            //     }
            //     return false;
            // });

            for (storage_key, _storage_value) in STORAGE_CACHE.iter() {
                if storage_key.0.eq(&storage.address) {
                    STORAGE_CACHE.invalidate(&storage_key);
                }
            }
        } else {
            for (k, v) in storage.storage.clone() {
                STORAGE_CACHE.insert((storage.address, StorageKey::from(k)), v);
            }
        }
    }

    let mut binding = CHANGE_SET_TOTAL_TIME.write();

    let current = binding.get_mut();
    let new = *current + execute_start.elapsed().as_micros();
    *current = new;
}

#[derive(Debug)]
pub(crate) struct CachedBundleStateProvider<SP: StateProvider, EDP: ExecutionDataProvider> {
    /// The inner state provider.
    pub state_provider: SP,
    /// Block execution data.
    pub block_execution_data_provider: EDP,
    /// Cache metrics.
    pub cache_metrics: CacheMetrics,
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> CachedBundleStateProvider<SP, EDP> {
    /// Create new cached bundle state provider
    pub(crate) fn new(state_provider: SP, block_execution_data_provider: EDP) -> Self {
        Self {
            state_provider,
            block_execution_data_provider,
            cache_metrics: CacheMetrics::default(),
        }
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

        let cached = HASH_CACHE.get(&block_number);
        return match cached {
            Some(hash) => Ok(Some(hash)),
            None => {
                let db_value = self.state_provider.block_hash(block_number);
                match db_value {
                    Ok(hash) => {
                        if let Some(acc) = hash {
                            HASH_CACHE.insert(block_number, acc);
                        }
                        Ok(hash)
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }
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
        self.cache_metrics.account_access_total.increment(1);

        let cached = ACCOUNT_CACHE.get(&address);
        return match cached {
            Some(account) => Ok(Some(account)),
            None => {
                let db_value = AccountReader::basic_account(&self.state_provider, address);
                match db_value {
                    Ok(account) => {
                        if let Some(acc) = account {
                            ACCOUNT_CACHE.insert(address, acc);
                        }
                        Ok(account)
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }
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
        storage_key: reth_primitives::StorageKey,
    ) -> ProviderResult<Option<reth_primitives::StorageValue>> {
        let u256_storage_key = storage_key.into();
        if let Some(value) = self
            .block_execution_data_provider
            .execution_outcome()
            .storage(&account, u256_storage_key)
        {
            return Ok(Some(value))
        }

        self.cache_metrics.storage_access_total.increment(1);

        let cache_key = (account, storage_key);
        let cached_value = STORAGE_CACHE.get(&cache_key);

        if let Some(v) = cached_value {
            return Ok(Some(v))
        }

        if let Some(value) = StateProvider::storage(&self.state_provider, account, storage_key)? {
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
        let cached = CONTRACT_CACHE.get(&code_hash);
        return match cached {
            Some(code) => Ok(Some(code)),
            None => {
                let db_value = self.state_provider.bytecode_by_hash(code_hash);
                match db_value {
                    Ok(code) => {
                        if let Some(acc) = code.clone() {
                            CONTRACT_CACHE.insert(code_hash, acc);
                        }
                        Ok(code)
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }
    }
}
