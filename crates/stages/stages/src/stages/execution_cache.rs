use std::{collections::HashSet, sync::atomic::AtomicU64, time::Instant};

use lazy_static::lazy_static;
use parking_lot::RwLock;
use tracing::info;

use quick_cache::sync::Cache;
use reth_db_api::transaction::DbTx;
use reth_primitives::{Account, Address, BlockNumber, Bytecode, StorageKey, StorageValue, B256};
use reth_provider::{
    AccountReader, BlockHashReader, LatestStateProviderRef, StateProofProvider, StateProvider,
    StateRootProvider,
};
use reth_revm::db::{states::StateChangeset, BundleState};
use reth_stages_api::{MetricEvent, MetricEventsSender};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{updates::TrieUpdates, AccountProof};

/// The size of cache, counted by the number of accounts.
const CACHE_SIZE: usize = 10240;

type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(CACHE_SIZE*5);

    /// Contract cache
    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::new(CACHE_SIZE*5);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::new(CACHE_SIZE*10);

    /// Block hash cache
    static ref BLOCK_HASH_CACHE: Cache<u64, B256> = Cache::new(CACHE_SIZE*5);
}

pub(crate) fn apply_changeset_to_cache(change_set: StateChangeset) {
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
}

pub(crate) fn clear_cache() {
    ACCOUNT_CACHE.clear();
    STORAGE_CACHE.clear();
    CONTRACT_CACHE.clear();
    BLOCK_HASH_CACHE.clear();
}

/// State provider over latest state that takes tx reference.
#[derive(Debug)]
pub(crate) struct CachedLatestStateProviderRef<'b, TX: DbTx> {
    provider: LatestStateProviderRef<'b, TX>,
    metrics_tx: Option<MetricEventsSender>,
}

impl<'b, TX: DbTx> CachedLatestStateProviderRef<'b, TX> {
    /// Create new state provider
    pub(crate) fn new(
        provider: LatestStateProviderRef<'b, TX>,
        metrics_tx: Option<MetricEventsSender>,
    ) -> Self {
        Self { provider, metrics_tx }
    }
}

impl<'b, TX: DbTx> AccountReader for CachedLatestStateProviderRef<'b, TX> {
    /// Get basic account information.
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        if let Some(v) = ACCOUNT_CACHE.get(&address) {
            if let Some(metrics_tx) = &self.metrics_tx {
                let _ = metrics_tx
                    .send(MetricEvent::ExecutionCache { account_hit: true, storage_hit: false });
            }
            return Ok(Some(v))
        }
        if let Some(value) = self.provider.basic_account(address)? {
            ACCOUNT_CACHE.insert(address, value);
            return Ok(Some(value))
        }
        Ok(None)
    }
}

impl<'b, TX: DbTx> BlockHashReader for CachedLatestStateProviderRef<'b, TX> {
    /// Get block hash by number.
    fn block_hash(&self, block_number: u64) -> ProviderResult<Option<B256>> {
        if let Some(v) = BLOCK_HASH_CACHE.get(&block_number) {
            return Ok(Some(v))
        }
        if let Some(value) = self.provider.block_hash(block_number)? {
            BLOCK_HASH_CACHE.insert(block_number, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.provider.canonical_hashes_range(start, end)
    }
}

impl<'b, TX: DbTx> StateRootProvider for CachedLatestStateProviderRef<'b, TX> {
    fn state_root(&self, bundle_state: &BundleState) -> ProviderResult<B256> {
        self.provider.state_root(bundle_state)
    }

    fn state_root_with_updates(
        &self,
        bundle_state: &BundleState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.provider.state_root_with_updates(bundle_state)
    }
}

impl<'b, TX: DbTx> StateProofProvider for CachedLatestStateProviderRef<'b, TX> {
    fn proof(
        &self,
        bundle_state: &BundleState,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.provider.proof(bundle_state, address, slots)
    }
}

impl<'b, TX: DbTx> StateProvider for CachedLatestStateProviderRef<'b, TX> {
    /// Get storage.
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let cache_key = (account, storage_key);
        if let Some(v) = STORAGE_CACHE.get(&cache_key) {
            if let Some(metrics_tx) = &self.metrics_tx {
                let _ = metrics_tx
                    .send(MetricEvent::ExecutionCache { account_hit: false, storage_hit: true });
            }
            return Ok(Some(v))
        }
        if let Some(value) = self.provider.storage(account, storage_key)? {
            STORAGE_CACHE.insert(cache_key, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(v) = CONTRACT_CACHE.get(&code_hash) {
            return Ok(Some(v))
        }
        if let Some(value) = self.provider.bytecode_by_hash(code_hash)? {
            CONTRACT_CACHE.insert(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use itertools::Itertools;
//     use reth_primitives::{address, U256};
//
//     #[test]
//     fn test_cached_hashmap() {
//         //init data
//         let address = address!("D3b0d838cCCEAe7ebF1781D11D1bB741DB7Fe1A7");
//         let mut m: HashMap<StorageKey, StorageValue> = HashMap::new();
//         m.insert(B256::random(), U256::MAX);
//         STORAGE_CACHE.insert(address, m);
//
//         //put data
//         let mut cached = STORAGE_CACHE.get(&address).unwrap_or_else(|| HashMap::new());
//         cached.insert(B256::random(), U256::MAX);
//
//         //verify data
//         let cached = STORAGE_CACHE.get(&address).unwrap_or_else(|| HashMap::new());
//         println!("{}", cached.keys().len());
//     }
// }
