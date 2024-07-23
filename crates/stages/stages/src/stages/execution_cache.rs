use std::{collections::HashMap, num::NonZeroUsize};

use lazy_static::lazy_static;
use lru::LruCache;
use parking_lot::RwLock;
use tracing::debug;

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

lazy_static! {
        /// Account cache
    static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(CACHE_SIZE);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<Address, HashMap<StorageKey, StorageValue>> = Cache::new(CACHE_SIZE);
}

pub(crate) fn apply_changeset_to_cache(change_set: StateChangeset) {
    for (address, account_info) in change_set.accounts.iter() {
        match account_info {
            None => {
                ACCOUNT_CACHE.remove(address);
                STORAGE_CACHE.remove(address);
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
            STORAGE_CACHE.remove(&storage.address);
        } else {
            let mut map = HashMap::new();
            for (k, v) in storage.storage.clone() {
                map.insert(k.into(), v);
            }
            STORAGE_CACHE.insert(storage.address, map);
        }
    }
}

pub(crate) fn clear_cache() {
    ACCOUNT_CACHE.clear();
    STORAGE_CACHE.clear();
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
        if let Some(metrics_tx) = &self.metrics_tx {
            let _ = metrics_tx.send(MetricEvent::ExecutionCache {
                account_access: true,
                account_hit: false,
                storage_access: false,
                storage_hit: false,
            });
        }
        let cached = ACCOUNT_CACHE.get(&address);
        return match cached {
            Some(account) => {
                debug!(target: "sync::stages::execution", address = ?address.to_string(), "Hit execution stage account cache");
                if let Some(metrics_tx) = &self.metrics_tx {
                    let _ = metrics_tx.send(MetricEvent::ExecutionCache {
                        account_access: false,
                        account_hit: true,
                        storage_access: false,
                        storage_hit: false,
                    });
                }
                Ok(Some(account))
            }
            None => {
                let db_value = AccountReader::basic_account(&self.provider, address);
                match db_value {
                    Ok(account) => {
                        if let Some(_) = account {
                            ACCOUNT_CACHE.insert(address, account.unwrap());
                            debug!(target: "sync::stages::execution", address = ?address.to_string(), "Add execution stage account cache");
                        }
                        Ok(account)
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }
    }
}

impl<'b, TX: DbTx> BlockHashReader for CachedLatestStateProviderRef<'b, TX> {
    /// Get block hash by number.
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        BlockHashReader::block_hash(&self.provider, number)
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
        if let Some(metrics_tx) = &self.metrics_tx {
            let _ = metrics_tx.send(MetricEvent::ExecutionCache {
                account_access: false,
                account_hit: false,
                storage_access: true,
                storage_hit: false,
            });
        }

        let mut cached = STORAGE_CACHE.get(&account).unwrap_or_else(|| HashMap::new());

        if let Some(v) = cached.get(&storage_key) {
            debug!(target: "sync::stages::execution", address = ?account.to_string(), storage_key = ?storage_key, "Hit execution stage storage cache");
            if let Some(metrics_tx) = &self.metrics_tx {
                let _ = metrics_tx.send(MetricEvent::ExecutionCache {
                    account_access: false,
                    account_hit: false,
                    storage_access: false,
                    storage_hit: true,
                });
            }
            return Ok(Some(*v))
        }

        if let Some(value) = StateProvider::storage(&self.provider, account, storage_key)? {
            cached.insert(storage_key, value);
            STORAGE_CACHE.insert(account, cached);
            debug!(target: "sync::stages::execution", address = ?account.to_string(), storage_key = ?storage_key, "Add execution stage storage cache");
            return Ok(Some(value))
        }
        Ok(None)
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        StateProvider::bytecode_by_hash(&self.provider, code_hash)
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
