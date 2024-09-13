use itertools::Itertools;
use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use std::collections::HashSet;

use crate::cache::CACHED_TRIE_NODES;
use metrics::counter;
use reth_primitives::{Account, B256, U256};
use reth_trie::{cache::TrieCache, HashedPostStateSorted};
use std::str::FromStr;

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;

// Type alias for hashed storage key
type HashedStorageKey = (B256, B256);

lazy_static! {
    /// Cache for hashed accounts
    static ref HASHED_ACCOUNTS: Cache<B256, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Cache for hashed storages
    static ref HASHED_STORAGES: Cache<HashedStorageKey, U256> = Cache::new(STORAGE_CACHE_SIZE);

    /// Mapping for deleting storages
    static ref HASHED_STORAGES_MAPPING: Cache<B256, HashSet<B256>> =
        Cache::new(STORAGE_CACHE_SIZE);

    /// Combined cache for hashed states
    pub static ref CACHED_HASH_STATES: (&'static Cache<B256, Account>, &'static Cache<HashedStorageKey, U256>) =
        (&HASHED_ACCOUNTS, &HASHED_STORAGES);
}

// Implement methods for CACHED_HASH_STATES
impl CACHED_HASH_STATES {
    /// Insert an account into the cache
    fn insert_account(&self, k: B256, v: Account) {
        HASHED_ACCOUNTS.insert(k, v)
    }

    /// Remove an account from the cache
    fn remove_account(&self, k: &B256) {
        HASHED_ACCOUNTS.remove(k);
    }

    /// Insert storage into the cache
    fn insert_storage(&self, k: HashedStorageKey, v: U256) {
        let mut set = HASHED_STORAGES_MAPPING.get(&k.0).unwrap_or_default();
        set.insert(k.1);
        HASHED_STORAGES_MAPPING.insert(k.0, set);

        HASHED_STORAGES.insert(k, v);
    }

    /// Remove storage from the cache
    fn remove_storage(&self, k: &HashedStorageKey) {
        let mut set = HASHED_STORAGES_MAPPING.get(&k.0).unwrap_or_default();
        set.remove(&k.1);
        HASHED_STORAGES_MAPPING.insert(k.0, set);

        HASHED_STORAGES.remove(k);
    }
}

// Implement TrieCache trait for CACHED_HASH_STATES
impl TrieCache<B256, Account, HashedStorageKey, U256> for CACHED_HASH_STATES {
    /// Get an account from the cache
    fn get_account(&self, k: &B256) -> Option<Account> {
        counter!("hashed-cache.account.total").increment(1);
        match HASHED_ACCOUNTS.get(k) {
            Some(r) => {
                counter!("hashed-cache.account.hit").increment(1);
                Some(r)
            }
            None => None,
        }
    }

    /// Get storage from the cache
    fn get_storage(&self, k: &HashedStorageKey) -> Option<U256> {
        counter!("hashed-cache.storage.total").increment(1);
        match HASHED_STORAGES.get(k) {
            Some(r) => {
                counter!("hashed-cache.storage.hit").increment(1);
                Some(r)
            }
            None => None,
        }
    }
}

/// Write hashed state to the cache
pub(crate) fn write_hashed_state(hashed_state: &HashedPostStateSorted) {
    // Write hashed account changes
    for (hashed_address, account) in hashed_state.accounts().accounts_sorted() {
        if let Some(account) = account {
            CACHED_HASH_STATES.insert_account(hashed_address, account);
        } else {
            CACHED_HASH_STATES.remove_account(&hashed_address);
        }
    }

    // Write hashed storage changes
    let sorted_storages = hashed_state.account_storages().iter().sorted_by_key(|(key, _)| *key);
    for (hashed_address, storage) in sorted_storages {
        if storage.is_wiped() {
            let set = HASHED_STORAGES_MAPPING.get(hashed_address).unwrap_or_default();
            for s in &set {
                let storage_key = (*hashed_address, s.clone());
                CACHED_HASH_STATES.remove_storage(&storage_key);
            }
            HASHED_STORAGES_MAPPING.remove(hashed_address);
        }

        for (hashed_slot, value) in storage.storage_slots_sorted() {
            let key = (*hashed_address, hashed_slot);
            CACHED_HASH_STATES.remove_storage(&key);
            if !value.is_zero() {
                CACHED_HASH_STATES.insert_storage(key, value);
            }
        }
    }
}

/// Clear cached accounts and storages
pub(crate) fn clear_hashed_state() {
    CACHED_HASH_STATES.0.clear();
    CACHED_HASH_STATES.1.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache() {
        let address = B256::random();
        let account = Account::default();
        CACHED_HASH_STATES.insert_account(address, account);
        assert_eq!(HASHED_ACCOUNTS.len(), 1);

        CACHED_HASH_STATES.0.clear();
        assert_eq!(HASHED_ACCOUNTS.len(), 0);
    }
}
