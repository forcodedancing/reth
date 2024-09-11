use itertools::Itertools;
use lazy_static::lazy_static;
use quick_cache::sync::Cache;

use metrics::counter;
use reth_primitives::{Account, B256, U256};
use reth_trie::{cache::TrieCache, HashedPostStateSorted};
use std::{collections::HashMap, str::FromStr};
use tracing::debug;

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

    /// Combined cache for hashed states
    pub static ref CACHED_HASH_STATES: (&'static Cache<B256, Account>, &'static Cache<HashedStorageKey, U256>) =
        (&HASHED_ACCOUNTS, &HASHED_STORAGES);
}

// Implement methods for CACHED_HASH_STATES
impl CACHED_HASH_STATES {
    /// Insert an account into the cache
    fn insert_account(&self, k: B256, v: Account) {
        let tmp =
            B256::from_str("0xfcbd49b3a106f7e49c6e147b76ca4682aefd4fe6d07f4368f542751aaf85d596")
                .unwrap();
        if !k.eq(&tmp) {
            debug!("INSERT_HASHED_ACCOUNT: {:?} {:?}", k.clone(), v.clone());
            self.0.insert(k, v)
        }
    }

    /// Remove an account from the cache
    fn remove_account(&self, k: &B256) {
        self.0.remove(k);
    }

    /// Insert storage into the cache
    fn insert_storage(&self, k: HashedStorageKey, v: U256) {
        debug!("INSERT_HASHED_STORAGE: {:?} {:?}", k.clone(), v.clone());
        self.1.insert(k, v);
    }

    /// Remove storage from the cache
    fn remove_storage(&self, k: &HashedStorageKey) {
        self.1.remove(k);
    }
}

// Implement TrieCache trait for CACHED_HASH_STATES
impl TrieCache<B256, Account, HashedStorageKey, U256> for CACHED_HASH_STATES {
    /// Get an account from the cache
    fn get_account(&self, k: &B256) -> Option<Account> {
        counter!("hashed-cache.account.total").increment(1);
        match self.0.get(k) {
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
        match self.1.get(k) {
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
            debug!("DDD to remove account cache {}", hashed_address);
        }
    }

    // Write hashed storage changes
    let sorted_storages = hashed_state.account_storages().iter().sorted_by_key(|(key, _)| *key);
    let mut to_wipe = false;
    for (hashed_address, storage) in sorted_storages {
        if storage.is_wiped() {
            debug!("DDD to clear storage cache {}", hashed_address);
            to_wipe = true;
            break;
        }
        for (hashed_slot, value) in storage.storage_slots_sorted() {
            let key = (*hashed_address, hashed_slot);
            CACHED_HASH_STATES.remove_storage(&key);
            if !value.is_zero() {
                CACHED_HASH_STATES.insert_storage(key, value);
            } else {
                debug!("DDD zero value storage cache {} {}", hashed_address, hashed_slot);
            }
        }
    }
    if to_wipe {
        CACHED_HASH_STATES.1.clear();
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
