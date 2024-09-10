use itertools::Itertools;
use lazy_static::lazy_static;
use quick_cache::sync::Cache;

use metrics::counter;
use reth_primitives::{Account, B256, U256};
use reth_trie::{cache::TrieCache, HashedPostStateSorted};

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
    /// Remove an account from the cache
    fn remove_account(&self, k: &B256) {
        self.0.remove(k);
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

    /// Insert an account into the cache
    fn insert_account(&self, k: B256, v: Account) {
        self.0.insert(k, v)
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

    /// Insert storage into the cache
    fn insert_storage(&self, k: HashedStorageKey, v: U256) {
        self.1.insert(k, v);
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
            CACHED_HASH_STATES.1.clear();
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
