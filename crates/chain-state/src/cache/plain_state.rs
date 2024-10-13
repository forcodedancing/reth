use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use reth_primitives::{Account, Address, Bytecode, StorageKey, StorageValue, B256, U256};
use reth_revm::db::{BundleState, OriginalValuesKnown};
use schnellru::{ByLength, LruMap};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
};
use tracing::info;

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;
const CONTRACT_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE / 100;

// Type alias for address and storage key tuple
type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub(crate) static ref PLAIN_ACCOUNTS: Cache<Address, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
     pub(crate) static ref CONTRACT_CODES: Cache<B256, Bytecode> = Cache::new(CONTRACT_CACHE_SIZE);

     pub(crate) static ref STORAGES: Mutex<LruMap<Address, LruMap<B256, U256>>> = Mutex::new(LruMap::new(ByLength::new(ACCOUNT_CACHE_SIZE as u32)));
}

pub(crate) fn insert_account(k: Address, v: Account) {
    PLAIN_ACCOUNTS.insert(k, v);
}

/// Insert storage into the cache
pub(crate) fn insert_storage(k: AddressStorageKey, v: U256) {
    let mut outer = STORAGES.lock().unwrap();
    match outer.get(&k.0) {
        Some(inner) => {
            inner.insert(k.1, v);
        }
        None => {
            let mut inner = LruMap::new(ByLength::new(100));
            inner.insert(k.1, v);
            outer.insert(k.0, inner);
        }
    }
}

pub(crate) fn remove_storages(address: Address) {
    let mut outer = STORAGES.lock().unwrap();
    outer.remove(&address);
}
pub(crate) fn insert_storages(address: Address, storages: Vec<(U256, U256)>) {
    if storages.is_empty() {
        return;
    }

    let mut outer = STORAGES.lock().unwrap();
    match outer.get(&address) {
        Some(inner) => {
            for (k, v) in storages {
                inner.insert(StorageKey::from(k), v);
            }
        }
        None => {
            let mut inner = LruMap::new(ByLength::new(100));
            for (k, v) in storages {
                inner.insert(StorageKey::from(k), v);
            }
            outer.insert(address, inner);
        }
    }
}

// Get account from cache
pub(crate) fn get_account(k: &Address) -> Option<Account> {
    PLAIN_ACCOUNTS.get(k)
}

// Get storage from cache
pub(crate) fn get_storage(k: &AddressStorageKey) -> Option<StorageValue> {
    let mut outer = STORAGES.lock().unwrap();
    match outer.get(&k.0) {
        Some(inner) => match inner.get(&k.1) {
            Some(value) => Some(*value),
            None => None,
        },
        None => None,
    }
}

// Get code from cache
pub(crate) fn get_code(k: &B256) -> Option<Bytecode> {
    CONTRACT_CODES.get(k)
}

// Insert code into cache
pub(crate) fn insert_code(k: B256, v: Bytecode) {
    CONTRACT_CODES.insert(k, v);
}

/// Write committed state to cache.
pub(crate) fn write_plain_state(bundle: BundleState) {
    let change_set = bundle.into_plain_state(OriginalValuesKnown::Yes);

    // Update account cache
    for (address, account_info) in &change_set.accounts {
        match account_info {
            None => {
                PLAIN_ACCOUNTS.remove(address);
            }
            Some(acc) => {
                PLAIN_ACCOUNTS.insert(
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

    // Update storage cache
    for storage in &change_set.storage {
        if storage.wipe_storage {
            info!(target: "blockchain_tree", "wipe_storage is true.");
            remove_storages(storage.address);
        }

        insert_storages(storage.address, storage.storage.clone());
    }
}

/// Clear cached accounts and storages.
pub(crate) fn clear_plain_state() {
    PLAIN_ACCOUNTS.clear();
    let mut outer = STORAGES.lock().unwrap();
    outer.clear();
}
