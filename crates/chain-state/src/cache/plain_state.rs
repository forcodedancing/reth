use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

//use crate::StateCache;
use metrics::counter;
use reth_primitives::{Account, Address, Bytecode, StorageKey, StorageValue, B256, U256};
use reth_revm::db::{BundleState, OriginalValuesKnown};

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;
const CONTRACT_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE / 10;

// Type alias for address and storage key tuple
type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    static ref PLAIN_ACCOUNTS: Cache<Address, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Storage cache
    static ref PLAIN_STORAGES: Cache<AddressStorageKey, StorageValue> = Cache::new(STORAGE_CACHE_SIZE);

    /// Mapping for deleting storages
    static ref PLAIN_STORAGES_MAPPING: Mutex<HashMap<Address, HashSet<B256>>> = Mutex::new(HashMap::new());

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
    static ref CONTRACT_CODES: Cache<B256, Bytecode> = Cache::new(CONTRACT_CACHE_SIZE);

    //// Cached plain states
    ////#[allow(clippy::type_complexity)]
    ////pub static ref CACHED_PLAIN_STATES: (&'static Cache<Address, Account>, &'static Cache<AddressStorageKey, StorageValue>,  &'static Cache<B256, Bytecode>) = (&PLAIN_ACCOUNTS, &PLAIN_STORAGES, &CONTRACT_CODES);
}

// impl CACHED_PLAIN_STATES {
pub fn insert_account(k: Address, v: Account) {
    PLAIN_ACCOUNTS.insert(k, v);
}

/// Insert storage into the cache
pub fn insert_storage(k: AddressStorageKey, v: U256) {
    {
        let mut map = PLAIN_STORAGES_MAPPING.lock().unwrap();
        if let Some(set) = map.get_mut(&k.0) {
            set.insert(k.1);
        } else {
            let mut s = HashSet::new();
            s.insert(k.1);
            map.insert(k.0, s);
        }
    }
    PLAIN_STORAGES.insert(k, v);
}
// }

// Implementing StateCache trait for CACHED_PLAIN_STATES
// impl StateCache<Address, Account, AddressStorageKey, StorageValue, B256, Bytecode>
//     for CACHED_PLAIN_STATES
// {
// Get account from cache
pub fn get_account(k: &Address) -> Option<Account> {
    // counter!("plain-cache.account.total").increment(1);
    // match PLAIN_ACCOUNTS.get(k) {
    //     Some(r) => {
    //         counter!("plain-cache.account.hit").increment(1);
    //         Some(r)
    //     }
    //     None => None,
    // }

    PLAIN_ACCOUNTS.get(k)
}

// Get storage from cache
pub fn get_storage(k: &AddressStorageKey) -> Option<StorageValue> {
    // counter!("plain-cache.storage.total").increment(1);
    // match PLAIN_STORAGES.get(k) {
    //     Some(r) => {
    //         counter!("plain-cache.storage.hit").increment(1);
    //         Some(r)
    //     }
    //     None => None,
    // }

    PLAIN_STORAGES.get(k)
}

// Get code from cache
pub fn get_code(k: &B256) -> Option<Bytecode> {
    // counter!("plain-cache.code.total").increment(1);
    // match CONTRACT_CODES.get(k) {
    //     Some(r) => {
    //         counter!("plain-cache.code.hit").increment(1);
    //         Some(r)
    //     }
    //     None => None,
    // }

    CONTRACT_CODES.get(k)
}

// Insert code into cache
pub fn insert_code(k: B256, v: Bytecode) {
    CONTRACT_CODES.insert(k, v);
}
// }

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
            let mut map = PLAIN_STORAGES_MAPPING.lock().unwrap();
            if let Some(set) = map.get(&storage.address) {
                for s in set {
                    let storage_key = (storage.address, *s);
                    PLAIN_STORAGES.remove(&storage_key);
                }
            }
            map.remove(&storage.address);
        }

        for (k, v) in storage.storage.clone() {
            insert_storage((storage.address, StorageKey::from(k)), v);
        }
    }
}

/// Clear cached accounts and storages.
pub(crate) fn clear_plain_state() {
    PLAIN_ACCOUNTS.clear();
    PLAIN_STORAGES.clear();
    let mut map = PLAIN_STORAGES_MAPPING.lock().unwrap();
    map.clear();
}
