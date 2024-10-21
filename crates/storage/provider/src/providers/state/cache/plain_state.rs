use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use reth_db::{cursor::DbDupCursorRO, table::TableRow, tables, DatabaseError, PlainStorageState};
use reth_db_api::transaction::DbTx;
use reth_primitives::{Account, Address, Bytecode, StorageKey, StorageValue, B256, U256};
use std::sync::atomic::AtomicU64;
use tracing::info;

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;
const CONTRACT_CACHE_SIZE: usize = 10000;

// Type alias for address and storage key tuple
type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub static ref PLAIN_ACCOUNTS: Cache<Address, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Storage cache
     ///pub static ref PLAIN_STORAGES: Cache<AddressStorageKey, StorageValue> = Cache::new(STORAGE_CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
     pub(crate) static ref CONTRACT_CODES: Cache<B256, Bytecode> = Cache::new(CONTRACT_CACHE_SIZE);
}

pub(crate) fn insert_account(k: Address, v: Account) {
    PLAIN_ACCOUNTS.insert(k, v);
}

/// Insert storage into the cache
///pub(crate) fn insert_storage(k: AddressStorageKey, v: U256) {
//     PLAIN_STORAGES.insert(k, v);
// }

// Get account from cache
pub(crate) fn get_account(k: &Address) -> Option<Account> {
    PLAIN_ACCOUNTS.get(k)
}

// Get storage from cache
// pub(crate) fn get_storage(k: &AddressStorageKey) -> Option<StorageValue> {
//     PLAIN_STORAGES.get(k)
// }

// Get code from cache
pub(crate) fn get_code(k: &B256) -> Option<Bytecode> {
    CONTRACT_CODES.get(k)
}

// Insert code into cache
pub(crate) fn insert_code(k: B256, v: Bytecode) {
    CONTRACT_CODES.insert(k, v);
}
