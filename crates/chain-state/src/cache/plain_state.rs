use crate::ExecutedBlock;
use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use reth_db::{cursor::DbDupCursorRO, table::TableRow, tables, DatabaseError, PlainStorageState};
use reth_db_api::transaction::DbTx;
use reth_primitives::{Account, Address, Bytecode, StorageKey, StorageValue, B256, U256};
use reth_revm::db::{BundleState, OriginalValuesKnown};
use std::sync::atomic::AtomicU64;
use tracing::info;

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 500000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 2;
const CONTRACT_CACHE_SIZE: usize = 10000;

// Type alias for address and storage key tuple
type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub static ref PLAIN_ACCOUNTS: Cache<Address, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Storage cache
     pub static ref PLAIN_STORAGES: Cache<AddressStorageKey, StorageValue> = Cache::new(STORAGE_CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
     pub(crate) static ref CONTRACT_CODES: Cache<B256, Bytecode> = Cache::new(CONTRACT_CACHE_SIZE);
}

pub(crate) fn insert_account(k: Address, v: Account) {
    PLAIN_ACCOUNTS.insert(k, v);
}

/// Insert storage into the cache
pub(crate) fn insert_storage(k: AddressStorageKey, v: U256) {
    PLAIN_STORAGES.insert(k, v);
}

// Get account from cache
pub(crate) fn get_account(k: &Address) -> Option<Account> {
    PLAIN_ACCOUNTS.get(k)
}

// Get storage from cache
pub(crate) fn get_storage(k: &AddressStorageKey) -> Option<StorageValue> {
    PLAIN_STORAGES.get(k)
}

// Get code from cache
pub(crate) fn get_code(k: &B256) -> Option<Bytecode> {
    CONTRACT_CODES.get(k)
}

// Insert code into cache
pub(crate) fn insert_code(k: B256, v: Bytecode) {
    CONTRACT_CODES.insert(k, v);
}

pub struct PlainCacheWriter<'a, TX>(&'a TX);

impl<'a, TX> PlainCacheWriter<'a, TX> {
    pub const fn new(tx: &'a TX) -> Self {
        Self(tx)
    }
}

impl<'a, TX> PlainCacheWriter<'a, TX> {
    /// Write committed state to cache.
    pub fn write_plain_state(&mut self, blocks: Vec<ExecutedBlock>)
    where
        TX: DbTx,
    {
        let cursor = self.0.cursor_dup_read::<tables::PlainStorageState>();
        match cursor {
            Ok(mut cursor) => {
                for block in blocks {
                    if block.block.number % 100 == 0 {
                        info!("CACHE_SZ {}", PLAIN_STORAGES.len());
                    };
                    PLAIN_STORAGES.len();
                    let bundle_state = block.execution_outcome().clone().bundle;
                    let change_set = bundle_state.into_plain_state(OriginalValuesKnown::Yes);

                    // Update account cache
                    for (address, account_info) in &change_set.accounts {
                        match account_info {
                            None => {
                                PLAIN_ACCOUNTS.remove(address);
                            }
                            Some(acc) => {
                                let _ = PLAIN_ACCOUNTS.replace(
                                    *address,
                                    Account {
                                        nonce: acc.nonce,
                                        balance: acc.balance,
                                        bytecode_hash: Some(acc.code_hash),
                                    },
                                    true,
                                );
                            }
                        }
                    }

                    // Update storage cache
                    for storage in &change_set.storage {
                        if storage.wipe_storage {
                            let walker = cursor.walk_dup(Some(storage.address), None).unwrap();
                            for kv in walker {
                                match kv {
                                    Ok((k, v)) => {
                                        PLAIN_STORAGES.remove(&(k, v.key));
                                    }
                                    Err(_) => {
                                        PLAIN_STORAGES.clear();
                                        break;
                                    }
                                }
                            }
                        }

                        for (k, v) in storage.storage.clone() {
                            let _ = PLAIN_STORAGES.replace(
                                (storage.address, StorageKey::from(k)),
                                v,
                                true,
                            );
                        }
                    }
                }
            }
            Err(_) => {
                PLAIN_ACCOUNTS.clear();
                PLAIN_STORAGES.clear();
            }
        }
    }
}

/// Clear cached accounts and storages.
pub(crate) fn clear_plain_state() {
    PLAIN_ACCOUNTS.clear();
    PLAIN_STORAGES.clear();
}
