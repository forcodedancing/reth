use lazy_static::lazy_static;
use quick_cache::sync::Cache;

use reth_chain_state::StateCache;
use reth_primitives::{Account, Address, Bytecode, StorageKey, StorageValue, B256};
use reth_revm::db::BundleState;

// Cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;
const CONTRACT_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE / 10;

// Type alias for address and storage key tuple
type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::new(STORAGE_CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::new(CONTRACT_CACHE_SIZE);

    /// Cached plain states
    pub static ref CACHED_PLAIN_STATES: (&'static Cache<Address, Account>, &'static Cache<AddressStorageKey, StorageValue>,  &'static Cache<B256, Bytecode>) = (&ACCOUNT_CACHE, &STORAGE_CACHE, &CONTRACT_CACHE);
}

// Implementing StateCache trait for CACHED_PLAIN_STATES
impl StateCache<Address, Account, AddressStorageKey, StorageValue, B256, Bytecode>
    for CACHED_PLAIN_STATES
{
    // Get account from cache
    fn get_account(&self, k: &Address) -> Option<Account> {
        self.0.get(k)
    }

    // Insert account into cache
    fn insert_account(&self, k: Address, v: Account) {
        self.0.insert(k, v);
    }

    // Get storage from cache
    fn get_storage(&self, k: &AddressStorageKey) -> Option<StorageValue> {
        self.1.get(k)
    }

    // Insert storage into cache
    fn insert_storage(&self, k: AddressStorageKey, v: StorageValue) {
        self.1.insert(k, v);
    }

    // Get code from cache
    fn get_code(&self, k: &B256) -> Option<Bytecode> {
        self.2.get(k)
    }

    // Insert code into cache
    fn insert_code(&self, k: B256, v: Bytecode) {
        self.2.insert(k, v);
    }
}

/// Write committed state to cache.
pub(crate) fn write_plain_state(bundle: BundleState) {
    // Convert bundle state to plain state
    let change_set = bundle.into_plain_state(reth_provider::OriginalValuesKnown::Yes);

    // Update account cache
    for (address, account_info) in &change_set.accounts {
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

    // Update storage cache
    let mut to_wipe = false;
    for storage in &change_set.storage {
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

/// Clear cached accounts and storages.
pub(crate) fn clear_plain_state() {
    CACHED_PLAIN_STATES.0.clear();
    CACHED_PLAIN_STATES.1.clear();
}
