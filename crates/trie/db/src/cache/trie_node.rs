use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use lazy_static::lazy_static;
use quick_cache::sync::Cache;

use reth_primitives::{Account, B256};
use reth_trie::{
    cache::TrieCache,
    updates::{StorageTrieUpdates, TrieUpdates},
    BranchNodeCompact, Nibbles, StoredNibbles, StoredNibblesSubKey,
};

use metrics::counter;
use tracing::debug;

// Constants for cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;

// Type alias for Trie storage key
pub type TrieStorageKey = (B256, Nibbles);

lazy_static! {
    /// Cache for account trie nodes
    static ref TRIE_ACCOUNTS: Cache<Nibbles, BranchNodeCompact> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Cache for storage trie nodes
    static ref TRIE_STORAGES: Cache<TrieStorageKey, BranchNodeCompact> =
        Cache::new(STORAGE_CACHE_SIZE);

    /// Mapping for deleting storage trie nodes
    static ref TRIE_STORAGES_MAPPING: Mutex<HashMap<B256, HashSet<Nibbles>>> = Mutex::new(HashMap::new());

    /// Combine cache for trie nodes
    pub static ref CACHED_TRIE_NODES: (&'static Cache<Nibbles, BranchNodeCompact>, &'static Cache<TrieStorageKey, BranchNodeCompact>) =
        (&TRIE_ACCOUNTS, &TRIE_STORAGES);
}

// Implementation of methods for CACHED_TRIE_NODES
impl CACHED_TRIE_NODES {
    // Insert an account node into the cache
    pub fn insert_account(&self, k: Nibbles, v: BranchNodeCompact) {
        TRIE_ACCOUNTS.insert(k, v)
    }

    // Remove an account node from the cache
    fn remove_account(&self, k: &Nibbles) {
        TRIE_ACCOUNTS.remove(k);
    }

    // Insert a storage node into the cache
    pub fn insert_storage(&self, k: TrieStorageKey, v: BranchNodeCompact) {
        let mut map = TRIE_STORAGES_MAPPING.lock().unwrap();
        if let Some(set) = map.get_mut(&k.0) {
            set.insert(k.clone().1);
        } else {
            let mut s = HashSet::new();
            s.insert(k.clone().1);
            map.insert(k.0, s);
        }

        TRIE_STORAGES.insert(k, v)
    }

    // Remove a storage node from the cache
    fn remove_storage(&self, k: &TrieStorageKey) {
        TRIE_STORAGES.remove(k);

        let mut map = TRIE_STORAGES_MAPPING.lock().unwrap();
        if let Some(set) = map.get_mut(&k.0) {
            set.remove(&k.clone().1);
            if set.len() == 0 {
                map.remove(&k.0);
            }
        }
    }
}

// Implementation of TrieCache trait for CACHED_TRIE_NODES
impl TrieCache<Nibbles, BranchNodeCompact, TrieStorageKey, BranchNodeCompact>
    for CACHED_TRIE_NODES
{
    // Get an account node from the cache
    fn get_account(&self, k: &Nibbles) -> Option<BranchNodeCompact> {
        // counter!("trie-cache.account.total").increment(1);
        // match TRIE_ACCOUNTS.get(k) {
        //     Some(r) => {
        //         counter!("trie-cache.account.hit").increment(1);
        //         Some(r)
        //     }
        //     None => None,
        // }

        TRIE_ACCOUNTS.get(k)
    }

    // Get a storage node from the cache
    fn get_storage(&self, k: &TrieStorageKey) -> Option<BranchNodeCompact> {
        // counter!("trie-cache.storage.total").increment(1);
        // match TRIE_STORAGES.get(k) {
        //     Some(r) => {
        //         counter!("trie-cache.storage.hit").increment(1);
        //         Some(r)
        //     }
        //     None => None,
        // }

        TRIE_STORAGES.get(k)
    }
}

// Write trie updates
pub fn write_trie_updates(trie_updates: &TrieUpdates) {
    if trie_updates.is_empty() {
        return;
    }

    // Merge updated and removed nodes. Updated nodes must take precedence.
    let mut account_updates = trie_updates
        .removed_nodes_ref()
        .iter()
        .filter_map(|n| (!trie_updates.account_nodes_ref().contains_key(n)).then_some((n, None)))
        .collect::<Vec<_>>();
    account_updates.extend(
        trie_updates.account_nodes_ref().iter().map(|(nibbles, node)| (nibbles, Some(node))),
    );
    account_updates.sort_unstable_by(|a, b| a.0.cmp(b.0));

    // Process each account update
    for (key, updated_node) in account_updates {
        let nibbles = StoredNibbles(key.clone());
        CACHED_TRIE_NODES.remove_account(&nibbles.0.clone());
        if let Some(node) = updated_node {
            if !nibbles.0.is_empty() {
                CACHED_TRIE_NODES.insert_account(nibbles.0, node.clone());
            }
        }
    }

    // Write storage trie updates
    write_storage_trie_updates(trie_updates.storage_tries_ref());
}

// Write storage trie updates
fn write_storage_trie_updates(storage_tries: &HashMap<B256, StorageTrieUpdates>) {
    let mut storage_tries = Vec::from_iter(storage_tries);
    storage_tries.sort_unstable_by(|a, b| a.0.cmp(b.0));

    // Process each storage trie update
    for (hashed_address, storage_trie_updates) in storage_tries {
        write_single_storage_trie_updates(hashed_address, storage_trie_updates)
    }
}

// Write a single storage trie update
fn write_single_storage_trie_updates(hashed_address: &B256, updates: &StorageTrieUpdates) {
    // The storage trie for this account has to be deleted.
    if updates.is_deleted() {
        let mut map = TRIE_STORAGES_MAPPING.lock().unwrap();
        if let Some(set) = map.get(hashed_address) {
            for s in set {
                let storage_key = (*hashed_address, s.clone());
                TRIE_STORAGES.remove(&storage_key);
            }
        }
        map.remove(hashed_address);
    }

    // Merge updated and removed nodes. Updated nodes must take precedence.
    let mut storage_updates = updates
        .removed_nodes_ref()
        .iter()
        .filter_map(|n| (!updates.storage_nodes_ref().contains_key(n)).then_some((n, None)))
        .collect::<Vec<_>>();
    storage_updates
        .extend(updates.storage_nodes_ref().iter().map(|(nibbles, node)| (nibbles, Some(node))));

    // Sort trie node updates.
    storage_updates.sort_unstable_by(|a, b| a.0.cmp(b.0));

    for (nibbles, maybe_updated) in storage_updates.into_iter().filter(|(n, _)| !n.is_empty()) {
        let nibbles = StoredNibblesSubKey(nibbles.clone());
        let storage_key = (*hashed_address, nibbles.0.clone());
        CACHED_TRIE_NODES.remove_storage(&storage_key);

        // There is an updated version of this node, insert new entry.
        if let Some(node) = maybe_updated {
            CACHED_TRIE_NODES.insert_storage(storage_key, node.clone());
        }
    }
}

// Clear all trie nodes from the cache
pub fn clear_trie_node() {
    CACHED_TRIE_NODES.0.clear();
    CACHED_TRIE_NODES.1.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache() {
        let address = B256::random();
        let key1 = StoredNibblesSubKey::from(vec![0x1, 0x2]);
        let value1 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key2 = StoredNibblesSubKey::from(vec![0x2, 0x4]);
        let value2 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);

        CACHED_TRIE_NODES.insert_storage((address, key1.clone().into()), value1);
        CACHED_TRIE_NODES.insert_storage((address, key2.clone().into()), value2);
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().len(), 1);
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().get(&address).unwrap().len(), 2);

        CACHED_TRIE_NODES.remove_storage(&(address, key1.clone().into()));
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().len(), 1);
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().get(&address).unwrap().len(), 1);

        CACHED_TRIE_NODES.remove_storage(&(address, key1.clone().into()));
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().len(), 1);
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().get(&address).unwrap().len(), 1);

        CACHED_TRIE_NODES.remove_storage(&(address, key2.clone().into()));
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().len(), 0);
        assert_eq!(TRIE_STORAGES_MAPPING.lock().unwrap().get(&address), None);
    }
}
