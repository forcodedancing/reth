use std::collections::HashMap;

use lazy_static::lazy_static;
use quick_cache::sync::Cache;

use reth_primitives::B256;
use reth_trie::{
    cache::TrieCache,
    updates::{StorageTrieUpdates, TrieUpdates},
    BranchNodeCompact, Nibbles, StoredNibbles, StoredNibblesSubKey,
};

use metrics::counter;

// Constants for cache sizes
const ACCOUNT_CACHE_SIZE: usize = 1000000;
const STORAGE_CACHE_SIZE: usize = ACCOUNT_CACHE_SIZE * 10;

// Type alias for Trie storage key
type TrieStorageKey = (B256, Nibbles);

lazy_static! {
    /// Cache for account trie nodes
    static ref TRIE_ACCOUNTS: Cache<Nibbles, BranchNodeCompact> = Cache::new(ACCOUNT_CACHE_SIZE);

    /// Cache for storage trie nodes
    static ref TRIE_STORAGES: Cache<TrieStorageKey, BranchNodeCompact> =
        Cache::new(STORAGE_CACHE_SIZE);

    /// Combine cache for trie nodes
    pub static ref CACHED_TRIE_NODES: (&'static Cache<Nibbles, BranchNodeCompact>, &'static Cache<TrieStorageKey, BranchNodeCompact>) =
        (&TRIE_ACCOUNTS, &TRIE_STORAGES);
}

// Implementation of methods for CACHED_TRIE_NODES
impl CACHED_TRIE_NODES {
    // Remove an account node from the cache
    fn remove_account(&self, k: &Nibbles) {
        self.0.remove(k);
    }

    // Remove a storage node from the cache
    fn remove_storage(&self, k: &TrieStorageKey) {
        self.1.remove(k);
    }
}

// Implementation of TrieCache trait for CACHED_TRIE_NODES
impl TrieCache<Nibbles, BranchNodeCompact, TrieStorageKey, BranchNodeCompact>
    for CACHED_TRIE_NODES
{
    // Get an account node from the cache
    fn get_account(&self, k: &Nibbles) -> Option<BranchNodeCompact> {
        counter!("trie-cache.account.total").increment(1);
        match self.0.get(k) {
            Some(r) => {
                counter!("trie-cache.account.hit").increment(1);
                Some(r)
            }
            None => None,
        }
    }

    // Insert an account node into the cache
    fn insert_account(&self, k: Nibbles, v: BranchNodeCompact) {
        self.0.insert(k, v)
    }

    // Get a storage node from the cache
    fn get_storage(&self, k: &TrieStorageKey) -> Option<BranchNodeCompact> {
        counter!("trie-cache.storage.total").increment(1);
        match self.1.get(k) {
            Some(r) => {
                counter!("trie-cache.storage.hit").increment(1);
                Some(r)
            }
            None => None,
        }
    }

    // Insert a storage node into the cache
    fn insert_storage(&self, k: TrieStorageKey, v: BranchNodeCompact) {
        self.1.insert(k, v)
    }
}

// Write trie updates
pub(crate) fn write_trie_updates(trie_updates: &TrieUpdates) {
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
        CACHED_TRIE_NODES.1.clear();
        return;
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
pub(crate) fn clear_trie_node() {
    CACHED_TRIE_NODES.0.clear();
    CACHED_TRIE_NODES.1.clear();
}
