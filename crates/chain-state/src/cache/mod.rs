mod plain_state;
pub use plain_state::CACHED_PLAIN_STATES;

mod hashed_state;
pub use hashed_state::CACHED_HASH_STATES;
use tracing::debug;
use crate::ExecutedBlock;

mod trie_node;
use crate::cache::{
    hashed_state::{clear_hashed_state, write_hashed_state},
    plain_state::{clear_plain_state, write_plain_state},
    trie_node::{clear_trie_node, write_trie_updates},
};
pub use trie_node::CACHED_TRIE_NODES;

/// Writes the execution outcomes, trie updates, and hashed states of the given blocks to the cache.
pub fn write_to_cache(blocks: Vec<ExecutedBlock>) {
    for block in blocks {
        debug!("Writing block {} to cache", block.block.header.number);
        let bundle_state = block.execution_outcome().clone().bundle;
        let trie_updates = block.trie_updates().clone();
        let hashed_state = block.hashed_state();
        write_plain_state(bundle_state);
        write_hashed_state(&hashed_state.clone().into_sorted());
        write_trie_updates(&trie_updates);
    }
}

/// Clears all cached states and trie nodes.
pub fn clear_all_cache() {
    clear_plain_state();
    clear_hashed_state();
    clear_trie_node();
}
