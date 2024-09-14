mod plain_state;
pub use plain_state::CACHED_PLAIN_STATES;

use crate::ExecutedBlock;
use tracing::debug;

use crate::cache::plain_state::{clear_plain_state, write_plain_state};

/// Writes the execution outcomes, trie updates, and hashed states of the given blocks to the cache.
pub fn write_to_cache(blocks: Vec<ExecutedBlock>) {
    for block in blocks {
        debug!("Start to write block {} to cache", block.block.header.number);
        let bundle_state = block.execution_outcome().clone().bundle;
        let trie_updates = block.trie_updates().clone();
        let hashed_state = block.hashed_state();
        write_plain_state(bundle_state);
        reth_trie_db::cache::write_hashed_state(&hashed_state.clone().into_sorted());
        reth_trie_db::cache::write_trie_updates(&trie_updates);
        debug!("Finish to write block {} to cache", block.block.header.number);
    }
}

/// Clears all cached states and trie nodes.
pub fn clear_all_cache() {
    clear_plain_state();
    reth_trie_db::cache::clear_hashed_state();
    reth_trie_db::cache::clear_trie_node();
}
