pub mod cached_provider;
mod plain_state;

use crate::ExecutedBlock;
use tracing::debug;

use crate::cache::plain_state::{
    clear_plain_state, get_account, get_code, get_storage, insert_account, insert_code,
    insert_storage, write_plain_state,
};

/// Writes the execution outcomes, trie updates, and hashed states of the given blocks to the cache.
pub fn write_to_cache(blocks: Vec<ExecutedBlock>) {
    for block in blocks {
        debug!("Start to write block {} to cache", block.block.header.number);
        let bundle_state = block.execution_outcome().clone().bundle;
        let trie_updates = block.trie_updates();
        write_plain_state(bundle_state);
        reth_trie_db::cache::write_trie_updates(&trie_updates);
        debug!("Finish to write block {} to cache", block.block.header.number);
    }
}

/// Clears all cached states and trie nodes.
pub fn clear_all_cache() {
    clear_plain_state();
    reth_trie_db::cache::clear_trie_node();
}
