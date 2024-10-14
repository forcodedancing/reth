/// State provider with cached states for execution.
pub mod cached_provider;
pub mod plain_state;

use crate::{
    cache::plain_state::{
        clear_plain_state, get_account, get_code, get_storage, insert_account, insert_code,
        insert_storage, PlainCacheWriter,
    },
    ExecutedBlock,
};
use reth_db::{
    cursor::{DbCursorRW, DbDupCursorRO, DbDupCursorRW},
    tables,
};
use tracing::debug;

/// Writes the execution outcomes of the given blocks to the cache.
// pub fn write_to_cache(
//     blocks: Vec<ExecutedBlock>,
//     storage_cursor: &dyn DbDupCursorRO<tables::PlainStorageState>,
// ) {
//     for block in blocks {
//         debug!("Start to write block {} to cache", block.block.header.number);
//         let bundle_state = block.execution_outcome().clone().bundle;
//
//         let mut cache_writer = PlainCacheWriter::new(storage_cursor);
//         cache_writer.write_plain_state(bundle_state);
//         debug!("Finish to write block {} to cache", block.block.header.number);
//     }
// }

/// Clears all cached states.
pub fn clear_cache() {
    clear_plain_state();
}
