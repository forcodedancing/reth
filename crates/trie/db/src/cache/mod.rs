use tracing::debug;

pub mod cached_trie_cursor;
mod trie_node;

pub use crate::cache::trie_node::{clear_trie_node, get_account, write_trie_updates};
