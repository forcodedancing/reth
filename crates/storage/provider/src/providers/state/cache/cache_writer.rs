use crate::providers::state::cache::plain_state::{PLAIN_ACCOUNTS, PLAIN_STORAGES};
use alloy_primitives::StorageKey;
use quick_cache::sync::Cache;
use reth_chain_state::ExecutedBlock;
use reth_db::{cursor::DbDupCursorRO, table::TableRow, tables, DatabaseError, PlainStorageState};
use reth_db_api::transaction::DbTx;
use reth_primitives::Account;
use revm::db::{states::StateChangeset, BundleState, OriginalValuesKnown};
use tracing::info;

pub struct PlainCacheWriter<'a, TX>(&'a TX);

impl<'a, TX> PlainCacheWriter<'a, TX> {
    pub const fn new(tx: &'a TX) -> Self {
        Self(tx)
    }
}

impl<'a, TX> PlainCacheWriter<'a, TX> {
    /// Write committed state to cache.
    pub fn write_executed_blocks(&mut self, blocks: Vec<ExecutedBlock>)
    where
        TX: DbTx,
    {
        for block in blocks {
            if block.block.number % 100 == 0 {
                info!(
                    "ACCOUNT_CACHE_SZ {}, block number {}",
                    super::plain_state::PLAIN_ACCOUNTS.len(),
                    block.block.number
                );
                info!(
                    "STORAGE_CACHE_SZ {}, block number {}",
                    super::plain_state::PLAIN_STORAGES.len(),
                    block.block.number
                );
            };

            let bundle_state = block.execution_outcome().clone().bundle;
            let change_set = bundle_state.into_plain_state(OriginalValuesKnown::Yes);
            self.write_change_set(0, &change_set);
        }
    }

    pub fn write_change_set(&mut self, last_block: u64, change_set: &StateChangeset)
    where
        TX: DbTx,
    {
        if last_block > 0 {
            info!(
                "block number {}, P_ACCOUNT_CACHE_SZ {}",
                last_block,
                super::plain_state::PLAIN_ACCOUNTS.len(),
            );
            info!(
                "block number {}, P_STORAGE_CACHE_SZ {}",
                last_block,
                super::plain_state::PLAIN_STORAGES.len(),
            );
        }
        // Update account cache
        for (address, account_info) in &change_set.accounts {
            match account_info {
                None => {
                    super::plain_state::PLAIN_ACCOUNTS.remove(address);
                }
                Some(acc) => {
                    super::plain_state::PLAIN_ACCOUNTS.insert(
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

        let cursor = self.0.cursor_dup_read::<tables::PlainStorageState>();
        match cursor {
            Ok(mut cursor) => {
                // Update storage cache
                for storage in &change_set.storage {
                    if storage.wipe_storage {
                        let walker = cursor.walk_dup(Some(storage.address), None);
                        match walker {
                            Ok(walker) => {
                                for kv in walker {
                                    match kv {
                                        Ok((k, v)) => {
                                            super::plain_state::PLAIN_STORAGES.remove(&(k, v.key));
                                        }
                                        Err(_) => {
                                            super::plain_state::PLAIN_STORAGES.clear();
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                super::plain_state::PLAIN_STORAGES.clear();
                                break;
                            }
                        }
                    }

                    for (k, v) in storage.storage.clone() {
                        super::plain_state::PLAIN_STORAGES
                            .insert((storage.address, StorageKey::from(k)), v);
                    }
                }
            }
            Err(_) => {
                super::plain_state::PLAIN_STORAGES.clear();
            }
        }
    }
}

/// Clear cached accounts and storages.
pub fn clear_plain_state() {
    PLAIN_ACCOUNTS.clear();
    PLAIN_STORAGES.clear();
}
