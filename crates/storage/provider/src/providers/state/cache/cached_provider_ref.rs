use crate::{
    providers::{state::macros::delegate_provider_impls, StaticFileProvider},
    AccountReader, BlockHashReader, StateProvider, StateRootProvider,
};
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use reth_db::tables;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    transaction::DbTx,
};
use reth_primitives::{Account, Bytecode, StaticFileSegment};
use reth_storage_api::{StateProofProvider, StorageRootProvider};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use reth_trie::{
    proof::Proof, updates::TrieUpdates, witness::TrieWitness, AccountProof, HashedPostState,
    HashedStorage, MultiProof, StateRoot, StorageRoot, TrieInput,
};
use reth_trie_db::{DatabaseProof, DatabaseStateRoot, DatabaseStorageRoot, DatabaseTrieWitness};
use std::collections::{HashMap, HashSet};

/// State provider over latest state that takes tx reference.
#[derive(Debug)]
pub struct CachedStateProviderRef<'b, TX: DbTx> {
    /// database transaction
    tx: &'b TX,
    /// Static File provider
    static_file_provider: StaticFileProvider,
}

impl<'b, TX: DbTx> CachedStateProviderRef<'b, TX> {
    /// Create new state provider
    pub const fn new(tx: &'b TX, static_file_provider: StaticFileProvider) -> Self {
        Self { tx, static_file_provider }
    }
}

impl<'b, TX: DbTx> AccountReader for CachedStateProviderRef<'b, TX> {
    /// Get basic account information.
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        if let Some(v) = crate::providers::state::cache::plain_state::get_account(&address) {
            return Ok(Some(v))
        }
        if let Some(value) = self.tx.get::<tables::PlainAccountState>(address)? {
            crate::providers::state::cache::plain_state::insert_account(address, value);
            return Ok(Some(value))
        }
        Ok(None)
    }
}

impl<'b, TX: DbTx> BlockHashReader for CachedStateProviderRef<'b, TX> {
    /// Get block hash by number.
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Headers,
            number,
            |static_file| static_file.block_hash(number),
            || Ok(self.tx.get::<tables::CanonicalHeaders>(number)?),
        )
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::Headers,
            start..end,
            |static_file, range, _| static_file.canonical_hashes_range(range.start, range.end),
            |range, _| {
                self.tx
                    .cursor_read::<tables::CanonicalHeaders>()
                    .map(|mut cursor| {
                        cursor
                            .walk_range(range)?
                            .map(|result| result.map(|(_, hash)| hash).map_err(Into::into))
                            .collect::<ProviderResult<Vec<_>>>()
                    })?
                    .map_err(Into::into)
            },
            |_| true,
        )
    }
}

impl<'b, TX: DbTx> StateRootProvider for CachedStateProviderRef<'b, TX> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        StateRoot::overlay_root(self.tx, hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        StateRoot::overlay_root_from_nodes(self.tx, input)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_with_updates(self.tx, hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_from_nodes_with_updates(self.tx, input)
            .map_err(|err| ProviderError::Database(err.into()))
    }
}

impl<'b, TX: DbTx> StorageRootProvider for CachedStateProviderRef<'b, TX> {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        StorageRoot::overlay_root(self.tx, address, hashed_storage)
            .map_err(|err| ProviderError::Database(err.into()))
    }
}

impl<'b, TX: DbTx> StateProofProvider for CachedStateProviderRef<'b, TX> {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Proof::overlay_account_proof(self.tx, input, address, slots)
            .map_err(Into::<ProviderError>::into)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: HashMap<B256, HashSet<B256>>,
    ) -> ProviderResult<MultiProof> {
        Proof::overlay_multiproof(self.tx, input, targets).map_err(Into::<ProviderError>::into)
    }

    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
    ) -> ProviderResult<HashMap<B256, Bytes>> {
        TrieWitness::overlay_witness(self.tx, input, target).map_err(Into::<ProviderError>::into)
    }
}

impl<'b, TX: DbTx> StateProvider for CachedStateProviderRef<'b, TX> {
    /// Get storage.
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let key = (account, storage_key);
        if let Some(v) = crate::providers::state::cache::plain_state::get_storage(&key) {
            return Ok(Some(v))
        }

        let mut cursor = self.tx.cursor_dup_read::<tables::PlainStorageState>()?;
        if let Some(entry) = cursor.seek_by_key_subkey(account, storage_key)? {
            if entry.key == storage_key {
                crate::providers::state::cache::plain_state::insert_storage(key, entry.value);
                return Ok(Some(entry.value))
            }
        }
        Ok(None)
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(v) = crate::providers::state::cache::plain_state::get_code(&code_hash) {
            return Ok(Some(v))
        }
        if let Some(value) = self.tx.get::<tables::Bytecodes>(code_hash)? {
            crate::providers::state::cache::plain_state::insert_code(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}
