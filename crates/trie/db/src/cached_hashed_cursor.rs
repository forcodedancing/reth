use reth_db::tables;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    transaction::DbTx,
};
use reth_primitives::{Account, B256, U256};
use reth_storage_errors::db::DatabaseError;
use reth_trie::{
    cache::TrieCache,
    hashed_cursor::{HashedCursor, HashedCursorFactory, HashedStorageCursor},
};

/// Factory for creating cached hashed cursors.
pub(crate) struct CachedHashedCursorFactory<'a, TX> {
    tx: &'a TX,
    hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
}

impl<'a, TX> Clone for CachedHashedCursorFactory<'a, TX> {
    fn clone(&self) -> Self {
        Self { tx: self.tx, hashed_cache: self.hashed_cache }
    }
}

impl<'a, TX> CachedHashedCursorFactory<'a, TX> {
    /// Creates a new `CachedHashedCursorFactory`.
    pub(crate) const fn new(
        tx: &'a TX,
        hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
    ) -> Self {
        Self { tx, hashed_cache }
    }
}

impl<'a, TX: DbTx> HashedCursorFactory for CachedHashedCursorFactory<'a, TX> {
    type AccountCursor = CachedHashedAccountCursor<<TX as DbTx>::Cursor<tables::HashedAccounts>>;
    type StorageCursor = CachedHashedStorageCursor<<TX as DbTx>::DupCursor<tables::HashedStorages>>;

    /// Creates a new hashed account cursor.
    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, reth_db::DatabaseError> {
        Ok(CachedHashedAccountCursor::new(
            self.tx.cursor_read::<tables::HashedAccounts>()?,
            self.hashed_cache,
        ))
    }

    /// Creates a new hashed storage cursor.
    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, reth_db::DatabaseError> {
        Ok(CachedHashedStorageCursor::new(
            self.tx.cursor_dup_read::<tables::HashedStorages>()?,
            hashed_address,
            self.hashed_cache,
        ))
    }
}

/// Cursor for iterating over cached hashed accounts.
pub(crate) struct CachedHashedAccountCursor<C> {
    /// Database hashed account cursor.
    cursor: C,
    /// Cache layer.
    hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
    /// Last key with value.
    last_key: Option<B256>,
}

impl<C> CachedHashedAccountCursor<C>
where
    C: DbCursorRO<tables::HashedAccounts>,
{
    /// Creates a new `CachedHashedAccountCursor`.
    pub(crate) const fn new(
        cursor: C,
        hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
    ) -> Self {
        Self { cursor, hashed_cache, last_key: None }
    }

    /// Seeks the cursor to the specified key.
    fn seek_inner(&mut self, key: B256) -> Result<Option<(B256, Account)>, DatabaseError> {
        if let Some(result) = self.hashed_cache.get_account(&key) {
            return Ok(Some((key, result)))
        };
        match self.cursor.seek(key)? {
            Some((key, value)) => {
                self.hashed_cache.insert_account(key, value);

                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }

    /// Moves the cursor to the next entry.
    fn next_inner(&mut self, last_key: B256) -> Result<Option<(B256, Account)>, DatabaseError> {
        let _ = self.cursor.seek(last_key)?;
        match self.cursor.next()? {
            Some(entry) => {
                self.hashed_cache.insert_account(entry.0, entry.1);
                Ok(Some((entry.0, entry.1)))
            }
            None => Ok(None),
        }
    }
}

impl<C> HashedCursor for CachedHashedAccountCursor<C>
where
    C: DbCursorRO<tables::HashedAccounts>,
{
    type Value = Account;

    /// Seeks the cursor to the specified key.
    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        let entry = self.seek_inner(key)?;
        self.last_key = entry.as_ref().map(|entry| entry.0);
        Ok(entry)
    }

    /// Moves the cursor to the next entry.
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        let next = match self.last_key {
            Some(last_account) => {
                let entry = self.next_inner(last_account)?;
                self.last_key = entry.as_ref().map(|entry| entry.0);
                entry
            }
            // no previous entry was found
            None => None,
        };
        Ok(next)
    }
}

/// Cursor for iterating over cached hashed storages.
pub(crate) struct CachedHashedStorageCursor<C> {
    /// Database hashed storage cursor.
    cursor: C,
    /// Cache layer.
    hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
    /// Target hashed address of the account that the storage belongs to.
    hashed_address: B256,
    /// Last key with value.
    last_key: Option<B256>,
}

impl<C> CachedHashedStorageCursor<C>
where
    C: DbCursorRO<tables::HashedStorages> + DbDupCursorRO<tables::HashedStorages>,
{
    /// Creates a new `CachedHashedStorageCursor`.
    pub(crate) const fn new(
        cursor: C,
        hashed_address: B256,
        hashed_cache: &'static dyn TrieCache<B256, Account, (B256, B256), U256>,
    ) -> Self {
        Self { cursor, hashed_cache, hashed_address, last_key: None }
    }

    /// Seeks the cursor to the specified subkey.
    fn seek_inner(&mut self, subkey: B256) -> Result<Option<(B256, U256)>, DatabaseError> {
        let storage_key = (self.hashed_address, subkey);
        if let Some(result) = self.hashed_cache.get_storage(&storage_key) {
            return Ok(Some((subkey, result)))
        };

        match self.cursor.seek_by_key_subkey(self.hashed_address, subkey)? {
            Some(entry) => {
                let storage_key = (self.hashed_address, entry.key);
                self.hashed_cache.insert_storage(storage_key, entry.value);

                Ok(Some((entry.key, entry.value)))
            }
            None => Ok(None),
        }
    }

    /// Finds the storage entry that is right after the current cursor position.
    fn next_inner(&mut self, last_key: B256) -> Result<Option<(B256, U256)>, DatabaseError> {
        let _ = self.cursor.seek_by_key_subkey(self.hashed_address, last_key)?;
        match self.cursor.next_dup()? {
            Some(entry) => {
                let storage_key = (entry.0, entry.1.key);
                self.hashed_cache.insert_storage(storage_key, entry.1.value);

                Ok(Some((entry.1.key, entry.1.value)))
            }
            None => Ok(None),
        }
    }
}

impl<C> HashedCursor for CachedHashedStorageCursor<C>
where
    C: DbCursorRO<tables::HashedStorages> + DbDupCursorRO<tables::HashedStorages>,
{
    type Value = U256;

    /// Seeks the cursor to the specified subkey.
    fn seek(&mut self, subkey: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        let entry = self.seek_inner(subkey)?;
        self.last_key = entry.as_ref().map(|entry| entry.0);
        Ok(entry)
    }

    /// Moves the cursor to the next entry.
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        let next = match self.last_key {
            Some(last_slot) => {
                let entry = self.next_inner(last_slot)?;
                self.last_key = entry.as_ref().map(|entry| entry.0);
                entry
            }
            // no previous entry was found
            None => None,
        };
        Ok(next)
    }
}

impl<C> HashedStorageCursor for CachedHashedStorageCursor<C>
where
    C: DbCursorRO<tables::HashedStorages> + DbDupCursorRO<tables::HashedStorages>,
{
    /// Checks if the storage is empty.
    fn is_storage_empty(&mut self) -> Result<bool, reth_db::DatabaseError> {
        Ok(self.cursor.seek_exact(self.hashed_address)?.is_none())
    }
}
