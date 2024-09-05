use reth_db::tables;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    transaction::DbTx,
};
use reth_primitives::B256;
use reth_storage_errors::db::DatabaseError;
use reth_trie::{
    cache::TrieCache,
    trie_cursor::{TrieCursor, TrieCursorFactory},
    BranchNodeCompact, Nibbles, StoredNibbles, StoredNibblesSubKey,
};

/// Wrapper struct for database transaction implementing trie cursor factory trait.
pub(crate) struct CachedTrieCursorFactory<'a, TX> {
    tx: &'a TX,
    trie_cache:
        &'static dyn TrieCache<Nibbles, BranchNodeCompact, (B256, Nibbles), BranchNodeCompact>,
}

impl<'a, TX> Clone for CachedTrieCursorFactory<'a, TX> {
    fn clone(&self) -> Self {
        Self { tx: self.tx, trie_cache: self.trie_cache }
    }
}

impl<'a, TX> CachedTrieCursorFactory<'a, TX> {
    /// Create new [`CachedTrieCursorFactory`].
    pub(crate) const fn new(
        tx: &'a TX,
        trie_cache: &'static dyn TrieCache<
            Nibbles,
            BranchNodeCompact,
            (B256, Nibbles),
            BranchNodeCompact,
        >,
    ) -> Self {
        Self { tx, trie_cache }
    }
}

/// Implementation of the trie cursor factory for a database transaction.
impl<'a, TX: DbTx> TrieCursorFactory for CachedTrieCursorFactory<'a, TX> {
    type AccountTrieCursor = CachedAccountTrieCursor<<TX as DbTx>::Cursor<tables::AccountsTrie>>;
    type StorageTrieCursor = CachedStorageTrieCursor<<TX as DbTx>::DupCursor<tables::StoragesTrie>>;

    /// Create a new account trie cursor.
    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, DatabaseError> {
        Ok(CachedAccountTrieCursor::new(
            self.tx.cursor_read::<tables::AccountsTrie>()?,
            self.trie_cache,
        ))
    }

    /// Create a new storage trie cursor.
    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, DatabaseError> {
        Ok(CachedStorageTrieCursor::new(
            self.tx.cursor_dup_read::<tables::StoragesTrie>()?,
            hashed_address,
            self.trie_cache,
        ))
    }
}

/// A cursor over the account trie.
pub(crate) struct CachedAccountTrieCursor<C> {
    /// Database trie account cursor.
    cursor: C,
    /// Cache layer.
    trie_cache:
        &'static dyn TrieCache<Nibbles, BranchNodeCompact, (B256, Nibbles), BranchNodeCompact>,
    /// Last key with value.
    last_key: Option<Nibbles>,
}

impl<C> CachedAccountTrieCursor<C>
where
    C: DbCursorRO<tables::AccountsTrie> + Send + Sync,
{
    /// Create a new account trie cursor.
    pub(crate) const fn new(
        cursor: C,
        trie_cache: &'static dyn TrieCache<
            Nibbles,
            BranchNodeCompact,
            (B256, Nibbles),
            BranchNodeCompact,
        >,
    ) -> Self {
        Self { cursor, trie_cache, last_key: None }
    }

    /// Seek an exact match for the given key in the account trie.
    fn seek_exact_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        if let Some(result) = self.trie_cache.get_account(&key) {
            return Ok(Some((key, result)))
        };

        match self.cursor.seek_exact(StoredNibbles(key))? {
            Some(value) => {
                self.trie_cache.insert_account(value.0 .0.clone(), value.1.clone());

                Ok(Some((value.0 .0, value.1)))
            }
            None => Ok(None),
        }
    }

    /// Seek a key in the account trie that matches or is greater than the provided key.
    fn seek_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        if let Some(result) = self.trie_cache.get_account(&key) {
            return Ok(Some((key, result)))
        };

        return match self.cursor.seek(StoredNibbles(key))? {
            Some(value) => {
                self.trie_cache.insert_account(value.0 .0.clone(), value.1.clone());

                Ok(Some((value.0 .0, value.1)))
            }
            None => Ok(None),
        };
    }

    /// Move the cursor to the next entry in the account trie.
    fn next_inner(
        &mut self,
        last: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let _ = self.cursor.seek(StoredNibbles(last.clone()))?;
        match self.cursor.next()? {
            Some(value) => {
                self.trie_cache.insert_account(value.0 .0.clone(), value.1.clone());

                Ok(Some((value.0 .0, value.1)))
            }
            None => Ok(None),
        }
    }
}

impl<C> TrieCursor for CachedAccountTrieCursor<C>
where
    C: DbCursorRO<tables::AccountsTrie> + Send + Sync,
{
    /// Seeks an exact match for the given key in the account trie.
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_exact_inner(key)?;
        self.last_key = entry.as_ref().map(|(nibbles, _)| nibbles.clone());
        Ok(entry)
    }

    /// Seeks a key in the account trie that matches or is greater than the provided key.
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_inner(key)?;
        self.last_key = entry.as_ref().map(|(nibbles, _)| nibbles.clone());
        Ok(entry)
    }

    /// Move the cursor to the next entry and return it.
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let next = match &self.last_key {
            Some(last) => {
                let entry = self.next_inner(last.clone())?;
                self.last_key = entry.as_ref().map(|entry| entry.0.clone());
                entry
            }
            // no previous entry was found
            None => None,
        };
        Ok(next)
    }

    /// Retrieves the current key in the cursor.
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        match &self.last_key {
            Some(key) => Ok(Some(key.clone())),
            None => Ok(self.cursor.current()?.map(|(k, _)| k.0)),
        }
    }
}

/// A cursor over the storage tries stored in the database.
pub(crate) struct CachedStorageTrieCursor<C> {
    /// Database trie storage cursor.
    pub cursor: C,
    /// Cache layer.
    trie_cache:
        &'static dyn TrieCache<Nibbles, BranchNodeCompact, (B256, Nibbles), BranchNodeCompact>,
    /// Hashed address used for cursor positioning.
    hashed_address: B256,
    /// Last key with value.
    last_key: Option<Nibbles>,
}

impl<C> CachedStorageTrieCursor<C>
where
    C: DbCursorRO<tables::StoragesTrie> + DbDupCursorRO<tables::StoragesTrie> + Send + Sync,
{
    /// Create a new storage trie cursor.
    pub(crate) const fn new(
        cursor: C,
        hashed_address: B256,
        trie_cache: &'static dyn TrieCache<
            Nibbles,
            BranchNodeCompact,
            (B256, Nibbles),
            BranchNodeCompact,
        >,
    ) -> Self {
        Self { cursor, trie_cache, hashed_address, last_key: None }
    }

    /// Seek an exact match for the given key in the storage trie.
    fn seek_exact_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let storage_key = (self.hashed_address, key.clone());
        if let Some(result) = self.trie_cache.get_storage(&storage_key) {
            return Ok(Some((key, result)))
        };

        return match self
            .cursor
            .seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(key.clone()))?
        {
            Some(entry) => {
                let storage_key = (self.hashed_address, entry.nibbles.0.clone());
                self.trie_cache.insert_storage(storage_key, entry.node.clone());

                if entry.nibbles == StoredNibblesSubKey(key) {
                    Ok(Some((entry.nibbles.0, entry.node)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        };
    }

    /// Seek a key in the storage trie that matches or is greater than the provided key.
    fn seek_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let storage_key = (self.hashed_address, key.clone());
        if let Some(result) = self.trie_cache.get_storage(&storage_key) {
            return Ok(Some((key, result)))
        };

        return match self
            .cursor
            .seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(key))?
        {
            Some(value) => {
                let key = (self.hashed_address, value.nibbles.0.clone());
                self.trie_cache.insert_storage(key, value.node.clone());

                Ok(Some((value.nibbles.0, value.node)))
            }
            None => Ok(None),
        };
    }

    /// Move the cursor to the next entry in the storage trie.
    fn next_inner(
        &mut self,
        last: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let _ = self.cursor.seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(last))?;

        match self.cursor.next_dup()? {
            Some((_, value)) => {
                let storage_key = (self.hashed_address, value.nibbles.0.clone());
                self.trie_cache.insert_storage(storage_key, value.node.clone());

                Ok(Some((value.nibbles.0, value.node)))
            }
            None => Ok(None),
        }
    }
}

impl<C> TrieCursor for CachedStorageTrieCursor<C>
where
    C: DbCursorRO<tables::StoragesTrie> + DbDupCursorRO<tables::StoragesTrie> + Send + Sync,
{
    /// Seeks an exact match for the given key in the storage trie.
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_exact_inner(key)?;
        self.last_key = entry.as_ref().map(|(nibbles, _)| nibbles.clone());
        Ok(entry)
    }

    /// Seeks the given key in the storage trie.
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_inner(key)?;
        self.last_key = entry.as_ref().map(|(nibbles, _)| nibbles.clone());
        Ok(entry)
    }

    /// Move the cursor to the next entry and return it.
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let next = match &self.last_key {
            Some(last) => {
                let entry = self.next_inner(last.clone())?;
                self.last_key = entry.as_ref().map(|entry| entry.0.clone());
                entry
            }
            // no previous entry was found
            None => None,
        };
        Ok(next)
    }

    /// Retrieves the current value in the storage trie cursor.
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        match &self.last_key {
            Some(key) => Ok(Some(key.clone())),
            None => Ok(self.cursor.current()?.map(|(_, v)| v.nibbles.0)),
        }
    }
}
