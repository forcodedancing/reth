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
            self.last_key = Some(key.clone());
            return Ok(Some((key, result)))
        };

        match self.cursor.seek_exact(StoredNibbles(key))? {
            Some(value) => {
                self.last_key = Some(value.0 .0.clone());
                Ok(Some((value.0 .0, value.1)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Seek a key in the account trie that matches or is greater than the provided key.
    fn seek_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        if let Some(result) = self.trie_cache.get_account(&key) {
            self.last_key = Some(key.clone());
            return Ok(Some((key, result)))
        };

        match self.cursor.seek(StoredNibbles(key))? {
            Some(value) => {
                self.last_key = Some(value.0 .0.clone());
                Ok(Some((value.0 .0, value.1)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Move the cursor to the next entry in the account trie.
    fn next_inner(
        &mut self,
        last_key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        match self.cursor.seek(StoredNibbles(last_key.clone()))? {
            None => {
                self.last_key = None;
                return Ok(None);
            }
            Some(entry) => {
                if entry.0 .0.clone() > last_key.clone() {
                    // next is done already
                    self.last_key = Some(entry.0 .0.clone());
                    return Ok(Some((entry.0 .0, entry.1)));
                }
            }
        };

        match self.cursor.next()? {
            Some(value) => {
                self.last_key = Some(value.0 .0.clone());
                Ok(Some((value.0 .0, value.1)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
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
        let entry = self.seek_exact_inner(key.clone())?;
        Ok(entry)
    }

    /// Seeks a key in the account trie that matches or is greater than the provided key.
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_inner(key.clone())?;
        Ok(entry)
    }

    /// Move the cursor to the next entry and return it.
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let next = match &self.last_key {
            Some(last) => self.next_inner(last.clone())?,
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
            self.last_key = Some(key.clone());
            return Ok(Some((key, result)))
        };

        match self
            .cursor
            .seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(key.clone()))?
        {
            Some(entry) => {
                self.last_key = Some(entry.nibbles.0.clone());
                if entry.nibbles == StoredNibblesSubKey(key) {
                    Ok(Some((entry.nibbles.0, entry.node)))
                } else {
                    Ok(None)
                }
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Seek a key in the storage trie that matches or is greater than the provided key.
    fn seek_inner(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let storage_key = (self.hashed_address, key.clone());
        if let Some(result) = self.trie_cache.get_storage(&storage_key) {
            self.last_key = Some(key.clone());
            return Ok(Some((key, result)))
        };

        match self.cursor.seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(key))? {
            Some(value) => {
                self.last_key = Some(value.nibbles.0.clone());
                Ok(Some((value.nibbles.0, value.node)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Move the cursor to the next entry in the storage trie.
    fn next_inner(
        &mut self,
        last_key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        match self
            .cursor
            .seek_by_key_subkey(self.hashed_address, StoredNibblesSubKey(last_key.clone()))?
        {
            None => {
                self.last_key = None;
                return Ok(None);
            }
            Some(entry) => {
                if entry.nibbles.0.clone() > last_key {
                    // next is done already
                    self.last_key = Some(entry.nibbles.0.clone());
                    return Ok(Some((entry.nibbles.0.clone(), entry.node)));
                }
            }
        }

        match self.cursor.next_dup()? {
            Some((_, value)) => {
                self.last_key = Some(value.nibbles.0.clone());
                Ok(Some((value.nibbles.0, value.node)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
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
        let entry = self.seek_exact_inner(key.clone())?;
        Ok(entry)
    }

    /// Seeks the given key in the storage trie.
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let entry = self.seek_inner(key.clone())?;
        Ok(entry)
    }

    /// Move the cursor to the next entry and return it.
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let next = match &self.last_key {
            Some(last) => {
                let entry = self.next_inner(last.clone())?;
                entry
            }
            // no previous entry was found
            None => None,
        };
        Ok(next)
    }

    /// Retrieves the current key in the storage trie cursor.
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        match &self.last_key {
            Some(key) => Ok(Some(key.clone())),
            None => Ok(self.cursor.current()?.map(|(_, v)| v.nibbles.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseAccountTrieCursor, DatabaseStorageTrieCursor};
    use lazy_static::lazy_static;
    use quick_cache::sync::Cache;
    use reth_db_api::{cursor::DbCursorRW, transaction::DbTxMut};
    use reth_provider::test_utils::create_test_provider_factory;
    use reth_trie_common::StorageTrieEntry;
    use tokio::io::AsyncSeekExt;

    type TrieStorageKey = (B256, Nibbles);

    lazy_static! {
        static ref accounts: Cache<Nibbles, BranchNodeCompact> = Cache::new(100);
        static ref storages: Cache<TrieStorageKey, BranchNodeCompact> = Cache::new(100);
        pub static ref cached_trie: (
            &'static Cache<Nibbles, BranchNodeCompact>,
            &'static Cache<TrieStorageKey, BranchNodeCompact>
        ) = (&accounts, &storages);
    }

    impl TrieCache<Nibbles, BranchNodeCompact, TrieStorageKey, BranchNodeCompact> for cached_trie {
        fn get_account(&self, k: &Nibbles) -> Option<BranchNodeCompact> {
            self.0.get(k)
        }

        fn get_storage(&self, k: &TrieStorageKey) -> Option<BranchNodeCompact> {
            self.1.get(k)
        }
    }

    #[test]
    fn test_account_cursor() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_write::<tables::AccountsTrie>().unwrap();

        let key1 = Nibbles::from_vec(vec![0x2, 03]);
        let value1 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key2 = Nibbles::from_vec(vec![0x3, 04]);
        let value2 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key3 = Nibbles::from_vec(vec![0x4, 05]);
        let value3 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);

        cursor.upsert(reth_trie_common::StoredNibbles(key1.clone()), value1.clone()).unwrap();
        cursor.upsert(reth_trie_common::StoredNibbles(key2.clone()), value2.clone()).unwrap();
        cursor.upsert(reth_trie_common::StoredNibbles(key3.clone()), value3.clone()).unwrap();

        // database cursor
        let cursor = provider.tx_ref().cursor_write::<tables::AccountsTrie>().unwrap();
        let mut db_cursor = DatabaseAccountTrieCursor::new(cursor);
        assert_eq!(db_cursor.seek(key1.clone()).unwrap().unwrap().1, value1);
        assert_eq!(db_cursor.current().unwrap().unwrap(), key1.clone());

        assert_eq!(db_cursor.seek(key2.clone().into()).unwrap().unwrap().1, value2.clone().into());
        assert_eq!(db_cursor.current().unwrap().unwrap(), key2.clone());

        assert_eq!(db_cursor.seek(key3.clone()).unwrap().unwrap().1, value3.clone().into());
        assert_eq!(db_cursor.current().unwrap().unwrap(), key3.clone());

        assert_eq!(db_cursor.next(), Ok(None));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key3.clone());

        let cursor = provider.tx_ref().cursor_write::<tables::AccountsTrie>().unwrap();
        let mut db_cursor = DatabaseAccountTrieCursor::new(cursor);
        assert_eq!(db_cursor.seek(key1.clone()).unwrap().unwrap().1, value1.clone());
        assert_eq!(db_cursor.current().unwrap().unwrap(), key1.clone());

        assert_eq!(db_cursor.next().unwrap().unwrap().1, value2.clone());
        assert_eq!(db_cursor.current().unwrap().unwrap(), key2.clone());

        assert_eq!(db_cursor.next().unwrap().unwrap().1, value3.clone());
        assert_eq!(db_cursor.current().unwrap().unwrap(), key3.clone());

        assert_eq!(db_cursor.next(), Ok(None));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key3.clone());

        for i in 1..4 {
            if i == 1 {
                accounts.insert(key1.clone(), value1.clone());
            }
            if i == 2 {
                accounts.insert(key1.clone(), value1.clone());
                accounts.insert(key2.clone(), value2.clone());
            }

            // cached cursor
            let cursor = provider.tx_ref().cursor_write::<tables::AccountsTrie>().unwrap();
            let mut cache_cursor = CachedAccountTrieCursor::new(cursor, &cached_trie);
            assert_eq!(cache_cursor.seek(key1.clone()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key1.clone());

            assert_eq!(cache_cursor.seek(key2.clone()).unwrap().unwrap().1, value2.clone());
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key2.clone());

            assert_eq!(cache_cursor.seek(key3.clone()).unwrap().unwrap().1, value3.clone());
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key3.clone());

            assert_eq!(cache_cursor.next(), Ok(None));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key3.clone());

            let cursor = provider.tx_ref().cursor_write::<tables::AccountsTrie>().unwrap();
            let mut cache_cursor = CachedAccountTrieCursor::new(cursor, &cached_trie);
            assert_eq!(cache_cursor.seek(key1.clone()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key1.clone());

            assert_eq!(cache_cursor.next().unwrap().unwrap().1, value2.clone());
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key2.clone());

            assert_eq!(cache_cursor.next().unwrap().unwrap().1, value3.clone());
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key3.clone());

            assert_eq!(cache_cursor.next(), Ok(None));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key3.clone());
        }
    }

    #[test]
    fn test_storage_cursor() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();

        let hashed_address1 = B256::from([0; 32]);
        let key1 = StoredNibblesSubKey::from(vec![0x2, 0x3]);
        let value1 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key2 = StoredNibblesSubKey::from(vec![0x2, 0x4]);
        let value2 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);

        cursor
            .upsert(
                hashed_address1,
                StorageTrieEntry { nibbles: key1.clone(), node: value1.clone() },
            )
            .unwrap();
        cursor
            .upsert(
                hashed_address1,
                StorageTrieEntry { nibbles: key2.clone(), node: value2.clone() },
            )
            .unwrap();

        let hashed_address2 = B256::from([2; 32]);
        let key3 = StoredNibblesSubKey::from(vec![0x4, 0x3]);
        let value3 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key4 = StoredNibblesSubKey::from(vec![0x4, 0x4]);
        let value4 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);

        cursor
            .upsert(
                hashed_address2,
                StorageTrieEntry { nibbles: key3.clone(), node: value3.clone() },
            )
            .unwrap();
        cursor
            .upsert(
                hashed_address2,
                StorageTrieEntry { nibbles: key4.clone(), node: value4.clone() },
            )
            .unwrap();

        // database cursor
        let cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();
        let mut db_cursor = DatabaseStorageTrieCursor::new(cursor, hashed_address1);
        assert_eq!(db_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value1);
        assert_eq!(db_cursor.current().unwrap().unwrap(), key1.0);

        assert_eq!(db_cursor.seek(key2.clone().into()).unwrap().unwrap().1, value2);
        assert_eq!(db_cursor.current().unwrap().unwrap(), key2.clone().0);

        assert_eq!(db_cursor.next(), Ok(None));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key2.0);

        let cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();
        let mut db_cursor = DatabaseStorageTrieCursor::new(cursor, hashed_address2);
        assert_eq!(db_cursor.seek(key3.clone().into()).unwrap().unwrap().1, value3);
        assert_eq!(db_cursor.current().unwrap().unwrap(), key3.0);

        assert_eq!(db_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key4.clone().0);

        assert_eq!(db_cursor.next(), Ok(None));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key4.0);

        assert_eq!(db_cursor.next(), Ok(None));
        assert_eq!(db_cursor.current().unwrap().unwrap(), key4.0);

        for i in 1..4 {
            if i == 1 {
                storages.insert((hashed_address1.clone(), key2.clone().into()), value2.clone());

                let hashed_address3 = B256::from([1; 32]);
                let key5 = StoredNibblesSubKey::from(vec![0x10, 0x11]);
                let value5 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
                storages.insert((hashed_address3.clone(), key5.clone().into()), value5.clone());
            }
            if i == 2 {
                storages.insert((hashed_address2.clone(), key4.clone().into()), value4.clone());
            }
            if i == 3 {
                storages.insert((hashed_address2.clone(), key3.clone().into()), value3.clone());
            }

            // cached cursor
            let cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();
            let mut cache_cursor =
                CachedStorageTrieCursor::new(cursor, hashed_address1, &cached_trie);
            assert_eq!(cache_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key1.0);

            assert_eq!(cache_cursor.seek(key2.clone().into()).unwrap().unwrap().1, value2);
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key2.clone().0);

            assert_eq!(cache_cursor.next(), Ok(None));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key2.0);

            let cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();
            let mut cache_cursor =
                CachedStorageTrieCursor::new(cursor, hashed_address2, &cached_trie);
            assert_eq!(cache_cursor.seek(key3.clone().into()).unwrap().unwrap().1, value3);
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key3.0);

            assert_eq!(cache_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key4.clone().0);

            assert_eq!(cache_cursor.next(), Ok(None));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key4.0);

            assert_eq!(cache_cursor.next(), Ok(None));
            assert_eq!(cache_cursor.current().unwrap().unwrap(), key4.0);
        }
    }

    #[test]
    fn test_storage_cursor_back_and_forth() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();

        let hashed_address1 = B256::from([0; 32]);
        let key1 = StoredNibblesSubKey::from(vec![0x2, 0x3]);
        let value1 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        let key2 = StoredNibblesSubKey::from(vec![0x2, 0x4]);
        let value2 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);

        cursor
            .upsert(
                hashed_address1,
                StorageTrieEntry { nibbles: key1.clone(), node: value1.clone() },
            )
            .unwrap();
        cursor
            .upsert(
                hashed_address1,
                StorageTrieEntry { nibbles: key2.clone(), node: value2.clone() },
            )
            .unwrap();

        let key3 = StoredNibblesSubKey::from(vec![0x2, 0x2]);
        let value3 = BranchNodeCompact::new(1, 1, 1, vec![B256::random()], None);
        storages.insert((hashed_address1.clone(), key3.clone().into()), value3.clone());

        let cursor = provider.tx_ref().cursor_dup_write::<tables::StoragesTrie>().unwrap();
        let mut cache_cursor = CachedStorageTrieCursor::new(cursor, hashed_address1, &cached_trie);
        assert_eq!(cache_cursor.seek(key2.clone().0).unwrap().unwrap().1, value2.clone());
        assert_eq!(cache_cursor.seek(key3.clone().0).unwrap().unwrap().1, value3.clone());
        assert_eq!(cache_cursor.next().unwrap().unwrap().1, value1.clone());
        assert_eq!(cache_cursor.next().unwrap().unwrap().1, value2.clone());
        assert_eq!(cache_cursor.next().unwrap(), None);
    }
}
