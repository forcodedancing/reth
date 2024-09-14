use metrics::counter;
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
            self.last_key = Some(key);

            return Ok(Some((key, result)))
        };
        match self.cursor.seek(key)? {
            Some((key, value)) => {
                self.last_key = Some(key);
                Ok(Some((key, value)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Moves the cursor to the next entry.
    fn next_inner(&mut self, last_key: B256) -> Result<Option<(B256, Account)>, DatabaseError> {
        match self.cursor.seek(last_key)? {
            None => {
                self.last_key = None;
                return Ok(None);
            }
            Some(entry) => {
                if entry.0 > last_key {
                    // next is done already
                    self.last_key = Some(entry.0);
                    return Ok(Some((entry.0, entry.1)));
                }
            }
        };

        match self.cursor.next()? {
            Some(entry) => {
                self.last_key = Some(entry.0);
                Ok(Some((entry.0, entry.1)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
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
        Ok(entry)
    }

    /// Moves the cursor to the next entry.
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        counter!("hashed_next.account.total").increment(1);

        let next = match self.last_key {
            Some(last_account) => {
                let entry = self.next_inner(last_account)?;
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
            self.last_key = Some(subkey);
            return Ok(Some((subkey, result)))
        };

        match self.cursor.seek_by_key_subkey(self.hashed_address, subkey)? {
            Some(entry) => {
                self.last_key = Some(entry.key);
                Ok(Some((entry.key, entry.value)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
        }
    }

    /// Finds the storage entry that is right after the current cursor position.
    fn next_inner(&mut self, last_key: B256) -> Result<Option<(B256, U256)>, DatabaseError> {
        match self.cursor.seek_by_key_subkey(self.hashed_address, last_key)? {
            None => {
                self.last_key = None;
                return Ok(None);
            }
            Some(entry) => {
                if entry.key > last_key {
                    // next is done already
                    self.last_key = Some(entry.key);
                    return Ok(Some((entry.key, entry.value)));
                }
            }
        }

        match self.cursor.next_dup_val()? {
            Some(entry) => {
                self.last_key = Some(entry.key);
                Ok(Some((entry.key, entry.value)))
            }
            None => {
                self.last_key = None;
                Ok(None)
            }
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
        Ok(entry)
    }

    /// Moves the cursor to the next entry.
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        counter!("hashed_next.storage.total").increment(1);

        let next = match self.last_key {
            Some(last_slot) => {
                let entry = self.next_inner(last_slot)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseHashedAccountCursor, DatabaseHashedStorageCursor};
    use lazy_static::lazy_static;
    use quick_cache::sync::Cache;
    use reth_db_api::{cursor::DbCursorRW, transaction::DbTxMut};
    use reth_primitives::StorageEntry;
    use reth_provider::test_utils::create_test_provider_factory;

    type HashedStorageKey = (B256, B256);

    lazy_static! {
        static ref accounts: Cache<B256, Account> = Cache::new(100);
        static ref storages: Cache<HashedStorageKey, U256> = Cache::new(100);
        pub static ref cached_states: (&'static Cache<B256, Account>, &'static Cache<HashedStorageKey, U256>) =
            (&accounts, &storages);
    }

    impl TrieCache<B256, Account, HashedStorageKey, U256> for cached_states {
        fn get_account(&self, k: &B256) -> Option<Account> {
            self.0.get(k)
        }

        fn get_storage(&self, k: &HashedStorageKey) -> Option<U256> {
            self.1.get(k)
        }
    }

    #[test]
    fn test_account_cursor() {
        let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
            .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
            .unwrap();
        let _ = tracing_subscriber::fmt().with_env_filter(filter_layer).try_init();

        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_write::<tables::HashedAccounts>().unwrap();

        let hashed_acc1 = B256::from([0; 32]);
        let value1 = Account { nonce: 1, balance: U256::ZERO, bytecode_hash: None };
        let hashed_acc2 = B256::from([1; 32]);
        let value2 = Account { nonce: 2, balance: U256::ZERO, bytecode_hash: None };
        let hashed_acc3 = B256::from([2; 32]);
        let value3 = Account { nonce: 3, balance: U256::ZERO, bytecode_hash: None };

        cursor.upsert(hashed_acc1, value1.clone()).unwrap();
        cursor.upsert(hashed_acc2, value2.clone()).unwrap();
        cursor.upsert(hashed_acc3, value3.clone()).unwrap();

        // database cursor
        let cursor = provider.tx_ref().cursor_write::<tables::HashedAccounts>().unwrap();
        let mut db_cursor = DatabaseHashedAccountCursor::new(cursor);
        assert_eq!(db_cursor.seek(hashed_acc1.clone()).unwrap().unwrap().1, value1);
        assert_eq!(
            db_cursor.seek(hashed_acc2.clone().into()).unwrap().unwrap().1,
            value2.clone().into()
        );
        assert_eq!(db_cursor.seek(hashed_acc3.clone()).unwrap().unwrap().1, value3.clone().into());
        assert_eq!(db_cursor.next(), Ok(None));

        let cursor = provider.tx_ref().cursor_write::<tables::HashedAccounts>().unwrap();
        let mut db_cursor = DatabaseHashedAccountCursor::new(cursor);
        assert_eq!(db_cursor.seek(hashed_acc1.clone()).unwrap().unwrap().1, value1);
        assert_eq!(db_cursor.next().unwrap().unwrap().1, value2.clone());
        assert_eq!(db_cursor.next().unwrap().unwrap().1, value3.clone());
        assert_eq!(db_cursor.next(), Ok(None));

        for i in 1..4 {
            if i == 1 {
                accounts.insert(hashed_acc2.clone(), value2.clone());
            }
            if i == 2 {
                accounts.insert(hashed_acc1.clone(), value1.clone());
            }
            // cached cursor
            let cursor = provider.tx_ref().cursor_read::<tables::HashedAccounts>().unwrap();
            let mut cache_cursor = CachedHashedAccountCursor::new(cursor, &cached_states);
            assert_eq!(cache_cursor.seek(hashed_acc1.clone()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.seek(hashed_acc2.clone()).unwrap().unwrap().1, value2.clone());
            assert_eq!(cache_cursor.seek(hashed_acc3.clone()).unwrap().unwrap().1, value3.clone());
            assert_eq!(cache_cursor.next(), Ok(None));

            let cursor = provider.tx_ref().cursor_read::<tables::HashedAccounts>().unwrap();
            let mut cache_cursor = CachedHashedAccountCursor::new(cursor, &cached_states);
            assert_eq!(cache_cursor.seek(hashed_acc1.clone()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.next().unwrap().unwrap().1, value2.clone());
            assert_eq!(cache_cursor.next().unwrap().unwrap().1, value3.clone());
            assert_eq!(cache_cursor.next(), Ok(None));
        }
    }

    #[test]
    fn test_storage_cursor() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_dup_write::<tables::HashedStorages>().unwrap();

        let hashed_address1 = B256::from([0; 32]);
        let key1 = B256::from([1; 32]);
        let value1 = U256::from(12);
        let key2 = B256::from([2; 32]);
        let value2 = U256::from(34);

        cursor
            .upsert(hashed_address1, StorageEntry { key: key1.clone(), value: value1.clone() })
            .unwrap();
        cursor
            .upsert(hashed_address1, StorageEntry { key: key2.clone(), value: value2.clone() })
            .unwrap();

        let hashed_address2 = B256::from([1; 32]);
        let key3 = B256::from([3; 32]);
        let value3 = U256::from(56);
        let key4 = B256::from([4; 32]);
        let value4 = U256::from(78);

        cursor
            .upsert(hashed_address2, StorageEntry { key: key3.clone(), value: value3.clone() })
            .unwrap();
        cursor
            .upsert(hashed_address2, StorageEntry { key: key4.clone(), value: value4.clone() })
            .unwrap();

        // database cursor
        let cursor = provider.tx_ref().cursor_dup_write::<tables::HashedStorages>().unwrap();
        let mut db_cursor = DatabaseHashedStorageCursor::new(cursor, hashed_address1);
        assert_eq!(db_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value1);
        assert_eq!(db_cursor.seek(key2.clone().into()).unwrap().unwrap().1, value2);
        assert_eq!(db_cursor.seek(key3.clone().into()), Ok(None)); //not found
        assert_eq!(db_cursor.next(), Ok(None));

        let cursor = provider.tx_ref().cursor_dup_write::<tables::HashedStorages>().unwrap();
        let mut db_cursor = DatabaseHashedStorageCursor::new(cursor, hashed_address2);
        assert_eq!(db_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value3); //to the first one
        assert_eq!(db_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));

        assert_eq!(db_cursor.seek(key3.clone().into()).unwrap().unwrap().1, value3);
        assert_eq!(db_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));
        assert_eq!(db_cursor.next(), Ok(None));

        for i in 1..4 {
            if i == 1 {
                storages.insert((hashed_address2.clone(), key4.clone().into()), value4.clone());

                let hashed_address3 = B256::from([2; 32]);
                let key5 = B256::from([1; 32]);
                let value5 = U256::from(15);
                storages.insert((hashed_address3.clone(), key5.clone().into()), value5.clone());
            }
            if i == 2 {
                storages.insert((hashed_address2.clone(), key4.clone().into()), value4.clone());
            }
            if i == 3 {
                storages.insert((hashed_address2.clone(), key3.clone().into()), value3.clone());
            }

            // cached cursor
            let cursor = provider.tx_ref().cursor_dup_read::<tables::HashedStorages>().unwrap();
            let mut cache_cursor =
                CachedHashedStorageCursor::new(cursor, hashed_address1, &cached_states);
            assert_eq!(cache_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value1);
            assert_eq!(cache_cursor.seek(key2.clone().into()).unwrap().unwrap().1, value2);
            assert_eq!(cache_cursor.seek(key3.clone().into()), Ok(None)); //not found
            assert_eq!(cache_cursor.next(), Ok(None));

            let cursor = provider.tx_ref().cursor_dup_read::<tables::HashedStorages>().unwrap();
            let mut cache_cursor =
                CachedHashedStorageCursor::new(cursor, hashed_address2, &cached_states);
            assert_eq!(cache_cursor.seek(key1.clone().into()).unwrap().unwrap().1, value3); //to the first one
            assert_eq!(cache_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));

            assert_eq!(cache_cursor.seek(key3.clone().into()).unwrap().unwrap().1, value3);
            assert_eq!(cache_cursor.next(), Ok(Some((key4.clone().into(), value4.clone()))));
            assert_eq!(cache_cursor.next(), Ok(None));
        }
    }

    #[test]
    fn test_storage_cursor_back_and_forth() {
        let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
            .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
            .unwrap();
        let _ = tracing_subscriber::fmt().with_env_filter(filter_layer).try_init();

        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let mut cursor = provider.tx_ref().cursor_dup_write::<tables::HashedStorages>().unwrap();

        let hashed_address1 = B256::from([5; 32]);
        let key1 = B256::from([2; 32]);
        let value1 = U256::from(12);
        let key2 = B256::from([3; 32]);
        let value2 = U256::from(34);

        cursor
            .upsert(hashed_address1, StorageEntry { key: key1.clone(), value: value1.clone() })
            .unwrap();
        cursor
            .upsert(hashed_address1, StorageEntry { key: key2.clone(), value: value2.clone() })
            .unwrap();

        let key3 = B256::from([1; 32]);
        let value3 = U256::from(15);
        storages.insert((hashed_address1.clone(), key3.clone().into()), value3.clone());

        let cursor = provider.tx_ref().cursor_dup_read::<tables::HashedStorages>().unwrap();
        let mut cache_cursor =
            CachedHashedStorageCursor::new(cursor, hashed_address1, &cached_states);

        assert_eq!(cache_cursor.seek(key2.clone()).unwrap().unwrap().1, value2);
        assert_eq!(cache_cursor.seek(key3.clone()).unwrap().unwrap().1, value3);
        assert_eq!(cache_cursor.next().unwrap().unwrap().1, value1);
        assert_eq!(cache_cursor.next().unwrap().unwrap().1, value2);
        assert_eq!(cache_cursor.next().unwrap(), None);
    }
}
