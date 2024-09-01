use lazy_static::lazy_static;
use quick_cache::sync::Cache;
use reth_primitives::{Account, Address, BlockNumber, Bytecode, StorageKey, StorageValue, B256};
use reth_provider::{
    AccountReader, BlockHashReader, ExecutionDataProvider, StateProofProvider, StateProvider,
    StateRootProvider,
};
use reth_revm::db::BundleState;
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{updates::TrieUpdates, AccountProof, HashedPostState};

/// The size of cache, counted by the number of accounts.
const CACHE_SIZE: usize = 1000000;

type AddressStorageKey = (Address, StorageKey);

lazy_static! {
    /// Account cache
    pub static ref ACCOUNT_CACHE: Cache<Address, Account> = Cache::new(CACHE_SIZE);

    /// Contract cache
    /// The size of contract is large and the hot contracts should be limited.
    static ref CONTRACT_CACHE: Cache<B256, Bytecode> = Cache::new(CACHE_SIZE/10);

    /// Storage cache
    static ref STORAGE_CACHE: Cache<AddressStorageKey, StorageValue> = Cache::new(CACHE_SIZE*10);

    /// Block hash cache
    static ref BLOCK_HASH_CACHE: Cache<u64, B256> = Cache::new(CACHE_SIZE/10);
}

/// Apply committed state to canonical cache.
pub(crate) fn apply_bundle_state(bundle: BundleState) {
    let change_set = bundle.into_plain_state(reth_provider::OriginalValuesKnown::Yes);

    for (address, account_info) in &change_set.accounts {
        match account_info {
            None => {
                ACCOUNT_CACHE.remove(address);
            }
            Some(acc) => {
                ACCOUNT_CACHE.insert(
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

    let mut to_wipe = false;
    for storage in &change_set.storage {
        if storage.wipe_storage {
            to_wipe = true;
            break;
        } else {
            for (k, v) in storage.storage.clone() {
                STORAGE_CACHE.insert((storage.address, StorageKey::from(k)), v);
            }
        }
    }
    if to_wipe {
        STORAGE_CACHE.clear();
    }
}

/// Clear cached accounts and storages.
pub fn clear_accounts_and_storages() {
    ACCOUNT_CACHE.clear();
    STORAGE_CACHE.clear();
}

#[derive(Debug)]
pub(crate) struct CachedBundleStateProvider<SP: StateProvider, EDP: ExecutionDataProvider> {
    /// The inner state provider.
    pub(crate) state_provider: SP,
    /// Block execution data.
    pub(crate) block_execution_data_provider: EDP,
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> CachedBundleStateProvider<SP, EDP> {
    /// Create new cached bundle state provider
    pub(crate) const fn new(state_provider: SP, block_execution_data_provider: EDP) -> Self {
        Self { state_provider, block_execution_data_provider }
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> BlockHashReader
    for CachedBundleStateProvider<SP, EDP>
{
    fn block_hash(&self, block_number: BlockNumber) -> ProviderResult<Option<B256>> {
        let block_hash = self.block_execution_data_provider.block_hash(block_number);
        if block_hash.is_some() {
            return Ok(block_hash)
        }
        if let Some(v) = BLOCK_HASH_CACHE.get(&block_number) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.block_hash(block_number)? {
            BLOCK_HASH_CACHE.insert(block_number, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn canonical_hashes_range(
        &self,
        _start: BlockNumber,
        _end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        unimplemented!()
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> AccountReader
    for CachedBundleStateProvider<SP, EDP>
{
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        if let Some(account) =
            self.block_execution_data_provider.execution_outcome().account(&address)
        {
            return Ok(account)
        }
        if let Some(v) = ACCOUNT_CACHE.get(&address) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.basic_account(address)? {
            ACCOUNT_CACHE.insert(address, value);
            return Ok(Some(value))
        }
        Ok(None)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateRootProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn state_root(&self, bundle_state: &BundleState) -> ProviderResult<B256> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.state_root(&state)
    }

    fn hashed_state_root(&self, hashed_state: &reth_trie::HashedPostState) -> ProviderResult<B256> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_state_root(&state)
    }

    fn state_root_with_updates(
        &self,
        bundle_state: &BundleState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let mut state = self.block_execution_data_provider.execution_outcome().state().clone();
        state.extend(bundle_state.clone());
        self.state_provider.state_root_with_updates(&state)
    }

    fn hashed_state_root_with_updates(
        &self,
        hashed_state: &HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_state_root_with_updates(&state)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateProofProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn hashed_proof(
        &self,
        hashed_state: &HashedPostState,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        let bundle_state = self.block_execution_data_provider.execution_outcome().state();
        let mut state = HashedPostState::from_bundle_state(&bundle_state.state);
        state.extend(hashed_state.clone());
        self.state_provider.hashed_proof(&state, address, slots)
    }
}

impl<SP: StateProvider, EDP: ExecutionDataProvider> StateProvider
    for CachedBundleStateProvider<SP, EDP>
{
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let u256_storage_key = storage_key.into();
        if let Some(value) = self
            .block_execution_data_provider
            .execution_outcome()
            .storage(&account, u256_storage_key)
        {
            return Ok(Some(value))
        }
        let cache_key = (account, storage_key);
        if let Some(v) = STORAGE_CACHE.get(&cache_key) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.storage(account, storage_key)? {
            STORAGE_CACHE.insert(cache_key, value);
            return Ok(Some(value))
        }
        Ok(None)
    }

    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(bytecode) =
            self.block_execution_data_provider.execution_outcome().bytecode(&code_hash)
        {
            return Ok(Some(bytecode))
        }
        if let Some(v) = CONTRACT_CACHE.get(&code_hash) {
            return Ok(Some(v))
        }
        if let Some(value) = self.state_provider.bytecode_by_hash(code_hash)? {
            CONTRACT_CACHE.insert(code_hash, value.clone());
            return Ok(Some(value))
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_cache::CachedBundleStateProvider, BundleStateDataRef};
    use reth_execution_types::ExecutionOutcome;
    use reth_primitives::{
        revm_primitives::{AccountInfo, KECCAK_EMPTY},
        ForkBlock,
    };
    use reth_provider::{providers::ConsistentDbView, test_utils::create_test_provider_factory};
    use reth_revm::{db::AccountStatus, primitives::U256};
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn test_basic() {
        let execution_outcome = ExecutionOutcome::default();
        let empty = BTreeMap::new();

        let factory = create_test_provider_factory();
        let consistent_view = ConsistentDbView::new_with_latest_tip(factory.clone()).unwrap();
        let state_provider = consistent_view
            .provider_ro()
            .unwrap()
            .disable_long_read_transaction_safety()
            .state_provider_by_block_number(1)
            .unwrap();
        let bdp = BundleStateDataRef {
            execution_outcome: &execution_outcome,
            sidechain_block_hashes: &empty,
            canonical_block_hashes: &empty,
            canonical_fork: ForkBlock::new(1, B256::random()),
        };
        let cached_bundle_provider = CachedBundleStateProvider::new(state_provider, bdp);

        let account = Address::random();
        let result = cached_bundle_provider.basic_account(account).unwrap();
        assert_eq!(result.is_none(), true);

        ACCOUNT_CACHE
            .insert(account, Account { nonce: 100, balance: U256::ZERO, bytecode_hash: None });
        let result = cached_bundle_provider.basic_account(account).unwrap();
        assert_eq!(result.unwrap().nonce, 100);

        BLOCK_HASH_CACHE.insert(100, B256::with_last_byte(9));
        let result = cached_bundle_provider.block_hash(100).unwrap();
        assert_eq!(result.unwrap(), B256::with_last_byte(9));
    }

    #[test]
    fn test_apply_bundle_state() {
        let execution_outcome = ExecutionOutcome::default();
        let empty = BTreeMap::new();

        let factory = create_test_provider_factory();
        let consistent_view = ConsistentDbView::new_with_latest_tip(factory.clone()).unwrap();
        let state_provider = consistent_view
            .provider_ro()
            .unwrap()
            .disable_long_read_transaction_safety()
            .state_provider_by_block_number(1)
            .unwrap();
        let bdp = BundleStateDataRef {
            execution_outcome: &execution_outcome,
            sidechain_block_hashes: &empty,
            canonical_block_hashes: &empty,
            canonical_fork: ForkBlock::new(1, B256::random()),
        };
        let cached_bundle_provider = CachedBundleStateProvider::new(state_provider, bdp);

        // apply bundle state to set cache
        let account1 = Address::random();
        let account2 = Address::random();
        let bundle_state = BundleState::new(
            vec![
                (
                    account1,
                    None,
                    Some(AccountInfo {
                        nonce: 1,
                        balance: U256::from(10),
                        code_hash: KECCAK_EMPTY,
                        code: None,
                    }),
                    HashMap::from([
                        (U256::from(2), (U256::from(0), U256::from(10))),
                        (U256::from(5), (U256::from(0), U256::from(15))),
                    ]),
                ),
                (
                    account2,
                    None,
                    Some(AccountInfo {
                        nonce: 1,
                        balance: U256::from(10),
                        code_hash: KECCAK_EMPTY,
                        code: None,
                    }),
                    HashMap::from([]),
                ),
            ],
            vec![vec![
                (
                    account1,
                    Some(None),
                    vec![(U256::from(2), U256::from(0)), (U256::from(5), U256::from(0))],
                ),
                (account2, Some(None), vec![]),
            ]],
            vec![],
        );
        apply_bundle_state(bundle_state);

        let account1_result = cached_bundle_provider.basic_account(account1).unwrap();
        assert_eq!(account1_result.unwrap().nonce, 1);
        let storage1_result =
            cached_bundle_provider.storage(account1, B256::with_last_byte(2)).unwrap();
        assert_eq!(storage1_result.unwrap(), U256::from(10));
        let storage2_result =
            cached_bundle_provider.storage(account1, B256::with_last_byte(5)).unwrap();
        assert_eq!(storage2_result.unwrap(), U256::from(15));

        let account2_result = cached_bundle_provider.basic_account(account2).unwrap();
        assert_eq!(account2_result.unwrap().nonce, 1);

        // apply bundle state to set clear cache
        let account3 = Address::random();
        let mut bundle_state = BundleState::new(
            vec![(
                account3,
                Some(AccountInfo {
                    nonce: 3,
                    balance: U256::from(10),
                    code_hash: KECCAK_EMPTY,
                    code: None,
                }),
                None,
                HashMap::from([
                    (U256::from(2), (U256::from(0), U256::from(10))),
                    (U256::from(5), (U256::from(0), U256::from(15))),
                ]),
            )],
            vec![vec![(
                account3,
                Some(None),
                vec![(U256::from(2), U256::from(0)), (U256::from(5), U256::from(0))],
            )]],
            vec![],
        );
        bundle_state.state.get_mut(&account3).unwrap().status = AccountStatus::Destroyed;
        apply_bundle_state(bundle_state);

        let account1_result = cached_bundle_provider.basic_account(account1).unwrap();
        assert_eq!(account1_result.unwrap().nonce, 1);
        let storage1_result =
            cached_bundle_provider.storage(account1, B256::with_last_byte(2)).unwrap();
        assert_eq!(storage1_result.is_none(), true);
        let storage2_result =
            cached_bundle_provider.storage(account1, B256::with_last_byte(5)).unwrap();
        assert_eq!(storage2_result.is_none(), true);

        let account2_result = cached_bundle_provider.basic_account(account2).unwrap();
        assert_eq!(account2_result.unwrap().nonce, 1);
    }
}
