use crate::{
    in_memory::ExecutedBlock, CanonStateNotification, CanonStateNotifications,
    CanonStateSubscriptions,
};
use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, BlockNumber, Sealable, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use rand::{thread_rng, Rng};
use reth_chainspec::{ChainSpec, EthereumHardfork, MIN_TRANSACTION_GAS};
use reth_execution_types::{Chain, ExecutionOutcome};
use reth_primitives::{
    constants::{EIP1559_INITIAL_BASE_FEE, EMPTY_ROOT_HASH},
    proofs::{calculate_receipt_root, calculate_transaction_root, calculate_withdrawals_root},
    BlockBody, Header, Receipt, Receipts, Requests, SealedBlock, SealedBlockWithSenders,
    SealedHeader, Transaction, TransactionSigned, TransactionSignedEcRecovered,
};
use reth_trie::{root::state_root_unhashed, updates::TrieUpdates, HashedPostState};
use revm::{db::BundleState, primitives::AccountInfo};
use std::{
    collections::HashMap,
    ops::Range,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast::{self, Sender};

/// Functionality to build blocks for tests and help with assertions about
/// their execution.
#[derive(Debug)]
pub struct TestBlockBuilder {
    /// The account that signs all the block's transactions.
    pub signer: Address,
    /// Private key for signing.
    pub signer_pk: PrivateKeySigner,
    /// Keeps track of signer's account info after execution, will be updated in
    /// methods related to block execution.
    pub signer_execute_account_info: AccountInfo,
    /// Keeps track of signer's nonce, will be updated in methods related
    /// to block execution.
    pub signer_build_account_info: AccountInfo,
    /// Chain spec of the blocks generated by this builder
    pub chain_spec: ChainSpec,
}

impl Default for TestBlockBuilder {
    fn default() -> Self {
        let initial_account_info = AccountInfo::from_balance(U256::from(10).pow(U256::from(18)));
        let signer_pk = PrivateKeySigner::random();
        let signer = signer_pk.address();
        Self {
            chain_spec: ChainSpec::default(),
            signer,
            signer_pk,
            signer_execute_account_info: initial_account_info.clone(),
            signer_build_account_info: initial_account_info,
        }
    }
}

impl TestBlockBuilder {
    /// Signer pk setter.
    pub fn with_signer_pk(mut self, signer_pk: PrivateKeySigner) -> Self {
        self.signer = signer_pk.address();
        self.signer_pk = signer_pk;

        self
    }

    /// Chainspec setter.
    pub fn with_chain_spec(mut self, chain_spec: ChainSpec) -> Self {
        self.chain_spec = chain_spec;
        self
    }

    /// Gas cost of a single transaction generated by the block builder.
    pub fn single_tx_cost() -> U256 {
        U256::from(EIP1559_INITIAL_BASE_FEE * MIN_TRANSACTION_GAS)
    }

    /// Generates a random [`SealedBlockWithSenders`].
    pub fn generate_random_block(
        &mut self,
        number: BlockNumber,
        parent_hash: B256,
    ) -> SealedBlockWithSenders {
        let mut rng = thread_rng();

        let mock_tx = |nonce: u64| -> TransactionSignedEcRecovered {
            let tx = Transaction::Eip1559(TxEip1559 {
                chain_id: self.chain_spec.chain.id(),
                nonce,
                gas_limit: MIN_TRANSACTION_GAS,
                to: Address::random().into(),
                max_fee_per_gas: EIP1559_INITIAL_BASE_FEE as u128,
                max_priority_fee_per_gas: 1,
                ..Default::default()
            });
            let signature_hash = tx.signature_hash();
            let signature = self.signer_pk.sign_hash_sync(&signature_hash).unwrap();

            TransactionSigned::from_transaction_and_signature(tx, signature)
                .with_signer(self.signer)
        };

        let num_txs = rng.gen_range(0..5);
        let signer_balance_decrease = Self::single_tx_cost() * U256::from(num_txs);
        let transactions: Vec<TransactionSignedEcRecovered> = (0..num_txs)
            .map(|_| {
                let tx = mock_tx(self.signer_build_account_info.nonce);
                self.signer_build_account_info.nonce += 1;
                self.signer_build_account_info.balance -= signer_balance_decrease;
                tx
            })
            .collect();

        let receipts = transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                Receipt {
                    tx_type: tx.tx_type(),
                    success: true,
                    cumulative_gas_used: (idx as u64 + 1) * MIN_TRANSACTION_GAS,
                    ..Default::default()
                }
                .with_bloom()
            })
            .collect::<Vec<_>>();

        let initial_signer_balance = U256::from(10).pow(U256::from(18));

        let header = Header {
            number,
            parent_hash,
            gas_used: transactions.len() as u64 * MIN_TRANSACTION_GAS,
            gas_limit: self.chain_spec.max_gas_limit,
            mix_hash: B256::random(),
            base_fee_per_gas: Some(EIP1559_INITIAL_BASE_FEE),
            transactions_root: calculate_transaction_root(&transactions),
            receipts_root: calculate_receipt_root(&receipts),
            beneficiary: Address::random(),
            state_root: state_root_unhashed(HashMap::from([(
                self.signer,
                (
                    AccountInfo {
                        balance: initial_signer_balance - signer_balance_decrease,
                        nonce: num_txs,
                        ..Default::default()
                    },
                    EMPTY_ROOT_HASH,
                ),
            )])),
            // use the number as the timestamp so it is monotonically increasing
            timestamp: number +
                EthereumHardfork::Cancun.activation_timestamp(self.chain_spec.chain).unwrap(),
            withdrawals_root: Some(calculate_withdrawals_root(&[])),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::random()),
            ..Default::default()
        };

        let sealed = header.seal_slow();
        let (header, seal) = sealed.into_parts();

        let block = SealedBlock {
            header: SealedHeader::new(header, seal),
            body: BlockBody {
                transactions: transactions.into_iter().map(|tx| tx.into_signed()).collect(),
                ommers: Vec::new(),
                withdrawals: Some(vec![].into()),
                sidecars: None,
                requests: None,
            },
        };

        SealedBlockWithSenders::new(block, vec![self.signer; num_txs as usize]).unwrap()
    }

    /// Creates a fork chain with the given base block.
    pub fn create_fork(
        &mut self,
        base_block: &SealedBlock,
        length: u64,
    ) -> Vec<SealedBlockWithSenders> {
        let mut fork = Vec::with_capacity(length as usize);
        let mut parent = base_block.clone();

        for _ in 0..length {
            let block = self.generate_random_block(parent.number + 1, parent.hash());
            parent = block.block.clone();
            fork.push(block);
        }

        fork
    }

    /// Gets an [`ExecutedBlock`] with [`BlockNumber`], [`Receipts`] and parent hash.
    fn get_executed_block(
        &mut self,
        block_number: BlockNumber,
        receipts: Receipts,
        parent_hash: B256,
    ) -> ExecutedBlock {
        let block_with_senders = self.generate_random_block(block_number, parent_hash);

        ExecutedBlock::new(
            Arc::new(block_with_senders.block.clone()),
            Arc::new(block_with_senders.senders),
            Arc::new(ExecutionOutcome::new(
                BundleState::default(),
                receipts,
                block_number,
                vec![Requests::default()],
            )),
            Arc::new(HashedPostState::default()),
            Arc::new(TrieUpdates::default()),
        )
    }

    /// Generates an [`ExecutedBlock`] that includes the given [`Receipts`].
    pub fn get_executed_block_with_receipts(
        &mut self,
        receipts: Receipts,
        parent_hash: B256,
    ) -> ExecutedBlock {
        let number = rand::thread_rng().gen::<u64>();
        self.get_executed_block(number, receipts, parent_hash)
    }

    /// Generates an [`ExecutedBlock`] with the given [`BlockNumber`].
    pub fn get_executed_block_with_number(
        &mut self,
        block_number: BlockNumber,
        parent_hash: B256,
    ) -> ExecutedBlock {
        self.get_executed_block(block_number, Receipts { receipt_vec: vec![vec![]] }, parent_hash)
    }

    /// Generates a range of executed blocks with ascending block numbers.
    pub fn get_executed_blocks(
        &mut self,
        range: Range<u64>,
    ) -> impl Iterator<Item = ExecutedBlock> + '_ {
        let mut parent_hash = B256::default();
        range.map(move |number| {
            let current_parent_hash = parent_hash;
            let block = self.get_executed_block_with_number(number, current_parent_hash);
            parent_hash = block.block.hash();
            block
        })
    }

    /// Returns the execution outcome for a block created with this builder.
    /// In order to properly include the bundle state, the signer balance is
    /// updated.
    pub fn get_execution_outcome(&mut self, block: SealedBlockWithSenders) -> ExecutionOutcome {
        let receipts = block
            .body
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| Receipt {
                tx_type: tx.tx_type(),
                success: true,
                cumulative_gas_used: (idx as u64 + 1) * MIN_TRANSACTION_GAS,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        let mut bundle_state_builder = BundleState::builder(block.number..=block.number);

        for tx in &block.body.transactions {
            self.signer_execute_account_info.balance -= Self::single_tx_cost();
            bundle_state_builder = bundle_state_builder.state_present_account_info(
                self.signer,
                AccountInfo {
                    nonce: tx.nonce(),
                    balance: self.signer_execute_account_info.balance,
                    ..Default::default()
                },
            );
        }

        let execution_outcome = ExecutionOutcome::new(
            bundle_state_builder.build(),
            vec![vec![None]].into(),
            block.number,
            Vec::new(),
        );

        execution_outcome.with_receipts(Receipts::from(receipts))
    }
}
/// A test `ChainEventSubscriptions`
#[derive(Clone, Debug, Default)]
pub struct TestCanonStateSubscriptions {
    canon_notif_tx: Arc<Mutex<Vec<Sender<CanonStateNotification>>>>,
}

impl TestCanonStateSubscriptions {
    /// Adds new block commit to the queue that can be consumed with
    /// [`TestCanonStateSubscriptions::subscribe_to_canonical_state`]
    pub fn add_next_commit(&self, new: Arc<Chain>) {
        let event = CanonStateNotification::Commit { new };
        self.canon_notif_tx.lock().as_mut().unwrap().retain(|tx| tx.send(event.clone()).is_ok())
    }

    /// Adds reorg to the queue that can be consumed with
    /// [`TestCanonStateSubscriptions::subscribe_to_canonical_state`]
    pub fn add_next_reorg(&self, old: Arc<Chain>, new: Arc<Chain>) {
        let event = CanonStateNotification::Reorg { old, new };
        self.canon_notif_tx.lock().as_mut().unwrap().retain(|tx| tx.send(event.clone()).is_ok())
    }
}

impl CanonStateSubscriptions for TestCanonStateSubscriptions {
    /// Sets up a broadcast channel with a buffer size of 100.
    fn subscribe_to_canonical_state(&self) -> CanonStateNotifications {
        let (canon_notif_tx, canon_notif_rx) = broadcast::channel(100);
        self.canon_notif_tx.lock().as_mut().unwrap().push(canon_notif_tx);

        canon_notif_rx
    }
}
