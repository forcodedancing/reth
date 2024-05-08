use reth_evm::ConfigureEvm;
use reth_interfaces::executor::{BlockExecutionError, BlockValidationError};
use reth_primitives::{
    revm::env::fill_tx_env, Address, Block, BlockNumber, BlockWithSenders, Bloom, ChainSpec,
    GotExpected, Hardfork, Header, PruneModes, Receipt, ReceiptWithBloom, Receipts,
    TransactionSigned, Withdrawals, B256, U256,
};
use reth_provider::{
    BlockExecutor, BundleStateWithReceipts, ProviderError, PrunableBlockExecutor, StateProvider,
};
use revm::{
    db::StateDBBox,
    inspector_handle_register,
    interpreter::Host,
    primitives::{CfgEnvWithHandlerCfg, ResultAndState},
    DatabaseCommit, Evm, State,
};
use std::{marker::PhantomData, sync::Arc, time::Instant};
use tracing::{debug, trace};

use crate::Database;
use reth_db::{database, models::parlia::VoteAddress};
use reth_interfaces::executor::BscBlockExecutionError;
use reth_parlia_consensus::{
    get_top_validators_by_voting_power, is_breathe_block, is_system_transaction, Parlia,
    DIFF_INTURN, MAX_SYSTEM_REWARD, SYSTEM_REWARD_CONTRACT, SYSTEM_REWARD_PERCENT,
};
use reth_primitives::{constants::SYSTEM_ADDRESS, Bytes, SealedHeader, Transaction};
use reth_provider::DatabaseProviderRW;
use revm::primitives::{Env, TransactTo, TxEnv};
use std::collections::HashMap;

use crate::{
    batch::{BlockBatchRecord, BlockExecutorStats},
    database::StateProviderDatabase,
    eth_dao_fork::{DAO_HARDFORK_BENEFICIARY, DAO_HARDKFORK_ACCOUNTS},
    processor::{verify_receipt, EVMProcessor},
    stack::{InspectorStack, InspectorStackConfig},
    state_change::{apply_beacon_root_contract_call, post_block_balance_increments},
};

/// Bsc Ethereum implementation of the [BlockExecutor] trait for the [EVMProcessor].
impl<'a, EvmConfig, P> BlockExecutor for EVMProcessor<'a, EvmConfig, P>
where
    EvmConfig: ConfigureEvm,
{
    type Error = BlockExecutionError;

    fn execute_and_verify_receipt(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        // execute block
        let receipts = self.execute_inner(block, total_difficulty)?;

        // TODO Before Byzantium, receipts contained state root that would mean that expensive
        // operation as hashing that is needed for state root got calculated in every
        // transaction This was replaced with is_success flag.
        // See more about EIP here: https://eips.ethereum.org/EIPS/eip-658
        if self.chain_spec.fork(Hardfork::Byzantium).active_at_block(block.header.number) {
            let time = Instant::now();
            if let Err(error) =
                verify_receipt(block.header.receipts_root, block.header.logs_bloom, receipts.iter())
            {
                debug!(target: "evm", %error, ?receipts, "receipts verification failed");
                return Err(error)
            };
            self.stats.receipt_root_duration += time.elapsed();
        }

        self.batch_record.save_receipts(receipts)?;
        Ok(())
    }

    fn execute_transactions(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(Vec<Receipt>, u64), BlockExecutionError> {
        self.init_env(&block.header, total_difficulty);

        // perf: do not execute empty blocks
        if block.body.is_empty() {
            return Ok((Vec::new(), 0))
        }

        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body.len());
        for (sender, transaction) in block.transactions_with_sender() {
            let time = Instant::now();
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }
            // Execute transaction.
            let ResultAndState { result, state } = self.transact(transaction, *sender)?;
            trace!(
                target: "evm",
                ?transaction, ?result, ?state,
                "Executed transaction"
            );
            self.stats.execution_duration += time.elapsed();
            let time = Instant::now();

            self.db_mut().commit(state);

            self.stats.apply_state_duration += time.elapsed();

            // append gas used
            cumulative_gas_used += result.gas_used();

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Receipt {
                tx_type: transaction.tx_type(),
                // Success flag was added in `EIP-658: Embedding transaction status code in
                // receipts`.
                success: result.is_success(),
                cumulative_gas_used,
                // convert to reth log
                logs: result.into_logs().into_iter().map(Into::into).collect(),
            });
        }

        Ok((receipts, cumulative_gas_used))
    }

    fn execute_transactions_and_get_system_txs(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(Vec<&TransactionSigned>, Vec<Receipt>, u64), BlockExecutionError> {
        self.init_env(&block.header, total_difficulty);

        if !self
            .parlia_consensus
            .chain_spec()
            .fork(Hardfork::Feynman)
            .active_at_timestamp(block.timestamp)
        {
            let _parent =
                self.parlia_consensus.get_header_by_hash(block.number - 1, block.parent_hash)?;
            // apply system contract upgrade
            todo!()
        }

        // perf: do not execute empty blocks
        if block.body.is_empty() {
            return Ok((Vec::new(), Vec::new(), 0))
        }

        let mut cumulative_gas_used = 0;
        let mut system_txs = Vec::with_capacity(2);
        let mut receipts = Vec::with_capacity(block.body.len());
        for (sender, transaction) in block.transactions_with_sender() {
            if is_system_transaction(transaction, &block.header) {
                system_txs.push(transaction);
                continue
            }
            // systemTxs should be always at the end of block.
            if self.parlia_consensus.chain_spec().is_cancun_active_at_timestamp(block.timestamp) {
                if system_txs.len() > 0 {
                    return Err(BlockExecutionError::Validation(
                        BscBlockExecutionError::UnexpectedNormalTx.into(),
                    ))
                }
            }

            let time = Instant::now();
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }
            // Execute transaction.
            let ResultAndState { result, state } = self.transact(transaction, *sender)?;
            trace!(
                target: "evm",
                ?transaction, ?result, ?state,
                "Executed transaction"
            );
            self.stats.execution_duration += time.elapsed();
            let time = Instant::now();

            self.db_mut().commit(state);

            self.stats.apply_state_duration += time.elapsed();

            // append gas used
            cumulative_gas_used += result.gas_used();

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Receipt {
                tx_type: transaction.tx_type(),
                // Success flag was added in `EIP-658: Embedding transaction status code in
                // receipts`.
                success: result.is_success(),
                cumulative_gas_used,
                // convert to reth log
                logs: result.into_logs().into_iter().map(Into::into).collect(),
            });
        }

        Ok((system_txs, receipts, cumulative_gas_used))
    }

    fn take_output_state(&mut self) -> BundleStateWithReceipts {
        self.stats.log_debug();
        BundleStateWithReceipts::new(
            self.evm.context.evm.db.take_bundle(),
            self.batch_record.take_receipts(),
            self.batch_record.first_block().unwrap_or_default(),
        )
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.evm.context.evm.db.bundle_size_hint())
    }
}

impl<'a, EvmConfig, P> PrunableBlockExecutor for EVMProcessor<'a, EvmConfig, P>
where
    EvmConfig: ConfigureEvm,
{
    fn set_tip(&mut self, tip: BlockNumber) {
        self.batch_record.set_tip(tip);
    }

    fn set_prune_modes(&mut self, prune_modes: PruneModes) {
        self.batch_record.set_prune_modes(prune_modes);
    }

    #[cfg(feature = "bsc")]
    fn set_provider_for_parlia<DB: database::Database>(
        &mut self,
        provider: &DatabaseProviderRW<DB>,
    ) {
        self.parlia_consensus.set_provider(provider);
    }
}
