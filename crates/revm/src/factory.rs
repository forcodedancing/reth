use crate::{
    database::StateProviderDatabase,
    processor::EVMProcessor,
    stack::{InspectorStack, InspectorStackConfig},
};
use reth_evm::ConfigureEvm;
use reth_interfaces::executor::BlockExecutionError;
use reth_parlia_consensus::Parlia;
use reth_primitives::ChainSpec;
use reth_provider::{ExecutorFactory, PrunableBlockExecutor, StateProvider};
use std::sync::Arc;

/// Factory for creating [EVMProcessor].
#[derive(Clone, Debug)]
pub struct EvmProcessorFactory<EvmConfig, P> {
    chain_spec: Arc<ChainSpec>,
    stack: Option<InspectorStack>,
    /// Type that defines how the produced EVM should be configured.
    evm_config: EvmConfig,
    /// Parlia consensus instance
    parlia_consensus: Option<Arc<Parlia<P>>>,
}

impl<EvmConfig, P> EvmProcessorFactory<EvmConfig, P> {
    /// Create new factory
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self { chain_spec, stack: None, evm_config, parlia_consensus: None }
    }

    /// Sets the inspector stack for all generated executors.
    pub fn with_stack(mut self, stack: InspectorStack) -> Self {
        self.stack = Some(stack);
        self
    }

    /// Sets the inspector stack for all generated executors using the provided config.
    pub fn with_stack_config(mut self, config: InspectorStackConfig) -> Self {
        self.stack = Some(InspectorStack::new(config));
        self
    }

    #[cfg(feature = "bsc")]
    pub fn with_parlia(mut self, parlia_consensus: Arc<Parlia<P>>) -> Self {
        self.parlia_consensus = Some(parlia_consensus);
        self
    }
}

impl<EvmConfig, P> ExecutorFactory for EvmProcessorFactory<EvmConfig, P>
where
    EvmConfig: ConfigureEvm + Send + Sync + Clone + 'static,
{
    fn with_state<'a, SP: StateProvider + 'a>(
        &'a self,
        sp: SP,
    ) -> Box<dyn PrunableBlockExecutor<Error = BlockExecutionError> + 'a> {
        let database_state = StateProviderDatabase::new(sp);
        let mut evm = EVMProcessor::new_with_db(
            self.chain_spec.clone(),
            database_state,
            self.evm_config.clone(),
        );
        if let Some(stack) = &self.stack {
            evm.set_stack(stack.clone());
        }
        #[cfg(feature = "bsc")]
        if let Some(parlia_consensus) = &self.parlia_consensus {
            evm.set_parlia(parlia_consensus.clone());
        }
        Box::new(evm)
    }
}
