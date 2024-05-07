use crate::{
    database::StateProviderDatabase,
    processor::EVMProcessor,
    stack::{InspectorStack, InspectorStackConfig},
};
use reth_evm::ConfigureEvm;
use reth_interfaces::executor::BlockExecutionError;
#[cfg(feature = "bsc")]
use reth_parlia_consensus::{Parlia, ParliaConfig};
use reth_primitives::ChainSpec;
use reth_provider::{ExecutorFactory, PrunableBlockExecutor, StateProvider};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

/// Factory for creating [EVMProcessor].
#[derive(Clone, Debug)]
pub struct EvmProcessorFactory<EvmConfig, P> {
    chain_spec: Arc<ChainSpec>,
    stack: Option<InspectorStack>,
    /// Type that defines how the produced EVM should be configured.
    evm_config: EvmConfig,

    _phantom: PhantomData<P>,
    /// Parlia consensus config
    #[cfg(feature = "bsc")]
    parlia_cfg: Option<ParliaConfig>,
}

impl<EvmConfig, P> EvmProcessorFactory<EvmConfig, P> {
    /// Create new factory
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self {
            chain_spec,
            stack: None,
            evm_config,
            _phantom: PhantomData::default(),
            #[cfg(feature = "bsc")]
            parlia_cfg: None,
        }
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
    pub fn with_parlia_config(mut self, parlia_cfg: ParliaConfig) -> Self {
        self.parlia_cfg = Some(parlia_cfg);
        self
    }
}

impl<EvmConfig, P> ExecutorFactory for EvmProcessorFactory<EvmConfig, P>
where
    EvmConfig: ConfigureEvm + Send + Sync + Clone + 'static,
    P: Debug + Send + Sync + 'static,
{
    fn with_state<'a, SP: StateProvider + 'a>(
        &'a self,
        sp: SP,
    ) -> Box<dyn PrunableBlockExecutor<Error = BlockExecutionError> + 'a> {
        let database_state = StateProviderDatabase::new(sp);
        let mut evm = EVMProcessor::<EvmConfig, P>::new_with_db(
            self.chain_spec.clone(),
            database_state,
            self.evm_config.clone(),
        );
        if let Some(stack) = &self.stack {
            evm.set_stack(stack.clone());
        }
        #[cfg(feature = "bsc")]
        if let Some(parlia_cfg) = &self.parlia_cfg {
            evm.set_parlia(Arc::new(Parlia::new(self.chain_spec.clone(), parlia_cfg.clone())));
        }
        Box::new(evm)
    }
}
