//! `reth recover` command.

use clap::{Parser, Subcommand};
use reth_chainspec::EthChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_runner::CliContext;
use reth_node_builder::NodeTypesWithEngine;
use reth_provider::ChainSpecHardforks;

mod storage_tries;

/// `reth recover` command
#[derive(Debug, Parser)]
pub struct Command<C: ChainSpecParser> {
    #[command(subcommand)]
    command: Subcommands<C>,
}

/// `reth recover` subcommands
#[derive(Subcommand, Debug)]
pub enum Subcommands<C: ChainSpecParser> {
    /// Recover the node by deleting dangling storage tries.
    StorageTries(storage_tries::Command<C>),
}

impl<C: ChainSpecParser<ChainSpec: EthChainSpec + ChainSpecHardforks>> Command<C> {
    /// Execute `recover` command
    pub async fn execute<N: NodeTypesWithEngine<ChainSpec = C::ChainSpec>>(
        self,
        ctx: CliContext,
    ) -> eyre::Result<()> {
        match self.command {
            Subcommands::StorageTries(command) => command.execute::<N>(ctx).await,
        }
    }
}
