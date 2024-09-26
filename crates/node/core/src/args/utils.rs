//! Clap parser utilities

use std::{path::PathBuf, sync::Arc};

use alloy_genesis::Genesis;
#[cfg(feature = "bsc")]
use reth_bsc_chainspec::{BSC_CHAPEL, BSC_DEV, BSC_MAINNET, BSC_RIALTO};
use reth_chainspec::ChainSpec;
#[cfg(all(not(feature = "optimism"), not(feature = "bsc")))]
use reth_chainspec::{DEV, HOLESKY, MAINNET, SEPOLIA};
use reth_cli::chainspec::ChainSpecParser;
use reth_fs_util as fs;
#[cfg(feature = "optimism")]
use reth_optimism_chainspec::{BASE_MAINNET, BASE_SEPOLIA, OP_DEV, OP_MAINNET, OP_SEPOLIA};
#[cfg(all(feature = "optimism", feature = "opbnb"))]
use reth_optimism_chainspec::{OPBNB_MAINNET, OPBNB_QA, OPBNB_TESTNET};

#[cfg(feature = "bsc")]
/// Chains supported by bsc. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["bsc", "bsc-testnet"];
#[cfg(feature = "optimism")]
/// Chains supported by op-reth. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &[
    "optimism",
    "optimism-sepolia",
    "base",
    "base-sepolia",
    "opbnb-mainnet",
    "opbnb-testnet",
    "dev",
];
#[cfg(all(not(feature = "optimism"), not(feature = "bsc")))]
/// Chains supported by reth. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["mainnet", "sepolia", "holesky", "dev"];

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
#[cfg(all(not(feature = "optimism"), not(feature = "bsc")))]
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(match s {
        "mainnet" => MAINNET.clone(),
        "sepolia" => SEPOLIA.clone(),
        "holesky" => HOLESKY.clone(),
        "dev" => DEV.clone(),
        _ => Arc::new(parse_custom_chain_spec(s)?),
    })
}

/// Clap value parser for [`OpChainSpec`](reth_optimism_chainspec::OpChainSpec)s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
#[cfg(feature = "optimism")]
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(Arc::new(match s {
        "optimism" => OP_MAINNET.inner.clone(),
        "optimism_sepolia" | "optimism-sepolia" => OP_SEPOLIA.inner.clone(),
        "base" => BASE_MAINNET.inner.clone(),
        "base_sepolia" | "base-sepolia" => BASE_SEPOLIA.inner.clone(),
        "dev" => OP_DEV.inner.clone(),
        #[cfg(feature = "opbnb")]
        "opbnb_mainnet" | "opbnb-mainnet" => OPBNB_MAINNET.inner.clone(),
        #[cfg(feature = "opbnb")]
        "opbnb_testnet" | "opbnb-testnet" => OPBNB_TESTNET.inner.clone(),
        #[cfg(feature = "opbnb")]
        "opbnb_qa" | "opbnb-qa" => OPBNB_QA.inner.clone(),
        _ => parse_custom_chain_spec(s)?,
    }))
}

/// Clap value parser for [`BscChainSpec`](reth_bsc_chainspec::BscChainSpec)s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
#[cfg(feature = "bsc")]
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(Arc::new(match s {
        "bsc" | "bsc-mainnet" | "bsc_mainnet" => BSC_MAINNET.inner.clone(),
        "bsc-testnet" | "bsc-chapel" | "bsc_testnet" | "bsc_chapel" => BSC_CHAPEL.inner.clone(),
        "bsc-rialto" | "bsc-qa" | "bsc_rialto" | "bsc_qa" => BSC_RIALTO.inner.clone(),
        "dev" => BSC_DEV.inner.clone(),
        _ => parse_custom_chain_spec(s)?,
    }))
}

/// Parses a custom [`ChainSpec`].
pub fn parse_custom_chain_spec(s: &str) -> eyre::Result<ChainSpec, eyre::Error> {
    // try to read json from path first
    let raw = match fs::read_to_string(PathBuf::from(shellexpand::full(s)?.into_owned())) {
        Ok(raw) => raw,
        Err(io_err) => {
            // valid json may start with "\n", but must contain "{"
            if s.contains('{') {
                s.to_string()
            } else {
                return Err(io_err.into()) // assume invalid path
            }
        }
    };

    // both serialized Genesis and ChainSpec structs supported
    let genesis: Genesis = serde_json::from_str(&raw)?;

    Ok(genesis.into())
}

/// Default chain specification parser.
#[derive(Debug, Clone, Default)]
pub struct DefaultChainSpecParser;

impl ChainSpecParser for DefaultChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<ChainSpec>> {
        chain_value_parser(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_chain_spec() {
        for chain in SUPPORTED_CHAINS {
            chain_value_parser(chain).unwrap();
        }
    }
}
