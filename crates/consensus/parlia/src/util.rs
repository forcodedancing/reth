use lazy_static::lazy_static;
use reth_primitives::{Address, Header, TransactionSigned};

use alloy_json_abi::JsonAbi;
use serde_json::Error;
use std::{io::Read, str::FromStr};

lazy_static! {
    // preset contracts
    pub static ref VALIDATOR_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001000").unwrap();
    pub static ref SLASH_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001001").unwrap();
    pub static ref SYSTEM_REWARD_CONTRACT: Address = Address::from_str("0000000000000000000000000000000000001002").unwrap();
    pub static ref LIGHT_CLIENT_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001003").unwrap();
    pub static ref TOKEN_HUB_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001004").unwrap();
    pub static ref RELAYER_INCENTIVIZE_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001005").unwrap();
    pub static ref RELAYER_HUB_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001006").unwrap();
    pub static ref GOV_HUB_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001007").unwrap();
    pub static ref CROSS_CHAIN_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001008").unwrap();
    pub static ref TOKEN_MANAGER_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002000").unwrap();
    pub static ref STAKING_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002001").unwrap();
    pub static ref STAKE_HUB_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002002").unwrap();
    pub static ref STAKE_CREDIT_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002003").unwrap();
    pub static ref BSC_GOVERNOR_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002004").unwrap();
    pub static ref GOV_TOKEN_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002005").unwrap();
    pub static ref BSC_TIMELOCK_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000002006").unwrap();
    pub static ref TOKEN_RECOVER_PORTAL_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000003000").unwrap();

    pub static ref SYSTEM_CONTRACTS: Vec<Address> = vec![
        *VALIDATOR_CONTRACT,
        *SLASH_CONTRACT,
        *SYSTEM_REWARD_CONTRACT,
        *LIGHT_CLIENT_CONTRACT,
        *TOKEN_HUB_CONTRACT,
        *RELAYER_INCENTIVIZE_CONTRACT,
        *RELAYER_HUB_CONTRACT,
        *GOV_HUB_CONTRACT,
        *TOKEN_MANAGER_CONTRACT,
        *CROSS_CHAIN_CONTRACT,
        *STAKING_CONTRACT,
        *STAKE_HUB_CONTRACT,
        *STAKE_CREDIT_CONTRACT,
        *BSC_GOVERNOR_CONTRACT,
        *GOV_TOKEN_CONTRACT,
        *BSC_TIMELOCK_CONTRACT,
        *TOKEN_RECOVER_PORTAL_CONTRACT,
    ];
}

const SECONDS_PER_DAY: u64 = 86400; // 24 * 60 * 60

pub fn is_same_day_in_utc(first: u64, second: u64) -> bool {
    first / SECONDS_PER_DAY == second / SECONDS_PER_DAY
}

pub fn is_breathe_block(last_block_time: u64, block_time: u64) -> bool {
    last_block_time != 0 && !is_same_day_in_utc(last_block_time, block_time)
}

pub fn is_system_transaction(tx: &TransactionSigned, header: &Header) -> bool {
    if let Some(to) = tx.to() {
        if to == header.beneficiary && is_invoke_system_contract(&to) && tx.max_fee_per_gas() == 0 {
            return true;
        }
    }

    false
}

/// whether the contract is system or not
pub fn is_invoke_system_contract(addr: &Address) -> bool {
    SYSTEM_CONTRACTS.contains(addr)
}

pub fn load_abi_from_file(path: &str) -> Result<JsonAbi, Error> {
    let json = std::fs::read_to_string(path).unwrap();
    let abi: JsonAbi = serde_json::from_str(&json)?;
    Ok(abi)
}
