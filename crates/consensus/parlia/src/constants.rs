use reth_primitives::{constants::ETH_TO_WEI, U256};
use reth_rpc_types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN;

/// Fixed number of extra-data prefix bytes reserved for signer vanity
pub const EXTRA_VANITY_LEN: usize = 32;
/// Fixed number of extra-data prefix bytes reserved for signer vanity add validator num
pub const EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM: usize = 33;
/// Fixed number of extra-data suffix bytes reserved for signer seal
pub const EXTRA_SEAL_LEN: usize = 65;
/// Address length of signer
pub const ADDRESS_LENGTH: usize = 20;
/// Fixed number of extra-data suffix bytes reserved before Luban validator
pub const EXTRA_VALIDATOR_LEN_BEFORE_LUBAN: usize = ADDRESS_LENGTH;
/// Fixed number of extra-data suffix bytes reserved for Luban validator
pub const EXTRA_VALIDATOR_LEN: usize = EXTRA_VALIDATOR_LEN_BEFORE_LUBAN + BLS_PUBLIC_KEY_BYTES_LEN;
/// Difficulty for INTURN block
pub const DIFF_INTURN: U256 = U256::from(2);
/// Difficulty for NOTURN block
pub const DIFF_NOTURN: U256 = U256::from(1);
pub const SYSTEM_REWARD_PERCENT: usize = 4;
/// The max reward in system reward contract
pub const MAX_SYSTEM_REWARD: u128 = 100 * ETH_TO_WEI;
/// The distance to naturally justify a block
pub const NATURALLY_JUSTIFIED_DIST: u64 = 15;
pub(crate) const COLLECT_ADDITIONAL_VOTES_REWARD_RATIO: usize = 100;
