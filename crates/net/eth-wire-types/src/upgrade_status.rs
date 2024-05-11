use alloy_rlp::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use reth_codecs::derive_arbitrary;
use reth_primitives::{Bytes, B256};

#[derive_arbitrary(rlp)]
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UpgradeStatus {
    pub extension : Vec<Bytes>
}