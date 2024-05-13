use alloy_rlp::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use reth_codecs::derive_arbitrary;
use reth_primitives::{Bytes, B256, hex};

#[derive_arbitrary(rlp)]
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UpgradeStatus {
    pub extension : Vec<u8>
}

#[derive_arbitrary(rlp)]
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UpgradeStatusExtension {
   pub disable_peer_tx_broadcast: bool
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use alloy_rlp::Encodable;
    use reth_primitives::hex;
    use crate::{EthMessage, ProtocolMessage};

    #[test]
    fn test_encode_upgrade_status() {
        let extension = UpgradeStatusExtension{disable_peer_tx_broadcast: false};
        let mut buffer = Vec::<u8>::new();
        let _ = extension.encode(&mut buffer);
        let result = alloy_rlp::encode(ProtocolMessage::from(EthMessage::UpgradeStatus(UpgradeStatus{
            extension: buffer,
        })));

        println!("{}", hex::encode(result))
    }
}

