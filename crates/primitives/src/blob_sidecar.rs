#![allow(missing_docs)]

use crate::TransactionSigned;
use alloy_eips::eip4844::BlobTransactionSidecar;
use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable, RlpDecodableWrapper, RlpEncodableWrapper};
use bytes::BufMut;
use reth_codecs::derive_arbitrary;
use revm_primitives::U256;
use serde::{Deserialize, Serialize};

#[derive_arbitrary(rlp, 25)]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    RlpEncodableWrapper,
    RlpDecodableWrapper,
)]
pub struct BlobSidecars(pub Vec<BlobSidecar>);

#[derive_arbitrary(rlp, 25)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlobSidecar {
    pub blob_transaction_sidecar: BlobTransactionSidecar,
    pub block_number: U256,
    pub block_hash: B256,
    pub tx_index: u64,
    pub tx_hash: B256,
}

impl BlobSidecars {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// EncodeIndex encodes the i-th BlobTransactionSidecar to out. Note that this does not check
    /// for errors because we assume that BlobSidecars will only ever contain valid sidecars
    pub fn encode_index(&self, out: &mut dyn BufMut, index: usize) {
        let header = alloy_rlp::Header { list: true, payload_length: self.0[index].length() };
        header.encode(out);
        self.0[index].encode(out);
    }
}

impl BlobSidecar {
    pub fn new_from_tx(_tx: &TransactionSigned) -> Self {
        todo!()
    }

    pub fn sanity_check(&self, block_number: U256, block_hash: B256) -> bool {
        if self.block_number != block_number {
            return false;
        };
        if self.block_hash != block_hash {
            return false;
        };
        if self.blob_transaction_sidecar.blobs.len() !=
            self.blob_transaction_sidecar.commitments.len() ||
            self.blob_transaction_sidecar.blobs.len() !=
                self.blob_transaction_sidecar.proofs.len()
        {
            return false;
        };

        true
    }
}

impl Encodable for BlobSidecar {
    fn encode(&self, out: &mut dyn BufMut) {
        let list_header_self = alloy_rlp::Header { list: true, payload_length: self.length() };
        list_header_self.encode(out);

        let list_header_tx_sidecar = alloy_rlp::Header {
            list: true,
            payload_length: self.blob_transaction_sidecar.length(),
        };
        list_header_tx_sidecar.encode(out);

        self.blob_transaction_sidecar.encode(out);
        self.block_number.encode(out);
        self.block_hash.encode(out);
        self.tx_index.encode(out);
        self.tx_hash.encode(out);
    }

    fn length(&self) -> usize {
        self.blob_transaction_sidecar.length() +
            self.blob_transaction_sidecar.length().length() +
            self.block_number.length() +
            self.block_hash.length() +
            self.tx_index.length() +
            self.tx_hash.length()
    }
}

impl Decodable for BlobSidecar {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let _rlp_head_self = alloy_rlp::Header::decode(buf)?;
        let _rlp_head_tx_sidecar = alloy_rlp::Header::decode(buf)?;

        let this = Self {
            blob_transaction_sidecar: BlobTransactionSidecar {
                blobs: Decodable::decode(buf)?,
                commitments: Decodable::decode(buf)?,
                proofs: Decodable::decode(buf)?,
            },
            block_number: Decodable::decode(buf)?,
            block_hash: Decodable::decode(buf)?,
            tx_index: Decodable::decode(buf)?,
            tx_hash: Decodable::decode(buf)?,
        };

        return Ok(this)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::U256;
    use alloy_rlp::Decodable;

    #[test]
    fn encode_blob_sidecar() {
        let blob_sidecar = BlobSidecar {
            blob_transaction_sidecar: BlobTransactionSidecar {
                blobs: vec![],
                commitments: vec![],
                proofs: vec![],
            },
            block_number: U256::from(rand::random::<u64>()),
            block_hash: B256::random(),
            tx_index: rand::random::<u64>(),
            tx_hash: B256::random(),
        };

        let mut encoded = vec![];
        blob_sidecar.encode(&mut encoded);

        let decoded = BlobSidecar::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(blob_sidecar, decoded);
    }
}
