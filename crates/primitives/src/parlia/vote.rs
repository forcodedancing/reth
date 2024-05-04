use crate::{keccak256, BlockNumber, B256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};
use bytes::Bytes;
use reth_rpc_types::beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};

/// max attestation extra length
pub const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;
pub type ValidatorsBitSet = u64;

/// VoteData represents the vote range that validator voted for fast finality.
#[derive(
    Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize, RlpEncodable, RlpDecodable,
)]
pub struct VoteData {
    /// The source block number should be the latest justified block number.
    pub source_number: BlockNumber,
    /// The block hash of the source block.
    pub source_hash: B256,
    /// The target block number which validator wants to vote for.
    pub target_number: BlockNumber,
    /// The block hash of the target block.
    pub target_hash: B256,
}

impl VoteData {
    pub fn hash(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

/// VoteEnvelope a single vote from validator.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct VoteEnvelope {
    pub vote_address: BlsPublicKey,
    pub signature: BlsSignature,
    // the vote for fast finality
    pub data: VoteData,
}

impl VoteEnvelope {
    pub fn hash(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }

    /// verify, check if VoteEnvelope's signature is valid
    pub fn verify(&self) -> Result<(), Err> {
        let bls_key = PublicKey::from_bytes(&self.vote_address[..])?;
        let sig = Signature::from_bytes(&self.signature[..])?;

        let err = sig.verify(true, self.hash().as_bytes(), &[], &[], &bls_key, true);
        if !err == BLST_ERROR::BLST_SUCCESS {
            return Err(err.into());
        }
        Ok(())
    }
}

/// VoteAttestation represents the votes of super majority validators.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct VoteAttestation {
    /// The bitset marks the voted validators.
    pub vote_address_set: ValidatorsBitSet,
    /// The aggregated BLS signature of the voted validators' signatures.
    pub agg_signature: BlsSignature,
    /// The vote data for fast finality.
    pub data: VoteData,
    /// Reserved for future usage.
    pub extra: Bytes,
}
