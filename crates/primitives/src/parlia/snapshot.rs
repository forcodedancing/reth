use crate::{
    parlia::{VoteAttestation, VoteData},
    Address, BlockNumber, ChainSpec, GotExpected, SealedHeader, B256,
};
use reth_codecs::main_codec;
use reth_ethereum_forks::Hardfork;
use reth_rpc_types::beacon::BlsPublicKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// Number of blocks after which to save the snapshot to the database
pub const CHECKPOINT_INTERVAL: u64 = 1024;

/// record validators information
#[main_codec]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Default))]
pub struct ValidatorInfo {
    /// The index should offset by 1
    pub index: usize,
    pub vote_addr: BlsPublicKey,
}

/// Snapshot, record validators and proposal from epoch chg.
#[main_codec]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Default))]
pub struct Snapshot {
    /// record current epoch number
    pub epoch_num: u64,
    /// record block number when epoch chg
    pub block_number: BlockNumber,
    /// record block hash when epoch chg
    pub block_hash: B256,
    /// record epoch validators when epoch chg, sorted by ascending order.
    pub validators: Vec<Address>,
    /// record every validator's information
    pub validators_map: HashMap<Address, ValidatorInfo>,
    /// record recent block proposers
    pub recent_proposers: BTreeMap<BlockNumber, Address>,
    /// record the block attestation's vote data
    pub vote_data: Option<VoteData>,
}

impl Snapshot {
    pub fn new(
        mut validators: Vec<Address>,
        block_number: BlockNumber,
        block_hash: B256,
        epoch_num: u64,
        val_info_map: Option<HashMap<Address, ValidatorInfo>>,
    ) -> Self {
        // notice: the validators should be sorted by ascending order.
        validators.sort();
        Self {
            block_number,
            block_hash,
            epoch_num,
            validators,
            validators_map: val_info_map.unwrap_or_default(),
            recent_proposers: Default::default(),
            vote_data: None,
        }
    }

    // TODO: test apply
    pub fn apply(
        &mut self,
        validator: Address,
        next_header: &SealedHeader,
        mut next_validators: Vec<Address>,
        val_info_map: Option<HashMap<Address, ValidatorInfo>>,
        attestation: Option<VoteAttestation>,
    ) -> Option<Snapshot> {
        let block_number = next_header.number;
        if self.block_number + 1 != block_number {
            return None;
        }

        let mut snap = self.clone();
        snap.block_hash = next_header.hash();
        snap.block_number = block_number;
        let limit = (snap.validators.len() / 2 + 1) as u64;
        if block_number >= limit {
            snap.recent_proposers.remove(&(block_number - limit));
        }

        if !snap.validators.contains(&validator) {
            return None;
        }
        if snap.recent_proposers.iter().any(|(_, &addr)| addr == validator) {
            return None;
        }
        snap.recent_proposers.insert(block_number, validator);

        if !next_validators.is_empty() {
            next_validators.sort();
            snap.validators = next_validators;
            snap.validators_map = val_info_map.unwrap_or_default();
        }

        if let Some(attestation) = attestation {
            snap.vote_data = Some(attestation.data);
        }
        Some(snap)
    }

    /// Returns true if the block difficulty should be inturn
    pub fn is_inturn(&self, proposer: Address) -> bool {
        self.inturn_validator() == proposer
    }

    /// Returns the validator who should propose the block
    pub fn inturn_validator(&self) -> Address {
        self.validators[((self.block_number + 1) as usize) % self.validators.len()]
    }

    /// Return index of the validator's index in validators list
    pub fn index_of(&self, validator: Address) -> Option<usize> {
        for (i, &addr) in self.validators.iter().enumerate() {
            if validator == addr {
                return Some(i);
            }
        }
        None
    }

    pub fn sign_recently(&self, validator: Address) -> bool {
        for (num, addr) in self.recent_proposers.iter() {
            if *addr == validator {
                let limit = (self.validators.len() / 2 + 1) as u64;
                if self.block_number + 1 < limit || *num > self.block_number + 1 - limit {
                    return true;
                }
            }
        }
        false
    }
}
