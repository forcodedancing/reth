//! Bsc Consensus implementation.

// TODO: doc
#![allow(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
// The `bsc` feature must be enabled to use this crate.
#![cfg(feature = "bsc")]

use alloy_json_abi::JsonAbi;
use alloy_rlp::Decodable;
use lazy_static::lazy_static;
use lru::LruCache;
use parking_lot::RwLock;
use reth_consensus::{Consensus, ConsensusError, PostExecutionInput};
use reth_consensus_common::validation::validate_header_standalone;
use reth_db::models::parlia::{Snapshot, ValidatorInfo, VoteAddress, VoteAttestation};
use reth_primitives::{
    constants::EMPTY_MIX_HASH, Address, BlockWithSenders, ChainSpec, GotExpected, Header,
    SealedBlock, SealedHeader, B256, EMPTY_OMMER_ROOT_HASH, U256,
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
    sync::Arc,
    time::SystemTime,
};

mod util;
pub use util::*;
mod constants;
pub use constants::*;
mod feynman_fork;
pub use feynman_fork::*;
mod error;
pub use error::ParliaConsensusError;
mod go_rng;
pub use go_rng::{RngSource, Shuffle};
mod abi;
pub use abi::*;
mod validation;
pub use validation::validate_block_post_execution;
mod system_tx;

const RECOVERED_PROPOSER_CACHE_NUM: usize = 4096;

lazy_static! {
    // recovered proposer cache map by block_number: proposer_address
    static ref RECOVERED_PROPOSER_CACHE: RwLock<LruCache<B256, Address>> = RwLock::new(LruCache::new(NonZeroUsize::new(RECOVERED_PROPOSER_CACHE_NUM).unwrap()));
}

#[derive(Clone, Debug)]
pub struct ParliaConfig {
    epoch: u64,
    period: u64,
}

impl Default for ParliaConfig {
    fn default() -> Self {
        Self { epoch: 200, period: 3 }
    }
}

/// BSC parlia consensus implementation
#[derive(Clone)]
pub struct Parlia {
    chain_spec: Arc<ChainSpec>,
    epoch: u64,
    period: u64,
    validator_abi: JsonAbi,
    validator_abi_before_luban: JsonAbi,
    slash_abi: JsonAbi,
    stake_hub_abi: JsonAbi,
}

impl Default for Parlia {
    fn default() -> Self {
        Self::new(Arc::new(ChainSpec::default()), ParliaConfig::default())
    }
}

impl Parlia {
    pub fn new(chain_spec: Arc<ChainSpec>, cfg: ParliaConfig) -> Self {
        let validator_abi = serde_json::from_str(*VALIDATOR_SET_ABI).unwrap();
        let validator_abi_before_luban =
            serde_json::from_str(*VALIDATOR_SET_ABI_BEFORE_LUBAN).unwrap();
        let slash_abi = serde_json::from_str(*SLASH_INDICATOR_ABI).unwrap();
        let stake_hub_abi = serde_json::from_str(*STAKE_HUB_ABI).unwrap();

        Self {
            chain_spec,
            epoch: cfg.epoch,
            period: cfg.period,
            validator_abi,
            validator_abi_before_luban,
            slash_abi,
            stake_hub_abi,
        }
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn period(&self) -> u64 {
        self.period
    }

    #[inline]
    pub fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    pub fn recover_proposer(&self, header: &Header) -> Result<Address, ParliaConsensusError> {
        let mut cache = RECOVERED_PROPOSER_CACHE.write();

        let hash = header.hash_slow();
        if let Some(&proposer) = cache.get(&hash) {
            return Ok(proposer);
        }

        let extra_data = &header.extra_data;

        if extra_data.len() < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaConsensusError::ExtraSignatureMissing);
        }
        let signature_offset = header.extra_data.len() - EXTRA_SEAL_LEN;

        let sig = &header.extra_data[signature_offset..signature_offset + EXTRA_SEAL_LEN - 1];
        let rec =
            RecoveryId::from_i32(header.extra_data[signature_offset + EXTRA_SEAL_LEN - 1] as i32)
                .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;
        let signature = RecoverableSignature::from_compact(sig, rec)
            .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;

        let message = Message::from_digest_slice(
            hash_with_chain_id(header, self.chain_spec.chain.id()).as_slice(),
        )
        .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;

        let public = &SECP256K1
            .recover_ecdsa(&message, &signature)
            .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;
        let address_slice = &Keccak256::digest(&public.serialize_uncompressed()[1..])[12..];
        let proposer = Address::from_slice(address_slice);

        cache.put(hash, proposer);
        Ok(proposer)
    }

    #[allow(clippy::type_complexity)]
    pub fn parse_validators_from_header(
        &self,
        header: &Header,
    ) -> Result<(Vec<Address>, Option<HashMap<Address, ValidatorInfo>>), ParliaConsensusError> {
        let val_bytes = self.get_validator_bytes_from_header(header).ok_or_else(|| {
            ParliaConsensusError::InvalidHeaderExtraLen {
                header_extra_len: header.extra_data.len() as u64,
            }
        })?;

        if val_bytes.is_empty() {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch: true,
                validator_bytes_len: 0,
            })
        }

        if !self.chain_spec.is_luban_active_at_block(header.number) {
            let count = val_bytes.len() / EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
            let mut vals = Vec::with_capacity(count);
            for i in 0..count {
                let start = i * EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
                let end = start + EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
                vals.push(Address::from_slice(&val_bytes[start..end]));
            }

            return Ok((vals, None));
        }

        let count = val_bytes.len() / EXTRA_VALIDATOR_LEN;
        let mut vals = Vec::with_capacity(count);
        let mut val_info_map = HashMap::with_capacity(count);
        for i in 0..count {
            let start = i * EXTRA_VALIDATOR_LEN;
            let end = start + ADDRESS_LENGTH;
            let addr = Address::from_slice(&val_bytes[start..end]);
            vals.push(addr);

            let start = i * EXTRA_VALIDATOR_LEN + ADDRESS_LENGTH;
            let end = i * EXTRA_VALIDATOR_LEN + EXTRA_VALIDATOR_LEN;
            val_info_map.insert(
                addr,
                ValidatorInfo {
                    index: (i + 1) as u64,
                    vote_addr: VoteAddress::from_slice(&val_bytes[start..end]),
                },
            );
        }

        Ok((vals, Some(val_info_map)))
    }

    pub fn get_vote_attestation_from_header(
        &self,
        header: &Header,
    ) -> Result<Option<VoteAttestation>, ParliaConsensusError> {
        if header.extra_data.len() <= EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Ok(None);
        }

        if !self.chain_spec.is_luban_active_at_block(header.number) {
            return Ok(None);
        }

        let mut raw;
        let extra_len = header.extra_data.len();
        if header.number % self.epoch != 0 {
            raw = &header.extra_data[EXTRA_VANITY_LEN..extra_len - EXTRA_SEAL_LEN]
        } else {
            let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
            let start = EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM + count * EXTRA_VALIDATOR_LEN;
            let end = extra_len - EXTRA_SEAL_LEN;
            raw = &header.extra_data[start..end];
        }
        if raw.is_empty() {
            return Ok(None);
        }

        Ok(Some(
            Decodable::decode(&mut raw).map_err(|_| ParliaConsensusError::ABIDecodeInnerError)?,
        ))
    }

    pub fn get_validator_bytes_from_header(&self, header: &Header) -> Option<Vec<u8>> {
        let extra_len = header.extra_data.len();
        if extra_len <= EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return None;
        }

        let is_luban_active = self.chain_spec.is_luban_active_at_block(header.number);
        let is_epoch = header.number % self.epoch == 0;

        if !is_luban_active {
            if is_epoch &&
                (extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN) %
                    EXTRA_VALIDATOR_LEN_BEFORE_LUBAN !=
                    0
            {
                return None;
            }

            Some(header.extra_data[EXTRA_VANITY_LEN..extra_len - EXTRA_SEAL_LEN].to_vec())
        } else {
            if !is_epoch {
                return None;
            }

            let count = header.extra_data[EXTRA_VANITY_LEN] as usize;
            if count == 0 ||
                extra_len <= EXTRA_VANITY_LEN + EXTRA_SEAL_LEN + count * EXTRA_VALIDATOR_LEN
            {
                return None;
            }

            let start = EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM;
            let end = start + count * EXTRA_VALIDATOR_LEN;

            Some(header.extra_data[start..end].to_vec())
        }
    }

    pub fn back_off_time(&self, snap: &Snapshot, header: &Header) -> u64 {
        let validator = header.beneficiary;
        if snap.is_inturn(validator) {
            return 0;
        }

        let mut delay = BACKOFF_TIME_OF_INITIAL;
        let mut validators = snap.validators.clone();

        if self.chain_spec.is_planck_active_at_block(header.number) {
            let validator_count = validators.len() as u64;

            let mut recents = HashMap::with_capacity(snap.recent_proposers.len());
            let bound = header.number.saturating_sub(validator_count / 2 + 1);
            for (&seen, &proposer) in snap.recent_proposers.iter() {
                if header.number <= bound {
                    continue
                };
                recents.insert(proposer, seen);
            }

            if recents.contains_key(&validator) {
                // The backOffTime does not matter when a validator has signed recently.
                return 0;
            }

            let inturn_addr = validators[((snap.block_number + 1) % validator_count) as usize];
            if recents.contains_key(&inturn_addr) {
                delay = 0
            }

            // Exclude the recently signed validators
            validators.retain(|addr| !recents.contains_key(addr));
        }

        // get the index of the current validator and its shuffled backoff time.
        let idx = match snap.index_of(validator) {
            Some(i) => i,
            None => {
                // The backOffTime does not matter when a validator is not authorized.
                return 0;
            }
        };

        let mut rng = RngSource::new(snap.block_number as i64);
        let mut back_off_steps: Vec<u64> = (0..validators.len() as u64).collect();
        back_off_steps.shuffle(&mut rng);
        delay += back_off_steps[idx] * BACKOFF_TIME_OF_WIGGLE;

        delay
    }

    fn check_header_extra_len(&self, header: &Header) -> Result<(), ParliaConsensusError> {
        let extra_len = header.extra_data.len();
        if extra_len < EXTRA_VANITY_LEN {
            return Err(ParliaConsensusError::ExtraVanityMissing);
        }
        if extra_len < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaConsensusError::ExtraSignatureMissing);
        }

        if header.number % self.epoch != 0 {
            return Ok(());
        }

        if !self.chain_spec.is_luban_active_at_block(header.number) {
            if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) / EXTRA_VALIDATOR_LEN_BEFORE_LUBAN ==
                0
            {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                });
            }
            if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) % EXTRA_VALIDATOR_LEN_BEFORE_LUBAN !=
                0
            {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                });
            }
        } else {
            let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
            let expect =
                EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM + EXTRA_SEAL_LEN + count * EXTRA_VALIDATOR_LEN;
            if count == 0 || extra_len < expect {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                });
            }
        }

        Ok(())
    }

    fn check_header_extra(&self, header: &Header) -> Result<(), ParliaConsensusError> {
        self.check_header_extra_len(header)?;

        let is_epoch = header.number % self.epoch == 0;
        let validator_bytes_len = self.get_validator_len_from_header(header)?;
        if !is_epoch && validator_bytes_len != 0 {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch,
                validator_bytes_len,
            });
        }
        if is_epoch && validator_bytes_len == 0 {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch,
                validator_bytes_len,
            });
        }

        Ok(())
    }

    fn get_validator_len_from_header(
        &self,
        header: &Header,
    ) -> Result<usize, ParliaConsensusError> {
        self.check_header_extra_len(header)?;

        if header.number % self.epoch != 0 {
            return Ok(0);
        }

        let extra_len = header.extra_data.len();

        if !self.chain_spec.is_luban_active_at_block(header.number) {
            return Ok(extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN);
        }

        let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
        Ok(count * EXTRA_VALIDATOR_LEN)
    }
}

impl Debug for Parlia {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parlia")
            .field("chain_spec", &self.chain_spec)
            .field("epoch", &self.epoch)
            .field("period", &self.period)
            .finish()
    }
}

impl Consensus for Parlia {
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        // Don't waste time checking blocks from the future
        let present_timestamp =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if header.timestamp > present_timestamp {
            return Err(ConsensusError::TimestampIsInFuture {
                timestamp: header.timestamp,
                present_timestamp,
            });
        }

        // Check extra data
        self.check_header_extra(header).map_err(|_| ConsensusError::InvalidHeaderExtra)?;

        // Ensure that the mix digest is zero as we don't have fork protection currently
        if header.mix_hash != EMPTY_MIX_HASH {
            return Err(ConsensusError::InvalidMixHash);
        }

        // Ensure that the block with no uncles
        if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected { got: header.ommers_hash, expected: EMPTY_OMMER_ROOT_HASH }.into(),
            ));
        }

        validate_header_standalone(header, &self.chain_spec)?;
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        header.validate_against_parent(parent, &self.chain_spec).map_err(ConsensusError::from)?;
        Ok(())
    }

    // No total difficulty check for Parlia
    fn validate_header_with_total_difficulty(
        &self,
        _header: &Header,
        _total_difficulty: U256,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock) -> Result<(), ConsensusError> {
        // Check transaction root
        if let Err(error) = block.ensure_transaction_root_valid() {
            return Err(ConsensusError::BodyTransactionRootDiff(error.into()));
        }

        // EIP-4844: Shard Blob Transactions
        if self.chain_spec.is_cancun_active_at_timestamp(block.timestamp) {
            // Check that the blob gas used in the header matches the sum of the blob gas used by
            // each blob tx
            let header_blob_gas_used =
                block.blob_gas_used.ok_or(ConsensusError::BlobGasUsedMissing)?;
            let total_blob_gas = block.blob_gas_used();
            if total_blob_gas != header_blob_gas_used {
                return Err(ConsensusError::BlobGasUsedDiff(GotExpected {
                    got: header_blob_gas_used,
                    expected: total_blob_gas,
                }));
            }
        }

        Ok(())
    }

    fn validate_block_post_execution(
        &self,
        block: &BlockWithSenders,
        input: PostExecutionInput<'_>,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(block, &self.chain_spec, input.receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // To make sure the abi is correct
    #[test]
    fn new_parlia() {
        let parlia = Parlia::new(Arc::new(ChainSpec::default()), ParliaConfig::default());
        assert_eq!(parlia.epoch(), 300);
        assert_eq!(parlia.period(), 15);
    }
}
