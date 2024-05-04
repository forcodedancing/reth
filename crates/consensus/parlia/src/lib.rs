//! BSC Parlia consensus implementation.

#![allow(missing_docs)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use alloy_rlp::Decodable;
use bitset::BitSet;
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};
use lazy_static::lazy_static;
use lru::LruCache;
use parking_lot::RwLock;
use reth_db::database::Database;
use reth_provider::{HeaderProvider, ParliaSnapshotReader, ParliaSnapshotWriter};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    hash::Hash,
    num::NonZeroUsize,
    sync::Arc,
    time::SystemTime,
};

use reth_consensus_common::validation::validate_4844_header_standalone;
use reth_interfaces::consensus::{Consensus, ConsensusError, ParliaConsensusError};
use reth_primitives::{
    alloy_primitives::private::rand::prelude::SliceRandom,
    constants::EMPTY_MIX_HASH,
    parlia::{
        Snapshot, ValidatorInfo, VoteAttestation, CHECKPOINT_INTERVAL, MAX_ATTESTATION_EXTRA_LENGTH,
    },
    transaction::TransactionKind,
    Address, BlockNumber, Bytes, ChainSpec, GotExpected, Hardfork, Header, SealedBlock,
    SealedHeader, Transaction, TxLegacy, B256, EMPTY_OMMER_ROOT_HASH, U256,
};
use reth_rpc_types::beacon::BlsPublicKey;

mod util;
pub use util::*;
mod constants;
pub use constants::*;

pub mod contract_upgrade;
mod feynman_fork;
pub use feynman_fork::*;

const RECOVERED_PROPOSER_CACHE_NUM: usize = 4096;
const SNAP_CACHE_NUM: usize = 2048;

lazy_static! {
    // recovered proposer cache map by block_number: proposer_address
    static ref RECOVERED_PROPOSER_CACHE: RwLock<LruCache<B256, Address>> = RwLock::new(LruCache::new(NonZeroUsize::new(RECOVERED_PROPOSER_CACHE_NUM).unwrap()));

    // snapshot cache map by block_hash: snapshot
    static ref RECENT_SNAPS: RwLock<LruCache<B256, Snapshot>> = RwLock::new(LruCache::new(NonZeroUsize::new(SNAP_CACHE_NUM).unwrap()));
}

/// BSC parlia consensus implementation
#[derive(Debug)]
pub struct Parlia<P: HeaderProvider + ParliaSnapshotReader + ParliaSnapshotWriter> {
    chain_spec: Arc<ChainSpec>,
    epoch: u64,
    period: u64,
    validator_abi: JsonAbi,
    validator_abi_before_luban: JsonAbi,
    slash_abi: JsonAbi,
    stake_hub_abi: JsonAbi,
    provider: Option<P>,
}

impl<P: HeaderProvider + ParliaSnapshotReader + ParliaSnapshotWriter> Parlia<P> {
    pub fn new(chain_spec: Arc<ChainSpec>, epoch: u64, period: u64) -> Self {
        let validator_abi = load_abi_from_file("./abi/validator_set.json").unwrap();
        let validator_abi_before_luban =
            load_abi_from_file("./abi/validator_set_before_luban.json").unwrap();
        let slash_abi = load_abi_from_file("./abi/slash.json").unwrap();
        let stake_hub_abi = load_abi_from_file("./abi/stake_hub.json").unwrap();

        Self {
            chain_spec,
            epoch,
            period,
            validator_abi,
            validator_abi_before_luban,
            slash_abi,
            stake_hub_abi,
            provider: None,
        }
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn period(&self) -> u64 {
        self.period
    }

    pub fn recover_proposer(&self, header: &SealedHeader) -> Result<Address, ConsensusError> {
        let mut cache = RECOVERED_PROPOSER_CACHE.write();
        if let Some(&proposer) = cache.get(&header.hash()) {
            return Ok(proposer);
        }

        let extra_data = &header.extra_data;

        if extra_data.len() < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaConsensusError::ExtraSignatureMissing.into());
        }
        let signature_offset = header.extra_data.len() - EXTRA_SEAL_LEN;

        let sig = &header.extra_data[signature_offset..signature_offset + EXTRA_SEAL_LEN - 1];
        let rec =
            RecoveryId::from_i32(header.extra_data[signature_offset + EXTRA_SEAL_LEN - 1] as i32)?;
        let signature = RecoverableSignature::from_compact(sig, rec)?;

        let mut sig_hash_header = header.clone();
        sig_hash_header.extra_data =
            Bytes::copy_from_slice(&header.extra_data[..header.extra_data.len() - EXTRA_SEAL_LEN]);
        let message = Message::from_digest_slice(
            sig_hash_header.hash_with_chain_id(self.chain_spec.chain.id()).as_bytes(),
        )?;

        let public = &SECP256K1.recover_ecdsa(&message, &signature)?;
        let address_slice = &Keccak256::digest(&public.serialize_uncompressed()[1..])[12..];
        let proposer = Address::from_slice(address_slice);

        cache.put(header.hash(), proposer);
        Ok(proposer)
    }

    pub fn parse_validators_from_header(
        &self,
        header: &Header,
    ) -> Result<(Vec<Address>, Option<HashMap<Address, ValidatorInfo>>), ConsensusError> {
        let val_bytes = self.get_validator_bytes_from_header(header)?;

        if !self.chain_spec.fork(Hardfork::Luban).active_at_block(header.number) {
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
                    index: i + 1,
                    vote_addr: BlsPublicKey::from_slice(&val_bytes[start..end]),
                },
            );
        }

        Ok((vals, Some(val_info_map)))
    }

    pub fn get_vote_attestation_from_header(
        &self,
        header: &Header,
    ) -> Result<Option<VoteAttestation>, ConsensusError> {
        self.check_header_extra_len(header)?;

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

        Ok(Some(Decodable::decode(&mut raw)?))
    }

    pub fn get_snapshot_from_cache(&self, hash: &B256) -> Option<Snapshot> {
        let mut cache = RECENT_SNAPS.read();

        cache.get(hash).cloned()
    }

    pub fn get_validator_bytes_from_header(
        &self,
        header: &Header,
    ) -> Result<&[u8], ConsensusError> {
        self.check_header_extra_len(header)?;

        if header.number % self.epoch != 0 {
            return Err(ParliaConsensusError::NotInEpoch { block_number: header.number }.into());
        }

        let extra_len = header.extra_data.len();

        if !self.chain_spec.fork(Hardfork::Luban).active_at_block(header.number) {
            return Ok(&header.extra_data[EXTRA_VANITY_LEN..extra_len - EXTRA_SEAL_LEN]);
        }

        let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
        let start = EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM;
        let end = start + count * EXTRA_VALIDATOR_LEN;

        Ok(&header.extra_data[start..end])
    }

    fn check_header_extra_len(&self, header: &Header) -> Result<(), ConsensusError> {
        let extra_len = header.extra_data.len();
        if extra_len < EXTRA_VANITY_LEN {
            return Err(ParliaConsensusError::ExtraVanityMissing.into());
        }
        if extra_len < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaConsensusError::ExtraSignatureMissing.into());
        }

        if header.number % self.epoch != 0 {
            return Ok(());
        }

        if !self.chain_spec.fork(Hardfork::Luban).active_at_block(header.number) {
            if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) / EXTRA_VALIDATOR_LEN_BEFORE_LUBAN ==
                0
            {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                }
                .into());
            }
            if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) % EXTRA_VALIDATOR_LEN_BEFORE_LUBAN !=
                0
            {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                }
                .into());
            }
        } else {
            let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
            let expect =
                EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM + EXTRA_SEAL_LEN + count * EXTRA_VALIDATOR_LEN;
            if count == 0 || extra_len < expect {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                }
                .into());
            }
        }

        Ok(())
    }

    fn check_header_extra(&self, header: &Header) -> Result<(), ConsensusError> {
        self.check_header_extra_len(header)?;

        let is_epoch = header.number % self.epoch == 0;
        let validator_bytes_len = self.get_validator_len_from_header(header)?;
        if !is_epoch && validator_bytes_len != 0 {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch,
                validator_bytes_len,
            }
            .into());
        }
        if is_epoch && validator_bytes_len == 0 {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch,
                validator_bytes_len,
            }
            .into());
        }

        Ok(())
    }

    fn verify_block_time_for_ramanujan(
        &self,
        snapshot: &Snapshot,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec.fork(Hardfork::Ramanujan).active_at_block(header.number) {
            if header.timestamp <
                parent.timestamp +
                    self.period +
                    self.backoff_time(snapshot, header, header.beneficiary)
            {
                return Err(ParliaConsensusError::FutureBlock {
                    block_number: header.number,
                    hash: header.hash(),
                }
                .into());
            }
        }
    }

    fn verify_seal(&self, snap: &Snapshot, header: &SealedHeader) -> Result<(), ConsensusError> {
        let block_number = header.number;
        let proposer = self.recover_proposer(header)?;

        if proposer != header.beneficiary {
            return Err(ParliaConsensusError::WrongHeaderSigner {
                block_number,
                expected: header.beneficiary,
                got: proposer,
            }
            .into());
        }

        if !snap.validators.contains(&proposer) {
            return Err(ParliaConsensusError::SignerUnauthorized { block_number, proposer }.into());
        }

        for (seen, recent) in snap.recent_proposers.iter() {
            if *recent == proposer {
                // Signer is among recent_proposers, only fail if the current block doesn't shift it
                // out
                let limit = self.get_recently_proposal_limit(header, snap.validators.len() as u64);
                if *seen > block_number - limit {
                    return Err(ParliaConsensusError::SignerOverLimit { proposer }.into());
                }
            }
        }

        let is_inturn = snap.is_inturn(proposer);
        if (is_inturn && header.difficulty != DIFF_INTURN) ||
            (!is_inturn && header.difficulty != DIFF_NOTURN)
        {
            return Err(
                ParliaConsensusError::InvalidDifficulty { difficulty: header.difficulty }.into()
            );
        }

        Ok(())
    }

    fn get_recently_proposal_limit(&self, header: &Header, validator_count: u64) -> u64 {
        if self.chain_spec.fork(Hardfork::Luban).active_at_block(header.number) {
            validator_count * 2 / 3 + 1
        } else {
            validator_count / 2 + 1
        }
    }

    fn get_validator_len_from_header(&self, header: &Header) -> Result<usize, ConsensusError> {
        self.check_header_extra_len(header)?;

        if header.number % self.epoch != 0 {
            return Ok(0);
        }

        let extra_len = header.extra_data.len();

        if !self.chain_spec.fork(Hardfork::Luban).active_at_block(header.number) {
            return Ok(extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN);
        }

        let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
        Ok(count * EXTRA_VALIDATOR_LEN)
    }
}

impl<P> Parlia<P> {
    pub fn init_genesis_contracts(&self, nonce: u64) -> Vec<Transaction> {
        let function = self.validator_abi.function("init").unwrap().first().unwrap();
        let input = function.abi_encode_input(&[]).unwrap();

        let contracts = vec![
            *VALIDATOR_CONTRACT,
            *SLASH_CONTRACT,
            *LIGHT_CLIENT_CONTRACT,
            *RELAYER_HUB_CONTRACT,
            *TOKEN_HUB_CONTRACT,
            *RELAYER_INCENTIVIZE_CONTRACT,
            *CROSS_CHAIN_CONTRACT,
        ];

        contracts
            .into_iter()
            .enumerate()
            .map(|(idx, contract)| {
                Transaction::Legacy(TxLegacy {
                    chain_id: Some(self.chain_spec.chain.id()),
                    nonce: nonce + idx as u64,
                    gas_limit: u64::MAX / 2,
                    gas_price: 0,
                    value: U256::ZERO,
                    input: Bytes::from(input.clone()),
                    to: TransactionKind::Call(contract),
                })
            })
            .collect()
    }

    pub fn init_feynman_contracts(&self, nonce: u64) -> Vec<Transaction> {
        let function = self.stake_hub_abi.function("initialize").unwrap().first().unwrap();
        let input = function.abi_encode_input(&[]).unwrap();

        let contracts = vec![
            *STAKE_HUB_CONTRACT,
            *BSC_GOVERNOR_CONTRACT,
            *GOV_TOKEN_CONTRACT,
            *BSC_TIMELOCK_CONTRACT,
            *TOKEN_RECOVER_PORTAL_CONTRACT,
        ];

        contracts
            .into_iter()
            .enumerate()
            .map(|(idx, contract)| {
                Transaction::Legacy(TxLegacy {
                    chain_id: Some(self.chain_spec.chain.id()),
                    nonce: nonce + idx as u64,
                    gas_limit: u64::MAX / 2,
                    gas_price: 0,
                    value: U256::ZERO,
                    input: Bytes::from(input.clone()),
                    to: TransactionKind::Call(contract),
                })
            })
            .collect()
    }

    pub fn slash(&self, nonce: u64, address: Address) -> Transaction {
        let function = self.slash_abi.function("slash").unwrap().first().unwrap();
        let input = function.abi_encode_input(&[DynSolValue::from(address)]).unwrap();

        Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce,
            gas_limit: u64::MAX / 2,
            gas_price: 0,
            value: U256::ZERO,
            input: Bytes::from(input.clone()),
            to: TransactionKind::Call(*SLASH_CONTRACT),
        })
    }

    pub fn distribute_to_system(&self, nonce: u64, system_reward: u128) -> Transaction {
        Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce,
            gas_limit: u64::MAX / 2,
            gas_price: 0,
            value: U256::from(system_reward),
            input: Bytes::default(),
            to: TransactionKind::Call(*SYSTEM_REWARD_CONTRACT),
        })
    }

    pub fn distribute_to_validator(
        &self,
        nonce: u64,
        address: Address,
        block_reward: u128,
    ) -> Transaction {
        let function = self.validator_abi.function("deposit").unwrap().first().unwrap();
        let input = function.abi_encode_input(&[DynSolValue::from(address)]).unwrap();

        Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce,
            gas_limit: u64::MAX / 2,
            gas_price: 0,
            value: U256::from(block_reward),
            input: Bytes::from(input),
            to: TransactionKind::Call(*VALIDATOR_CONTRACT),
        })
    }

    pub fn distribute_finality_reward(
        &self,
        nonce: u64,
        validators: Vec<Address>,
        weights: Vec<U256>,
    ) -> Transaction {
        let function =
            self.validator_abi.function("distributeFinalityReward").unwrap().first().unwrap();

        let validators = validators.into_iter().map(|val| DynSolValue::from(val)).collect();
        let weights = weights.into_iter().map(|weight| DynSolValue::from(weight)).collect();
        let input = function
            .abi_encode_input(&[DynSolValue::Array(validators), DynSolValue::Array(weights)])
            .unwrap();

        Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce,
            gas_limit: u64::MAX / 2,
            gas_price: 0,
            value: U256::ZERO,
            input: Bytes::from(input),
            to: TransactionKind::Call(*VALIDATOR_CONTRACT),
        })
    }

    pub fn update_validator_set_v2(
        &self,
        nonce: u64,
        validators: Vec<Address>,
        voting_powers: Vec<U256>,
        vote_addresses: Vec<Vec<u8>>,
    ) -> Transaction {
        let function =
            self.validator_abi.function("updateValidatorSetV2").unwrap().first().unwrap();

        let validators = validators.into_iter().map(|val| DynSolValue::from(val)).collect();
        let voting_powers = voting_powers.into_iter().map(|val| DynSolValue::from(val)).collect();
        let vote_addresses = vote_addresses.into_iter().map(|val| DynSolValue::from(val)).collect();
        let input = function
            .abi_encode_input(&[
                DynSolValue::Array(validators),
                DynSolValue::Array(voting_powers),
                DynSolValue::Array(vote_addresses),
            ])
            .unwrap();

        Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce,
            gas_limit: u64::MAX / 2,
            gas_price: 0,
            value: U256::ZERO,
            input: Bytes::from(input),
            to: TransactionKind::Call(*VALIDATOR_CONTRACT),
        })
    }
}

impl<P> Parlia<P> {
    pub fn get_current_validators_before_luban(
        &self,
        block_number: BlockNumber,
    ) -> (Address, Bytes) {
        let function = if self.chain_spec.fork(Hardfork::Euler).active_at_block(block_number) {
            self.validator_abi_before_luban
                .function("getMiningValidators")
                .unwrap()
                .first()
                .unwrap()
        } else {
            self.validator_abi_before_luban.function("getValidators").unwrap().first().unwrap()
        };

        (*VALIDATOR_CONTRACT, Bytes::from(function.abi_encode_input(&[]).unwrap()))
    }

    pub fn unpack_data_into_validator_set_before_luban(&self, data: &[u8]) -> Vec<Address> {
        let function =
            self.validator_abi_before_luban.function("getValidators").unwrap().first().unwrap();
        let output = function.abi_decode_output(data, true).unwrap();

        output.into_iter().map(|val| val.as_address().unwrap()).collect()
    }

    pub fn get_current_validators(&self) -> (Address, Bytes) {
        let function = self.validator_abi.function("getMiningValidators").unwrap().first().unwrap();

        (*VALIDATOR_CONTRACT, Bytes::from(function.abi_encode_input(&[]).unwrap()))
    }

    pub fn unpack_data_into_validator_set(&self, data: &[u8]) -> (Vec<Address>, Vec<BlsPublicKey>) {
        let function = self.validator_abi.function("getMiningValidators").unwrap().first().unwrap();
        let output = function.abi_decode_output(data, true).unwrap();

        let consensus_addresses = output[0]
            .as_array()
            .unwrap()
            .into_iter()
            .map(|val| val.as_address().unwrap())
            .collect();
        let vote_address =
            output[1].as_array().unwrap().into_iter().map(|val| val.as_bytes().unwrap()).collect();

        (consensus_addresses, vote_address)
    }

    pub fn get_validator_election_info(&self) -> (Address, Bytes) {
        let function =
            self.stake_hub_abi.function("getValidatorElectionInfo").unwrap().first().unwrap();

        (
            *STAKE_HUB_CONTRACT,
            Bytes::from(
                function
                    .abi_encode_input(&[
                        DynSolValue::from(U256::from(0)),
                        DynSolValue::from(U256::from(0)),
                    ])
                    .unwrap(),
            ),
        )
    }

    pub fn unpack_data_into_validator_election_info(
        &self,
        data: &[u8],
    ) -> (Vec<Address>, Vec<U256>, Vec<Vec<u8>>, U256) {
        let function =
            self.stake_hub_abi.function("getValidatorElectionInfo").unwrap().first().unwrap();
        let output = function.abi_decode_output(data, true).unwrap();

        let consensus_address = output[0]
            .as_array()
            .unwrap()
            .into_iter()
            .map(|val| val.as_address().unwrap())
            .collect();
        let voting_powers = output[1]
            .as_array()
            .unwrap()
            .into_iter()
            .map(|val| val.as_uint().unwrap().into())
            .collect();
        let vote_addresses = output[2]
            .as_array()
            .unwrap()
            .into_iter()
            .map(|val| val.as_bytes().unwrap().to_vec())
            .collect();
        let total_length = output[3].as_uint().unwrap().into();

        (consensus_address, voting_powers, vote_addresses, total_length)
    }

    pub fn get_max_elected_validators(&self) -> (Address, Bytes) {
        let function =
            self.stake_hub_abi.function("maxElectedValidators").unwrap().first().unwrap();

        (*STAKE_HUB_CONTRACT, Bytes::from(function.abi_encode_input(&[]).unwrap()))
    }

    pub fn unpack_data_into_max_elected_validators(&self, data: &[u8]) -> U256 {
        let function =
            self.stake_hub_abi.function("maxElectedValidators").unwrap().first().unwrap();
        let output = function.abi_decode_output(data, true).unwrap();

        output[0].as_uint().unwrap().into()
    }
}

impl<P> Parlia<P> {
    pub fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    pub fn is_on_feynman(&self, timestamp: u64, parent_timestamp: u64) -> bool {
        self.chain_spec.fork(Hardfork::Feynman).active_at_timestamp(timestamp) &&
            !self.chain_spec.fork(Hardfork::Feynman).active_at_timestamp(parent_timestamp)
    }

    pub fn is_on_luban(&self, block_number: BlockNumber) -> bool {
        self.chain_spec.fork(Hardfork::Luban).active_at_block(block_number) &&
            !self.chain_spec.fork(Hardfork::Luban).active_at_block(block_number - 1)
    }
}

impl<P: HeaderProvider> Parlia<P> {
    pub fn verify_cascading_fields<P>(
        &self,
        snap: &Snapshot,
        header: &SealedHeader,
        parent: Option<&SealedHeader>,
    ) -> Result<(), ConsensusError> {
        if header.number == 0 {
            return Ok(());
        }

        let parent = parent.ok_or(ParliaConsensusError::UnknownAncestor {
            block_number: header.number,
            hash: header.hash(),
        })?;

        self.verify_block_time_for_ramanujan(snap, header, parent)?;
        self.verify_vote_attestation(snap, header, parent)?;
        self.verify_seal(snap, header)?;

        Ok(())
    }

    pub fn get_finality_weights<P>(
        &self,
        header: &Header,
    ) -> Result<(Vec<Address>, Vec<U256>), ConsensusError> {
        if header.number % self.epoch != 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut header = header;
        let mut accumulated_weights: HashMap<Address, U256> = HashMap::new();
        let start = (header.number - self.epoch).max(1);
        for height in (start..header.number).rev() {
            let header = self.get_header_by_hash(height, header.parent_hash)?;
            if let Some(attestation) = self.get_vote_attestation_from_header(&header)? {
                let justified_header = self.get_header_by_hash(
                    attestation.data.target_number,
                    attestation.data.target_hash,
                )?;
                let snap = self.snapshot(&justified_header, None)?;
                let validators = snap.validators;
                let validators_bit_set = BitSet::from_u64(attestation.vote_address_set);
                if validators_bit_set.count() as usize > validators.len() {
                    return Err(ParliaConsensusError::InvalidAttestationVoteCount(GotExpected {
                        got: validators_bit_set.count(),
                        expected: validators.len() as u64,
                    })
                    .into());
                }

                let mut valid_vote_count = 0;
                for (index, val) in validators.iter().enumerate() {
                    if validators_bit_set.test(index) {
                        *accumulated_weights.entry(*val).or_insert(U256::ZERO) += U256::from(1);
                        valid_vote_count += 1;
                    }
                }
                let quorum = (snap.validators.len() * 2 + 2) / 3; // ceil div
                if valid_vote_count > quorum {
                    *accumulated_weights.entry(header.beneficiary).or_insert(U256::ZERO) +=
                        U256::from(
                            ((valid_vote_count - quorum) * COLLECT_ADDITIONAL_VOTES_REWARD_RATIO) /
                                100,
                        );
                }
            }
        }

        let mut validators: Vec<Address> = accumulated_weights.keys().cloned().collect();
        validators.sort();
        let weights: Vec<U256> =
            validators.iter().map(|val| accumulated_weights[val].clone()).collect();

        Ok((validators, weights))
    }

    pub fn get_header_by_hash(
        &self,
        block_number: BlockNumber,
        hash: B256,
    ) -> Result<SealedHeader, ConsensusError> {
        let provider = self.provider.as_ref().ok_or(ParliaConsensusError::ProviderNotSet.into())?;
        let header = provider
            .sealed_header(block_number)?
            .ok_or(ParliaConsensusError::UnknownHeader { block_number, hash }.into())?;

        return if header.hash() == hash {
            Ok(header)
        } else {
            Err(ParliaConsensusError::UnknownHeader { block_number, hash }.into())
        }
    }

    fn verify_vote_attestation<P>(
        &self,
        snap: &Snapshot,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        let attestation = self.get_vote_attestation_from_header(header)?;
        if let Some(attestation) = attestation {
            if attestation.extra.len() > MAX_ATTESTATION_EXTRA_LENGTH {
                return Err(ParliaConsensusError::TooLargeAttestationExtraLen {
                    extra_len: MAX_ATTESTATION_EXTRA_LENGTH,
                }
                .into());
            }

            // the attestation target block should be direct parent.
            let target_block = attestation.data.target_number;
            let target_hash = attestation.data.target_hash;
            if target_block != parent.number || target_hash != header.parent_hash {
                return Err(ParliaConsensusError::InvalidAttestationTarget {
                    block_number: GotExpected { got: target_block, expected: parent.number },
                    block_hash: GotExpected { got: target_hash, expected: parent.hash() }.into(),
                }
                .into());
            }

            // the attestation source block should be the highest justified block.
            let source_block = attestation.data.source_number;
            let source_hash = attestation.data.source_hash;
            let ref justified: SealedHeader = self.get_justified_header(snap, parent)?;
            if source_block != justified.number || source_hash != justified.hash() {
                return Err(ParliaConsensusError::InvalidAttestationSource {
                    block_number: GotExpected { got: source_block, expected: justified.number },
                    block_hash: GotExpected { got: source_hash, expected: justified.hash() }.into(),
                }
                .into());
            }

            // query bls keys from snapshot.
            let validators_count = snap.validators.len();
            let vote_bit_set = BitSet::from_u64(attestation.vote_address_set);
            let bit_set_count = vote_bit_set.count() as usize;

            if bit_set_count > validators_count {
                return Err(ParliaConsensusError::InvalidAttestationVoteCount(GotExpected {
                    got: bit_set_count as u64,
                    expected: validators_count as u64,
                })
                .into());
            }
            let mut vote_addrs: Vec<BlsPublicKey> = Vec::with_capacity(bit_set_count);
            for (i, val) in snap.validators.iter().enumerate() {
                if !vote_bit_set.test(i) {
                    continue;
                }

                let val_info = snap
                    .validators_map
                    .get(val)
                    .ok_or(ParliaConsensusError::SnapNotFoundVoteAddr { address: *val }.into())?;
                vote_addrs.push(BlsPublicKey::from_slice(&val_info.vote_addr[..])?);
            }

            // check if voted validator count satisfied 2/3+1
            let at_least_votes = validators_count * 2 / 3;
            if vote_addrs.len() < at_least_votes {
                return Err(ParliaConsensusError::InvalidAttestationVoteCount(GotExpected {
                    got: vote_addrs.len() as u64,
                    expected: at_least_votes as u64,
                })
                .into());
            }

            // check bls aggregate sig
            let vote_addrs: Vec<&PublicKey> =
                vote_addrs.iter().map(|bytes| &PublicKey::from_bytes(&bytes[..])?).collect();

            let sig = Signature::from_bytes(&attestation.agg_signature[..])?;
            let err = sig.aggregate_verify(
                true,
                &[attestation.data.hash().as_bytes()],
                &[],
                &vote_addrs,
                true,
            )?;

            if !err == BLST_ERROR::BLST_SUCCESS {
                return Err(err.into());
            }
        }

        Ok(())
    }

    fn get_justified_header<P>(
        &self,
        snap: &Snapshot,
        header: &SealedHeader,
    ) -> Result<SealedHeader, ConsensusError> {
        let header_provider =
            self.provider.as_ref().ok_or(ParliaConsensusError::ProviderNotSet.into())?;
        // If there has vote justified block, find it or return naturally justified block.
        if let Some(ref vote) = snap.vote_data {
            if snap.block_number - vote.target_number > NATURALLY_JUSTIFIED_DIST {
                return self.find_ancient_header(header, NATURALLY_JUSTIFIED_DIST);
            }
            return Ok(header_provider.sealed_header(vote.target_number)?.ok_or_else(|| {
                ParliaConsensusError::UnknownHeader {
                    block_number: vote.target_number,
                    hash: vote.target_hash,
                }
            })?);
        }

        // If there is no vote justified block, then return root or naturally justified block.
        if header.number < NATURALLY_JUSTIFIED_DIST {
            return Ok(header_provider.sealed_header(0)?.ok_or_else(|| {
                ParliaConsensusError::UnknownHeader { block_number: 0, hash: Default::default() }
            })?);
        }

        self.find_ancient_header(header, NATURALLY_JUSTIFIED_DIST)
    }

    fn find_ancient_header<P>(
        &self,
        header: &SealedHeader,
        count: u64,
    ) -> Result<SealedHeader, ConsensusError> {
        let header_provider =
            self.provider.as_ref().ok_or(ParliaConsensusError::ProviderNotSet.into())?;
        let mut result = header.clone();
        for _ in 0..count {
            result = header_provider.sealed_header(result.number - 1)?.ok_or_else(|| {
                ParliaConsensusError::UnknownHeader {
                    block_number: result.number,
                    hash: result.hash(),
                }
                .into()
            })?;
        }
        Ok(result)
    }
}

impl<P: HeaderProvider + ParliaSnapshotReader + ParliaSnapshotWriter> Parlia<P> {
    pub fn set_provider(&mut self, provider: P) {
        self.provider = Some(provider);
    }

    pub fn snapshot<P>(
        &self,
        mut header: &SealedHeader,
        parent: Option<&SealedHeader>,
    ) -> Result<Snapshot, ConsensusError> {
        let provider = self.provider.as_ref().ok_or(ParliaConsensusError::ProviderNotSet.into())?;
        let mut cache = RECENT_SNAPS.write();

        let mut block_number = header.number;
        let mut block_hash = header.hash();
        let mut skip_headers = Vec::new();

        let mut snap: Snapshot;
        loop {
            // Read from cache
            if let Some(cached) = cache.get(&block_hash) {
                snap = cached.clone();
                break;
            }

            // Read from db
            if block_number % CHECKPOINT_INTERVAL == 0 {
                if let Some(cached) = provider.get_parlia_snapshot(block_hash)? {
                    snap = cached;
                    break;
                }
            }

            // If we're at the genesis, snapshot the initial state.
            if block_number == 0 {
                let (next_validators, bls_keys) = self.parse_validators_from_header(header)?;
                snap =
                    Snapshot::new(next_validators, block_number, block_hash, self.epoch, bls_keys);
                break;
            }

            // No snapshot for this header, gather the header and move backward
            skip_headers.push(header);
            if let Some(h) = parent {
                header = h;
                block_number = header.number;
                block_hash = header.hash();
            } else {
                if let Some(h) = provider.sealed_header(block_number - 1)? {
                    if h.hash() != header.parent_hash {
                        return Err(ConsensusError::ParentUnknown { hash: block_hash });
                    }
                    header = &h;
                    block_number = header.number;
                    block_hash = header.hash();
                }
            }
        }

        // apply skip headers
        skip_headers.reverse();
        for header in skip_headers.iter() {
            let validator = self.recover_proposer(header)?;
            let (next_validators, bls_keys) = self.parse_validators_from_header(header)?;
            let attestation = self.get_vote_attestation_from_header(header)?;
            snap = snap
                .apply(validator, header, next_validators, bls_keys, attestation)
                .ok_or(|_| ParliaConsensusError::ApplySnapshotFailed)?;
        }

        cache.put(snap.block_hash, snap.clone());
        if snap.block_number % CHECKPOINT_INTERVAL == 0 {
            provider.save_parlia_snapshot(snap.block_hash, snap.clone())?;
        }

        Ok(snap)
    }
}

impl<P> Debug for Parlia<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parlia")
            .field("chain_spec", &self.chain_spec)
            .field("epoch", &self.epoch)
            .field("period", &self.period)
            .finish()
    }
}

impl<P> Consensus for Parlia<P> {
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        // Don't waste time checking blocks from the future
        let present_timestamp =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if header.timestamp > present_timestamp {
            return Err(ConsensusError::TimestampIsInFuture {
                timestamp: header.timestamp,
                present_timestamp,
            }
            .into());
        }

        // Ensure that the block's difficulty is DIFF_INTURN or DIFF_NOTURN
        if header.difficulty != DIFF_INTURN && header.difficulty != DIFF_NOTURN {
            return Err(
                ParliaConsensusError::InvalidDifficulty { difficulty: header.difficulty }.into()
            );
        }

        // Check extra data
        self.check_header_extra(header)?;

        // Ensure that the mix digest is zero as we don't have fork protection currently
        if header.mix_hash != EMPTY_MIX_HASH {
            return Err(ParliaConsensusError::InvalidMixHash.into());
        }

        // Ensure that the block with no uncles
        if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected { got: header.ommers_hash, expected: EMPTY_OMMER_ROOT_HASH }.into(),
            ));
        }

        // Gas used needs to be less than gas limit. Gas used is going to be checked after
        // execution.
        if header.gas_used > header.gas_limit {
            return Err(ConsensusError::HeaderGasUsedExceedsGasLimit {
                gas_used: header.gas_used,
                gas_limit: header.gas_limit,
            });
        }

        // Check if base fee is set.
        if self.chain_spec.fork(Hardfork::London).active_at_block(header.number) &&
            header.base_fee_per_gas.is_none()
        {
            return Err(ConsensusError::BaseFeeMissing);
        }

        // Ensures that EIP-4844 fields are valid once cancun is active.
        if self.chain_spec.is_cancun_active_at_timestamp(header.timestamp) {
            validate_4844_header_standalone(header)?;
        } else if header.blob_gas_used.is_some() {
            return Err(ConsensusError::BlobGasUsedUnexpected);
        } else if header.excess_blob_gas.is_some() {
            return Err(ConsensusError::ExcessBlobGasUnexpected);
        } else if header.parent_beacon_block_root.is_some() {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

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
        header: &Header,
        total_difficulty: U256,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn validate_block(&self, block: &SealedBlock) -> Result<(), ConsensusError> {
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
}
