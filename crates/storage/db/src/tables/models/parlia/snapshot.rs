use crate::{
    models::parlia::{VoteAddress, VoteAttestation, VoteData},
    table::{Compress, Decompress},
    DatabaseError,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::BufMut;
use reth_codecs::{derive_arbitrary, impl_compact_for_bytes, main_codec, Compact};
use reth_primitives::{
    alloy_primitives::wrap_fixed_bytes, Address, BlockNumber, Bytes, SealedHeader, B256,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    io,
    io::{Read, Write},
};

/// Number of blocks after which to save the snapshot to the database
pub const CHECKPOINT_INTERVAL: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorsMap(HashMap<Address, ValidatorInfo>);

impl ValidatorsMap {
    pub fn serialized_size(&self) -> usize {
        // 8 bytes for the number of elements
        // 20 bytes for the address
        // 8 bytes for the index
        // 48 bytes for the vote address
        8 + self.0.len() * (20 + 8 + 48)
    }

    pub fn serialize_into<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.0.len() as u64)?;

        for (addr, val_info) in &self.0 {
            for byte in addr.as_slice() {
                writer.write_u8(*byte)?;
            }
            writer.write_u64::<LittleEndian>(val_info.index)?;
            for byte in val_info.vote_addr.as_slice() {
                writer.write_u8(*byte)?;
            }
        }

        Ok(())
    }
}

impl Compress for ValidatorsMap {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        let mut vec = Vec::with_capacity(self.serialized_size());
        self.serialize_into(&mut vec).expect("not able to encode ValidatorsMap");
        vec
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        self.serialize_into(buf.writer()).unwrap();
    }
}

impl Decompress for ValidatorsMap {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        let mut reader = value.as_ref();
        // Read the number of elements
        let len = reader.read_u64::<LittleEndian>().map_err(|_| DatabaseError::Decode)? as usize;

        let mut map = HashMap::with_capacity(len);

        for _ in 0..len {
            let mut addr_bytes = [0u8; 20];
            reader.read_exact(&mut addr_bytes).map_err(|_| DatabaseError::Decode)?;
            let addr = Address::from(addr_bytes);

            let index = reader.read_u64::<LittleEndian>().map_err(|_| DatabaseError::Decode)?;

            let mut vote_addr_bytes = [0u8; 48];
            reader.read_exact(&mut vote_addr_bytes).map_err(|_| DatabaseError::Decode)?;
            let vote_addr = VoteAddress::from(vote_addr_bytes);

            map.insert(addr, ValidatorInfo { index, vote_addr });
        }

        Ok(ValidatorsMap(map))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentProposers(BTreeMap<BlockNumber, Address>);

impl RecentProposers {
    pub fn serialized_size(&self) -> usize {
        // 8 bytes for the number of elements
        // 8 bytes for the block number
        // 20 bytes for the address
        8 + self.0.len() * (8 + 20)
    }

    pub fn serialize_into<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.0.len() as u64)?;

        for (number, addr) in &self.0 {
            writer.write_u64::<LittleEndian>(*number)?;
            for byte in addr.as_slice() {
                writer.write_u8(*byte)?;
            }
        }

        Ok(())
    }
}

impl Compress for RecentProposers {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        let mut vec = Vec::with_capacity(self.serialized_size());
        self.serialize_into(&mut vec).expect("not able to encode RecentProposers");
        vec
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        self.serialize_into(buf.writer()).unwrap();
    }
}

impl Decompress for RecentProposers {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        let mut reader = value.as_ref();
        let len = reader.read_u64::<LittleEndian>().map_err(|_| DatabaseError::Decode)? as usize;

        let mut map = BTreeMap::new();

        for _ in 0..len {
            let block_number =
                reader.read_u64::<LittleEndian>().map_err(|_| DatabaseError::Decode)?;

            let mut addr_bytes = [0u8; 20];
            reader.read_exact(&mut addr_bytes).map_err(|_| DatabaseError::Decode)?;
            let address = Address::from(addr_bytes);

            map.insert(block_number, address);
        }

        Ok(RecentProposers(map))
    }
}

/// record validators information
#[main_codec]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ValidatorInfo {
    /// The index should offset by 1
    pub index: u64,
    pub vote_addr: VoteAddress,
}

/// Snapshot, record validators and proposal from epoch chg.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
    pub vote_data: VoteData,
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
            vote_data: Default::default(),
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
            snap.vote_data = attestation.data;
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

impl Compress for Snapshot {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        todo!()
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        todo!()
    }
}

impl Decompress for Snapshot {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        todo!()
    }
}
