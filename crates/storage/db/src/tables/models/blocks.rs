//! Block related models and types.

use crate::table::{Compress, Decompress};
use bytes::BufMut;
use reth_codecs::{main_codec, Compact};
use reth_interfaces::db::DatabaseError;
use reth_primitives::{BlobSidecar, BlobSidecars, Header, TxNumber, Withdrawals, B256};
use std::ops::Range;
use crate::models::parlia::Snapshot;

/// Total number of transactions.
pub type NumTransactions = u64;

/// The storage of the block body indices.
///
/// It has the pointer to the transaction Number of the first
/// transaction in the block and the total number of transactions.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[main_codec]
pub struct StoredBlockBodyIndices {
    /// The number of the first transaction in this block
    ///
    /// Note: If the block is empty, this is the number of the first transaction
    /// in the next non-empty block.
    pub first_tx_num: TxNumber,
    /// The total number of transactions in the block
    ///
    /// NOTE: Number of transitions is equal to number of transactions with
    /// additional transition for block change if block has block reward or withdrawal.
    pub tx_count: NumTransactions,
}

impl StoredBlockBodyIndices {
    /// Return the range of transaction ids for this block.
    pub fn tx_num_range(&self) -> Range<TxNumber> {
        self.first_tx_num..self.first_tx_num + self.tx_count
    }

    /// Return the index of last transaction in this block unless the block
    /// is empty in which case it refers to the last transaction in a previous
    /// non-empty block
    pub fn last_tx_num(&self) -> TxNumber {
        self.first_tx_num.saturating_add(self.tx_count).saturating_sub(1)
    }

    /// First transaction index.
    ///
    /// Caution: If the block is empty, this is the number of the first transaction
    /// in the next non-empty block.
    pub fn first_tx_num(&self) -> TxNumber {
        self.first_tx_num
    }

    /// Return the index of the next transaction after this block.
    pub fn next_tx_num(&self) -> TxNumber {
        self.first_tx_num + self.tx_count
    }

    /// Return a flag whether the block is empty
    pub fn is_empty(&self) -> bool {
        self.tx_count == 0
    }

    /// Return number of transaction inside block
    ///
    /// NOTE: This is not the same as the number of transitions.
    pub fn tx_count(&self) -> NumTransactions {
        self.tx_count
    }
}

/// The storage representation of a block's ommers.
///
/// It is stored as the headers of the block's uncles.
#[main_codec]
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct StoredBlockOmmers {
    /// The block headers of this block's uncles.
    pub ommers: Vec<Header>,
}

/// The storage representation of block withdrawals.
#[main_codec]
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct StoredBlockWithdrawals {
    /// The block withdrawals.
    pub withdrawals: Withdrawals,
}

/// The storage representation of block sidecars.
#[main_codec]
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct StoredBlockSidecars {
    /// The block sidecars.
    pub sidecars: BlobSidecars,
}

impl Compress for StoredBlockSidecars {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        serde_cbor::to_vec(&self).expect("Failed to serialize StoredBlockSidecars")
    }

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        let compressed = self.compress();
        buf.put_slice(&compressed);
    }
}

impl Decompress for StoredBlockSidecars {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        serde_cbor::from_slice(value.as_ref()).map_err(|_| DatabaseError::Decode)
    }
}

/// Hash of the block header. Value for [`CanonicalHeaders`][crate::tables::CanonicalHeaders]
pub type HeaderHash = B256;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{Compress, Decompress};

    #[test]
    fn test_ommer() {
        let mut ommer = StoredBlockOmmers::default();
        ommer.ommers.push(Header::default());
        ommer.ommers.push(Header::default());
        assert_eq!(
            ommer.clone(),
            StoredBlockOmmers::decompress::<Vec<_>>(ommer.compress()).unwrap()
        );
    }

    #[test]
    fn block_indices() {
        let first_tx_num = 10;
        let tx_count = 6;
        let block_indices = StoredBlockBodyIndices { first_tx_num, tx_count };

        assert_eq!(block_indices.first_tx_num(), first_tx_num);
        assert_eq!(block_indices.last_tx_num(), first_tx_num + tx_count - 1);
        assert_eq!(block_indices.next_tx_num(), first_tx_num + tx_count);
        assert_eq!(block_indices.tx_count(), tx_count);
        assert_eq!(block_indices.tx_num_range(), first_tx_num..first_tx_num + tx_count);
    }
}
