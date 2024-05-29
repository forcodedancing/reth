use crate::{BlockNumReader, BlockReader};
use reth_interfaces::provider::{ProviderError, ProviderResult};
use reth_primitives::{BlobSidecar, BlockHashOrNumber, BlockNumber, TxHash, TxNumber};
use std::ops::{Range, RangeBounds, RangeInclusive};

///  Client trait for fetching [BlobSidecar] related data.
#[auto_impl::auto_impl(&, Arc)]
pub trait SidecarsProvider: BlockNumReader + Send + Sync {
    /// Get internal sidecar identifier by transaction hash.
    ///
    /// Returns None if the sidecar is not found.
    fn sidecar_id(&self, tx_hash: TxHash) -> ProviderResult<Option<TxNumber>>;

    /// Get sidecar by id
    fn sidecar_by_id(&self, id: TxNumber) -> ProviderResult<Option<BlobSidecar>>;

    /// Get sidecar by transaction hash.
    fn sidecar_by_hash(&self, hash: TxHash) -> ProviderResult<Option<BlobSidecar>>;

    /// Get sidecar block number
    fn sidecar_block(&self, id: TxNumber) -> ProviderResult<Option<BlockNumber>>;

    /// Get sidecars by block id.
    fn sidecars_by_block(&self, block: BlockHashOrNumber) -> ProviderResult<Option<Vec<BlobSidecar>>>;

    /// Get sidecars by block range.
    fn sidecars_by_block_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<BlobSidecar>>>;

    /// Get sidecars by sidecar range.
    fn sidecars_by_sidecar_range(
        &self,
        range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<BlobSidecar>>;
}

/// Client trait for fetching additional [BlobSidecar] related data.
#[auto_impl::auto_impl(&, Arc)]
pub trait SidecarsProviderExt: BlockReader + Send + Sync {
    /// Get transactions range by block range.
    fn sidecar_range_by_block_range(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<RangeInclusive<TxNumber>> {
        let from = self
            .block_body_indices(*block_range.start())?
            .ok_or(ProviderError::BlockBodyIndicesNotFound(*block_range.start()))?
            .first_sidecar_num();

        let to = self
            .block_body_indices(*block_range.end())?
            .ok_or(ProviderError::BlockBodyIndicesNotFound(*block_range.end()))?
            .last_sidecar_num();

        Ok(from..=to)
    }

    /// Get transaction hashes from a transaction range.
    fn sidecar_transaction_hashes_by_range(
        &self,
        tx_range: Range<TxNumber>,
    ) -> ProviderResult<Vec<(TxHash, TxNumber)>>;
}
