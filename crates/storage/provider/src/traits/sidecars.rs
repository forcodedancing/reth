use reth_interfaces::provider::ProviderResult;
use reth_primitives::{BlockHashOrNumber, BlobSidecars};

///  Client trait for fetching [BlobSidecars] related data.
#[auto_impl::auto_impl(&, Arc)]
pub trait SidecarsProvider: Send + Sync {
    /// Get sidecars by block id.
    fn sidecars_by_block(
        &self,
        id: BlockHashOrNumber,
        timestamp: u64,
    ) -> ProviderResult<Option<BlobSidecars>>;
}
