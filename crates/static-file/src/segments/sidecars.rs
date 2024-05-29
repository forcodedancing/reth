use crate::segments::{dataset_for_compression, prepare_jar, Segment};
use reth_db::{
    cursor::DbCursorRO, database::Database, static_file::create_static_file_T1, tables,
    transaction::DbTx,
};
use reth_interfaces::provider::{ProviderError, ProviderResult};
use reth_primitives::{
    static_file::{SegmentConfig, SegmentHeader},
    BlockNumber, StaticFileSegment, TxNumber,
};
use reth_provider::{
    providers::{StaticFileProvider, StaticFileWriter},
    BlockReader, DatabaseProviderRO, SidecarsProviderExt,
};
use std::{ops::RangeInclusive, path::Path};

/// Static File segment responsible for [StaticFileSegment::Sidecars] part of data.
#[derive(Debug, Default)]
pub struct Sidecars;

impl<DB: Database> Segment<DB> for Sidecars {
    fn segment(&self) -> StaticFileSegment {
        StaticFileSegment::Sidecars
    }

    /// Write Sidecars from database table [tables::Sidecars] to static files with segment
    /// [StaticFileSegment::Sidecars] for the provided block range.
    fn copy_to_static_files(
        &self,
        provider: DatabaseProviderRO<DB>,
        static_file_provider: StaticFileProvider,
        block_range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<()> {
        let mut static_file_writer =
            static_file_provider.get_writer(*block_range.start(), StaticFileSegment::Sidecars)?;

        for block in block_range {
            let _static_file_block =
                static_file_writer.increment_block(StaticFileSegment::Sidecars, block)?;
            debug_assert_eq!(_static_file_block, block);

            let block_body_indices = provider
                .block_body_indices(block)?
                .ok_or(ProviderError::BlockBodyIndicesNotFound(block))?;

            let mut sidecars_cursor = provider.tx_ref().cursor_read::<tables::Sidecars>()?;
            let sidecars_walker =
                sidecars_cursor.walk_range(block_body_indices.sidecar_num_range())?;

            for entry in sidecars_walker {
                let (sidecar_number, sidecar) = entry?;

                static_file_writer.append_sidecar(sidecar_number, sidecar)?;
            }
        }

        Ok(())
    }

    fn create_static_file_file(
        &self,
        provider: &DatabaseProviderRO<DB>,
        directory: &Path,
        config: SegmentConfig,
        block_range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<()> {
        let sidecar_range = provider.sidecar_range_by_block_range(block_range.clone())?;
        let sidecar_range_len = sidecar_range.clone().count();

        let jar = prepare_jar::<DB, 1>(
            provider,
            directory,
            StaticFileSegment::Sidecars,
            config,
            block_range,
            sidecar_range_len,
            || {
                Ok([dataset_for_compression::<DB, tables::Sidecars>(
                    provider,
                    &sidecar_range,
                    sidecar_range_len,
                )?])
            },
        )?;

        // Generate list of hashes for filters & PHF
        let hashes = if config.filters.has_filters() {
            Some(
                provider
                    .sidecar_transaction_hashes_by_range(
                        *sidecar_range.start()..(*sidecar_range.end() + 1),
                    )?
                    .into_iter()
                    .map(|(tx, _)| Ok(tx)),
            )
        } else {
            None
        };

        create_static_file_T1::<tables::Sidecars, TxNumber, SegmentHeader>(
            provider.tx_ref(),
            sidecar_range,
            None,
            // We already prepared the dictionary beforehand
            None::<Vec<std::vec::IntoIter<Vec<u8>>>>,
            hashes,
            sidecar_range_len,
            jar,
        )?;

        Ok(())
    }
}
