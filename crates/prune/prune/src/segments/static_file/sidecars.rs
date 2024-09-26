use crate::{
    db_ext::DbTxPruneExt,
    segments::{PruneInput, Segment},
    PrunerError,
};
use reth_db::{tables, transaction::DbTxMut};
use reth_provider::{providers::StaticFileProvider, BlockReader, DBProvider, TransactionsProvider};
use reth_prune_types::{
    PruneMode, PruneProgress, PrunePurpose, PruneSegment, SegmentOutput, SegmentOutputCheckpoint,
};
use reth_static_file_types::StaticFileSegment;
use tracing::trace;

#[derive(Debug)]
pub struct Sidecars {
    static_file_provider: StaticFileProvider,
}

impl Sidecars {
    pub const fn new(static_file_provider: StaticFileProvider) -> Self {
        Self { static_file_provider }
    }
}

impl<Provider> Segment<Provider> for Sidecars
where
    Provider: DBProvider<Tx: DbTxMut> + TransactionsProvider + BlockReader,
{
    fn segment(&self) -> PruneSegment {
        PruneSegment::Sidecars
    }

    fn mode(&self) -> Option<PruneMode> {
        self.static_file_provider
            .get_highest_static_file_block(StaticFileSegment::Sidecars)
            .map(PruneMode::before_inclusive)
    }

    fn purpose(&self) -> PrunePurpose {
        PrunePurpose::StaticFile
    }

    fn prune(&self, provider: &Provider, input: PruneInput) -> Result<SegmentOutput, PrunerError> {
        let (block_range_start, block_range_end) = match input.get_next_block_range() {
            Some(range) => (*range.start(), *range.end()),
            None => {
                trace!(target: "pruner", "No sidecars to prune");
                return Ok(SegmentOutput::done())
            }
        };
        let last_pruned_block =
            if block_range_start == 0 { None } else { Some(block_range_start - 1) };
        let range = last_pruned_block.map_or(0, |block| block + 1)..=block_range_end;

        let mut limiter = input.limiter;

        let mut last_pruned_block: Option<u64> = None;
        let (pruned, done) = provider.tx_ref().prune_table_with_range::<tables::Sidecars>(
            range,
            &mut limiter,
            |_| false,
            |row| last_pruned_block = Some(row.0),
        )?;
        trace!(target: "pruner", %pruned, %done, "Pruned sidecars");

        let done = last_pruned_block.map_or(false, |block| block == block_range_end);
        let progress = PruneProgress::new(done, &limiter);

        Ok(SegmentOutput {
            progress,
            pruned,
            checkpoint: Some(SegmentOutputCheckpoint {
                block_number: last_pruned_block,
                tx_number: None,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::segments::{PruneInput, Segment, SegmentOutput};
    use alloy_primitives::{BlockNumber, B256};
    use assert_matches::assert_matches;
    use reth_db::tables;
    use reth_provider::{PruneCheckpointReader, StaticFileProviderFactory};
    use reth_prune_types::{
        PruneCheckpoint, PruneInterruptReason, PruneLimiter, PruneMode, PruneProgress, PruneSegment,
    };
    use reth_stages::test_utils::{StorageKind, TestStageDB};
    use reth_testing_utils::{
        generators,
        generators::{random_block_range, BlockRangeParams},
    };
    use tracing::trace;

    #[test]
    fn prune() {
        reth_tracing::init_test_tracing();

        let db = TestStageDB::default();
        let mut rng = generators::rng();

        let blocks = random_block_range(
            &mut rng,
            0..=15,
            BlockRangeParams { parent: Some(B256::ZERO), tx_count: 0..1, ..Default::default() },
        );
        db.insert_blocks(blocks.iter(), StorageKind::Database(None)).expect("insert blocks");

        assert_eq!(db.table::<tables::Sidecars>().unwrap().len(), blocks.len());

        let test_prune = |to_block: BlockNumber, expected_result: (PruneProgress, usize)| {
            let segment = super::Sidecars::new(db.factory.static_file_provider());
            let prune_mode = PruneMode::Before(to_block);
            let mut limiter = PruneLimiter::default().set_deleted_entries_limit(10);
            let input = PruneInput {
                previous_checkpoint: db
                    .factory
                    .provider()
                    .unwrap()
                    .get_prune_checkpoint(PruneSegment::Sidecars)
                    .unwrap(),
                to_block,
                limiter: limiter.clone(),
            };

            let next_block_number_to_prune = db
                .factory
                .provider()
                .unwrap()
                .get_prune_checkpoint(PruneSegment::Sidecars)
                .unwrap()
                .and_then(|checkpoint| checkpoint.block_number)
                .map(|block_number| block_number + 1)
                .unwrap_or_default();

            let provider = db.factory.provider_rw().unwrap();
            let result = segment.prune(&provider, input.clone()).unwrap();
            limiter.increment_deleted_entries_count_by(result.pruned);
            trace!(target: "pruner::test",
                expected_prune_progress=?expected_result.0,
                expected_pruned=?expected_result.1,
                result=?result,
                "SegmentOutput"
            );

            assert_matches!(
                result,
                SegmentOutput {progress, pruned, checkpoint: Some(_)}
                    if (progress, pruned) == expected_result
            );
            segment
                .save_checkpoint(
                    &provider,
                    result.checkpoint.unwrap().as_prune_checkpoint(prune_mode),
                )
                .unwrap();
            provider.commit().expect("commit");

            let last_pruned_block_number = to_block.min(
                next_block_number_to_prune +
                    (input.limiter.deleted_entries_limit().unwrap() - 1) as u64,
            );

            assert_eq!(
                db.table::<tables::Sidecars>().unwrap().len(),
                blocks.len() - (last_pruned_block_number + 1) as usize
            );
            assert_eq!(
                db.factory
                    .provider()
                    .unwrap()
                    .get_prune_checkpoint(PruneSegment::Sidecars)
                    .unwrap(),
                Some(PruneCheckpoint {
                    block_number: Some(last_pruned_block_number),
                    tx_number: None,
                    prune_mode
                })
            );
        };

        test_prune(
            12,
            (PruneProgress::HasMoreData(PruneInterruptReason::DeletedEntriesLimitReached), 10),
        );
        test_prune(12, (PruneProgress::Finished, 3));
    }
}
