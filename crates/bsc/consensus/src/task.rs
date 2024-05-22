use crate::{Storage, Parlia};
use futures_util::{future::BoxFuture, FutureExt};
use reth_beacon_consensus::{BeaconEngineMessage, ForkchoiceStatus};
use reth_engine_primitives::EngineTypes;
use reth_primitives::{Block, BlockBody, ChainSpec, IntoRecoveredTransaction, SealedBlockWithSenders, Withdrawals};
use reth_provider::{BlockReader, CanonChainTracker, CanonStateNotificationSender, Chain, StateProviderFactory};
use reth_rpc_types::engine::ForkchoiceState;
use reth_network::message::PeerMessage;
use reth_consensus::{Consensus, ConsensusError};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{mpsc::{UnboundedSender,UnboundedReceiver}, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, warn};

/// A Future that listens for new headers and puts new blocks into storage
pub struct ParliaEngineTask<Client, Engine: EngineTypes, ConsensusEngine: Consensus> {
    chain_spec: Arc<ChainSpec>,
    /// The configured chain spec
    consensus: ConsensusEngine,
    /// The client used to interact with the state
    client: Client,
    /// Shared storage to insert new blocks
    storage: Storage,
    to_engine: UnboundedSender<BeaconEngineMessage<Engine>>,
    network_block_event_tx: UnboundedReceiver<PeerMessage>,
    /// Used to notify consumers of new blocks
    canon_state_notification: CanonStateNotificationSender,
}

// === impl MiningTask ===

impl<Client, Engine: EngineTypes, ConsensusEngine: Consensus>
ParliaEngineTask<Client, Engine, ConsensusEngine>
{
    /// Creates a new instance of the task
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        chain_spec: Arc<ChainSpec>,
        consensus: ConsensusEngine,
        to_engine: UnboundedSender<BeaconEngineMessage<Engine>>,
        network_block_event_tx: UnboundedReceiver<PeerMessage>,
        canon_state_notification: CanonStateNotificationSender,
        storage: Storage,
        client: Client,
    ) -> Self {
        Self {
            chain_spec,
            consensus,
            to_engine,
            network_block_event_tx,
            canon_state_notification,
            storage,
            client,
        }
    }
}

impl<Client, Engine, ConsensusEngine> Future for ParliaEngineTask<Client, Engine, ConsensusEngine>
    where
        Client: StateProviderFactory + CanonChainTracker + Clone + Unpin + 'static,
        Engine: EngineTypes + 'static,
        ConsensusEngine: Consensus,
{
    type Output = ();

    async fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            if let Poll::Ready(Some(msg)) = this.network_block_event_tx.poll_recv(cx) {
                match msg {
                    PeerMessage::NewBlock(block_msg) => {
                        // verify header
                        let block_reader = block_msg.block.clone();
                        let header = block_reader.block.header;

                        // skip if header less than best number
                        let latest_header = self.client
                            .latest_header()
                            .ok()
                            .flatten()
                            .unwrap_or_else(|| self.chain_spec.sealed_genesis_header());

                        if header.number.lt(latest_header.number) {
                            continue
                        }

                        let sealed_header = header.seal(header.parent_hash.clone());
                        match self.consensus.validate_header(&sealed_header).unwrap() {
                            Ok(_) => {}
                            Err(err) => {
                                error!(target: "consensus::parlia", %err, "Parlia verify header failed");
                            },
                        }

                        // Cached the block
                        let mut storage = self.storage.clone().write().await;
                        storage.insert_new_block(block_reader.block.header, BlockBody::from(block_reader.block));

                        // Notify beacon engine
                        let to_engine = this.to_engine.clone();
                        let state = ForkchoiceState {
                            head_block_hash: block_msg.hash,
                            finalized_block_hash: block_msg.hash,
                            safe_block_hash: block_msg.hash,
                        };

                        loop {
                            // send the new update to the engine, this will trigger the engine
                            // to download and execute the block we just inserted
                            let (tx, rx) = oneshot::channel();
                            let _ = to_engine.send(BeaconEngineMessage::ForkchoiceUpdated {
                                state,
                                payload_attrs: None,
                                tx,
                            });
                            debug!(target: "consensus::parlia", ?state, "Sent fork choice update");

                            match rx.await.unwrap() {
                                Ok(fcu_response) => {
                                    match fcu_response.forkchoice_status() {
                                        ForkchoiceStatus::Valid => break,
                                        ForkchoiceStatus::Invalid => {
                                            error!(target: "consensus::parlia", ?fcu_response, "Forkchoice update returned invalid response");
                                            break
                                        }
                                        ForkchoiceStatus::Syncing => {
                                            debug!(target: "consensus::parlia", ?fcu_response, "Forkchoice update returned SYNCING, waiting for VALID");
                                            // wait for the next fork choice update
                                            continue
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!(target: "consensus::parlia", %err, "Parlia fork choice update failed");
                                    break
                                }
                            }
                        }
                    }
                    None => ()
                }
            }

        }

        Poll::Pending
    }
}

