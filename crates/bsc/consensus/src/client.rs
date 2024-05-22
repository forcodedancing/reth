//! This includes download client implementations for auto sealing miners.
use crate::{Storage};
use std::collections::HashMap;
use reth_interfaces::p2p::{
    bodies::client::{BodiesClient, BodiesFut},
    download::DownloadClient,
    headers::client::{HeadersClient, HeadersFut, HeadersRequest},
    priority::Priority,
};
use reth_beacon_consensus::{BeaconEngineMessage, ForkchoiceStatus};
use reth_engine_primitives::EngineTypes;
use reth_network_types::{PeerId, WithPeerId};
use reth_primitives::{BlockBody, BlockHashOrNumber, Header, HeadersDirection, B256, ChainSpec, SealedHeader, BlockNumber, BlockHash, U256};
use reth_provider::BlockReaderIdExt;
use tokio::sync::{mpsc::{UnboundedSender,UnboundedReceiver}, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{trace, warn};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use futures_util::TryFutureExt;
use reth_network::FetchClient;

#[derive(Debug, Clone)]
pub enum InnerFetchError {
    HeaderNotFound,
    BodyNotFound,
}

type InnerFetchHeaderResult = Result<Vec<Header>, InnerFetchError>;
type InnerFetchBodyResult = Result<Vec<BlockBody>, InnerFetchError>;

/// A download client that polls the miner for transactions and assembles blocks to be returned in
/// the download process.
///
/// When polled, the miner will assemble blocks when miners produce ready transactions and store the
/// blocks in memory.
#[derive(Debug, Clone)]
pub struct ParliaClient {
    /// cached header and body
    storage: Storage,
    fetch_client: FetchClient,
}

impl ParliaClient 
{
    pub(crate) fn new(storage: Storage, fetch_client: FetchClient) -> Self {
        Self { storage, fetch_client }
    }

    async fn fetch_headers(&self, request: HeadersRequest) -> InnerFetchHeaderResult {
        trace!(target: "consensus::parlia", ?request, "received headers request");


        let storage = self.storage.read().await;
        let HeadersRequest { start, limit, direction } = request;
        let mut headers = Vec::new();

        let mut block: BlockHashOrNumber = match start {
            BlockHashOrNumber::Hash(start) => start.into(),
            BlockHashOrNumber::Number(num) => {
                if let Some(hash) = storage.block_hash(num) {
                    hash.into()
                } else {
                    warn!(target: "consensus::parlia", num, "no matching block found");
                    return Err(InnerFetchError::HeaderNotFound);
                }
            }
        };

        for _ in 0..limit {
            // fetch from storage
            if let Some(header) = storage.header_by_hash_or_number(block) {
                match direction {
                    HeadersDirection::Falling => block = header.parent_hash.into(),
                    HeadersDirection::Rising => {
                        let next = header.number + 1;
                        block = next.into()
                    }
                }
                headers.push(header);
            } else {
                break
            }
        }

        trace!(target: "consensus::parlia", ?headers, "returning headers");

       Ok(headers)
    }

    async fn fetch_bodies(&self, hashes: Vec<B256>) -> InnerFetchBodyResult {
        trace!(target: "consensus::parlia", ?hashes, "received bodies request");
        let storage = self.storage.read().await;
        let mut bodies = Vec::new();
        for hash in hashes {
            if let Some(body) = storage.bodies.get(&hash).cloned() {
                bodies.push(body);
            } else {
                return Err(InnerFetchError::BodyNotFound)
            }
        }

        trace!(target: "consensus::parlia", ?bodies, "returning bodies");

        Ok(bodies)
    }
}

impl HeadersClient for ParliaClient {
    type Output = HeadersFut;

    fn get_headers_with_priority(
        &self,
        request: HeadersRequest,
        priority: Priority,
    ) -> Self::Output {
        let this = self.clone();
        Box::pin(async move {
            match this.fetch_headers(request.clone()).await {
                Ok(headers) => {
                    Ok(WithPeerId::new(PeerId::random(), headers))
                },
                Err(e) => {
                    warn!(target: "consensus::parlia", "internal fetch header failed");
                    self.fetch_client.get_headers_with_priority(request.clone(),priority).try_into()?
                }
            }
        })
    }
}

impl BodiesClient for ParliaClient {
    type Output = BodiesFut;

    fn get_block_bodies_with_priority(
        &self,
        hashes: Vec<B256>,
        priority: Priority,
    ) -> Self::Output {
        let this = self.clone();
        Box::pin(async move {
            match this.fetch_bodies(hashes.clone()).await {
                Ok(bodies) => {
                    Ok(WithPeerId::new(PeerId::random(), bodies))
                },
                Err(e) => {
                    warn!(target: "consensus::parlia", "internal fetch bodies failed");
                    self.fetch_client.get_block_bodies_with_priority(hashes.clone(), priority).try_into()?
                }
            }
        })
    }
}

impl DownloadClient for ParliaClient {
    fn report_bad_message(&self, peer_id: PeerId) {
        let this = self.clone();
        self.report_bad_message(peer_id)
    }

    fn num_connected_peers(&self) -> usize {
        let this = self.clone();
        self.num_connected_peers()
    }
}
