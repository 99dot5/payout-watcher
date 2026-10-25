//! The rollup node's batcher, the write side: the node posts what it is given
//! to the rollup's L1 inbox on its own schedule.

use super::Client;
use crate::error::Error;

impl<P> Client<P> {
    /// `POST /local/batcher/injection` of `messages` (each sent as hex); the
    /// answer is one batcher message id per message, in order, which
    /// [`Client::batcher_queue`] takes.
    ///
    /// A non-success status means nothing was queued. An [`Error::Decode`]
    /// means the node accepted the batch but its answer did not read as a
    /// list of ids: the messages are queued and only their ids are unknown.
    pub async fn batcher_injection(&self, messages: &[Vec<u8>]) -> Result<Vec<String>, Error> {
        let batch: Vec<String> = messages.iter().map(hex::encode).collect();

        self.transport
            .post_json(&["local", "batcher", "injection"], &[], &batch)
            .await
    }
}
