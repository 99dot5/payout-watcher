//! The two connection profiles a client is built with, as a type parameter so
//! that using one for the other's job does not compile.

use crate::NodeUrl;
use crate::endpoint::endpoint;
use crate::error::{Error, RawResponse, classify, decode};
use reqwest::{RequestBuilder, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// One-shot requests: no idle connection is ever reused, and every request
/// has a connect timeout and a whole-request timeout.
///
/// Why no reuse: octez answers some endpoints chunked and then closes the
/// connection. A pooling client puts that socket back in its pool, and the
/// NEXT request on it fails with `connection closed before message
/// completed`. One handshake per request costs nothing at the rates these
/// nodes are read.
#[derive(Debug, Clone, Copy)]
pub struct Request;

/// A long-lived answer read as it arrives (the L1 node's
/// `/monitor/heads/main`): TCP keep-alive and a connect timeout, but no
/// request timeout, which would cut the stream. The caller bounds the wait
/// for each item.
#[derive(Debug, Clone, Copy)]
pub struct Stream;

/// The settings of a [`Request`] client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestSettings {
    pub connect_timeout: Duration,
    /// From sending the request to reading the whole body.
    pub request_timeout: Duration,
}

impl Default for RequestSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// The settings of a [`Stream`] client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSettings {
    pub connect_timeout: Duration,
    pub tcp_keepalive: Duration,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            tcp_keepalive: Duration::from_secs(30),
        }
    }
}

/// The HTTP client could not be built (the TLS backend failed to initialise).
#[derive(Debug, Error)]
#[error("cannot build the HTTP client: {0}")]
pub struct BuildError(#[from] reqwest::Error);

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Request {}
    impl Sealed for super::Stream {}
}

/// A connection profile: [`Request`] or [`Stream`]. Sealed.
pub trait Profile: sealed::Sealed + Clone + Send + Sync + 'static {
    type Settings: Clone + Default;

    #[doc(hidden)]
    fn http_client(settings: &Self::Settings) -> Result<reqwest::Client, BuildError>;
}

impl Profile for Request {
    type Settings = RequestSettings;

    fn http_client(settings: &RequestSettings) -> Result<reqwest::Client, BuildError> {
        Ok(reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .build()?)
    }
}

impl Profile for Stream {
    type Settings = StreamSettings;

    fn http_client(settings: &StreamSettings) -> Result<reqwest::Client, BuildError> {
        Ok(reqwest::Client::builder()
            .tcp_keepalive(settings.tcp_keepalive)
            .connect_timeout(settings.connect_timeout)
            .build()?)
    }
}

/// A node's base URL and the HTTP client of profile `P`. Cloning is cheap and
/// shares the client.
#[derive(Debug, Clone)]
pub(crate) struct Transport<P> {
    http: reqwest::Client,
    base: NodeUrl,
    profile: PhantomData<fn() -> P>,
}

impl<P: Profile> Transport<P> {
    pub(crate) fn new(base: NodeUrl, settings: &P::Settings) -> Result<Self, BuildError> {
        Ok(Self {
            http: P::http_client(settings)?,
            base,
            profile: PhantomData,
        })
    }
}

impl<P> Transport<P> {
    pub(crate) fn base(&self) -> &NodeUrl {
        &self.base
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn url<S: AsRef<str>>(&self, segments: &[S], query: &[(&str, &str)]) -> Url {
        let mut url = endpoint(&self.base, segments);

        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }

        url
    }

    /// Send `request` to `url` and read the whole answer, whatever its status.
    pub(crate) async fn send(
        &self,
        url: &Url,
        request: RequestBuilder,
    ) -> Result<RawResponse, Error> {
        let unavailable = |source| Error::Unavailable {
            url: url.to_string(),
            source,
        };
        let response = request.send().await.map_err(unavailable)?;
        let status = response.status();
        let body = response.text().await.map_err(unavailable)?;

        Ok(RawResponse { status, body })
    }

    pub(crate) async fn get_raw<S: AsRef<str>>(
        &self,
        segments: &[S],
        query: &[(&str, &str)],
    ) -> Result<RawResponse, Error> {
        let url = self.url(segments, query);

        self.send(&url, self.http.get(url.clone())).await
    }

    /// The body of a success answer to a `GET`, as text.
    pub(crate) async fn get_text<S: AsRef<str>>(
        &self,
        segments: &[S],
        query: &[(&str, &str)],
    ) -> Result<String, Error> {
        let url = self.url(segments, query);
        let raw = self.send(&url, self.http.get(url.clone())).await?;

        classify(url.as_str(), raw)
    }

    pub(crate) async fn get_json<S: AsRef<str>, T: DeserializeOwned>(
        &self,
        segments: &[S],
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        let url = self.url(segments, query);
        let raw = self.send(&url, self.http.get(url.clone())).await?;

        decode(url.as_str(), &classify(url.as_str(), raw)?)
    }

    /// Like [`Self::get_json`], with a 404 as `None`.
    pub(crate) async fn get_json_or_not_found<S: AsRef<str>, T: DeserializeOwned>(
        &self,
        segments: &[S],
    ) -> Result<Option<T>, Error> {
        let url = self.url(segments, &[]);
        let raw = self.send(&url, self.http.get(url.clone())).await?;

        if raw.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        decode(url.as_str(), &classify(url.as_str(), raw)?).map(Some)
    }

    pub(crate) async fn post_json<S: AsRef<str>, B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        segments: &[S],
        query: &[(&str, &str)],
        body: &B,
    ) -> Result<T, Error> {
        let url = self.url(segments, query);
        let raw = self
            .send(&url, self.http.post(url.clone()).json(body))
            .await?;

        decode(url.as_str(), &classify(url.as_str(), raw)?)
    }
}
