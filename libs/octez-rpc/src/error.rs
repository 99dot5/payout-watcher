use reqwest::StatusCode;
use thiserror::Error;

/// How much of an error body an [`Error`] keeps.
const BODY_LIMIT: usize = 2000;

/// The error id suffix the L1 node answers with, in an HTTP 500, for a rollup
/// address it has no rollup at (measured: the `genesis_info` of an unknown
/// `sr1…` is `[{"kind": "temporary", "id":
/// "proto.<protocol>.smart_rollup_does_not_exist", "rollup": "sr1…"}]`).
const ROLLUP_NOT_FOUND_ID: &str = "smart_rollup_does_not_exist";

/// A request to a node that did not produce the answer asked for.
#[derive(Debug, Error)]
pub enum Error {
    /// No HTTP answer: refused, reset, timed out, or the empty reply a node
    /// gives for about a second while it starts.
    #[error("node at {url} unavailable: {source}")]
    Unavailable {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    /// A non-success status other than [`Error::RollupNotFound`]. A 5xx is the
    /// node failing (or not having the block yet), a 4xx a request it refuses,
    /// such as a block identifier it does not parse (400).
    #[error("node answered {code} to {url}: {body}")]
    Status {
        url: String,
        code: StatusCode,
        body: String,
    },
    /// The L1 node has no smart rollup at the address asked about.
    #[error("no such smart rollup ({url}): {body}")]
    RollupNotFound { url: String, body: String },
    /// A success status whose body is not the expected shape. The request was
    /// served: for a write (an injection) this means the node accepted it.
    #[error("answer from {url} did not decode: {reason}")]
    Decode { url: String, reason: String },
}

/// An HTTP answer the caller classifies itself: the status and the whole body
/// text, whatever the status. A transport failure is an
/// [`Error::Unavailable`], never one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: StatusCode,
    pub body: String,
}

/// The body of a success answer, or the error a non-success one stands for.
pub(crate) fn classify(url: &str, response: RawResponse) -> Result<String, Error> {
    let RawResponse { status, body } = response;

    if status.is_success() {
        return Ok(body);
    }

    Err(failure(url, status, body))
}

/// The error a non-success answer stands for.
pub(crate) fn failure(url: &str, status: StatusCode, body: String) -> Error {
    let body: String = body.chars().take(BODY_LIMIT).collect();

    if status == StatusCode::INTERNAL_SERVER_ERROR && body.contains(ROLLUP_NOT_FOUND_ID) {
        return Error::RollupNotFound {
            url: url.to_string(),
            body,
        };
    }

    Error::Status {
        url: url.to_string(),
        code: status,
        body,
    }
}

/// `body` decoded as JSON into `T`.
pub(crate) fn decode<T: serde::de::DeserializeOwned>(url: &str, body: &str) -> Result<T, Error> {
    serde_json::from_str(body).map_err(|e| Error::Decode {
        url: url.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(status: u16, body: &str) -> RawResponse {
        RawResponse {
            status: StatusCode::from_u16(status).expect("a status"),
            body: body.to_string(),
        }
    }

    #[test]
    fn a_success_is_its_body() {
        assert_eq!(classify("u", raw(200, "null")).expect("ok"), "null");
    }

    #[test]
    fn a_500_naming_the_missing_rollup_is_rollup_not_found() {
        let body =
            r#"[{"kind":"temporary","id":"proto.025-PsUshuai.smart_rollup_does_not_exist"}]"#;

        assert!(matches!(
            classify("u", raw(500, body)),
            Err(Error::RollupNotFound { .. })
        ));
    }

    #[test]
    fn any_other_failure_is_a_status() {
        for (status, body) in [
            (500, r#"[{"kind":"temporary","id":"failure"}]"#),
            (503, "smart_rollup_does_not_exist"),
            (400, "Cannot parse block identifier."),
            (404, ""),
        ] {
            match classify("u", raw(status, body)) {
                Err(Error::Status { code, .. }) => assert_eq!(code.as_u16(), status),
                other => panic!("{status}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_long_error_body_is_cut() {
        match classify("u", raw(500, &"x".repeat(BODY_LIMIT * 2))) {
            Err(Error::Status { body, .. }) => assert_eq!(body.len(), BODY_LIMIT),
            other => panic!("{other:?}"),
        }
    }
}
