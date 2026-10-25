use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// A node base URL: `http` or `https`, a host, no query, no fragment; a path
/// prefix is kept, a trailing slash on a non-root path is dropped so equal
/// nodes compare equal.
///
/// Requests are built by appending path segments to it, so a query or a
/// fragment on the base would either be dropped or end up on every request.
/// Only the validating constructors build one, so a configuration that loads
/// holds a URL every client accepts, and a bad URL fails at load, never at the
/// first request. There is no `Deref` to [`Url`] on purpose: `Url::join`
/// resolves a relative reference and drops the base's last path segment.
///
/// It deserialises from a string, validated:
///
/// ```
/// use octez_rpc::NodeUrl;
///
/// #[derive(serde::Deserialize)]
/// struct Settings {
///     l1_node_url: NodeUrl,
///     #[serde(default)]
///     rollup_node_url: Option<NodeUrl>,
/// }
///
/// let settings: Settings =
///     serde_json::from_str(r#"{"l1_node_url": "http://localhost:8732"}"#).unwrap();
///
/// assert_eq!(settings.l1_node_url.as_str(), "http://localhost:8732/");
/// assert!(settings.rollup_node_url.is_none());
///
/// assert!(serde_json::from_str::<Settings>(r#"{"l1_node_url": "ftp://h"}"#).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeUrl(Url);

/// A URL [`NodeUrl`] refuses. Each message names the URL.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidNodeUrl {
    #[error("{raw:?} is not a URL: {source}")]
    NotAUrl {
        raw: String,
        source: url::ParseError,
    },
    #[error("{url} has scheme {found:?}, expected \"http\" or \"https\"")]
    Scheme { url: String, found: String },
    #[error("{url} has no host")]
    NoHost { url: String },
    #[error("{url} carries a query, which a request base cannot take")]
    Query { url: String },
    #[error("{url} carries a fragment, which a request base cannot take")]
    Fragment { url: String },
}

impl NodeUrl {
    /// Parse `raw` and validate it (see [`NodeUrl`]).
    pub fn parse(raw: &str) -> Result<Self, InvalidNodeUrl> {
        let url = Url::parse(raw).map_err(|source| InvalidNodeUrl::NotAUrl {
            raw: raw.to_string(),
            source,
        })?;

        Self::try_from(url)
    }

    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<Url> for NodeUrl {
    type Error = InvalidNodeUrl;

    fn try_from(mut url: Url) -> Result<Self, InvalidNodeUrl> {
        if url.host_str().is_none_or(str::is_empty) {
            return Err(InvalidNodeUrl::NoHost {
                url: url.to_string(),
            });
        }

        if !matches!(url.scheme(), "http" | "https") {
            return Err(InvalidNodeUrl::Scheme {
                url: url.to_string(),
                found: url.scheme().to_string(),
            });
        }

        if url.query().is_some() {
            return Err(InvalidNodeUrl::Query {
                url: url.to_string(),
            });
        }

        if url.fragment().is_some() {
            return Err(InvalidNodeUrl::Fragment {
                url: url.to_string(),
            });
        }

        if url.path() != "/"
            && let Some(path) = url.path().strip_suffix('/')
        {
            let path = path.to_string();

            url.set_path(&path);
        }

        Ok(Self(url))
    }
}

impl TryFrom<String> for NodeUrl {
    type Error = InvalidNodeUrl;

    fn try_from(raw: String) -> Result<Self, InvalidNodeUrl> {
        Self::parse(&raw)
    }
}

impl FromStr for NodeUrl {
    type Err = InvalidNodeUrl;

    fn from_str(raw: &str) -> Result<Self, InvalidNodeUrl> {
        Self::parse(raw)
    }
}

impl From<NodeUrl> for String {
    fn from(url: NodeUrl) -> Self {
        url.0.into()
    }
}

impl fmt::Display for NodeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn refused(raw: &str) -> InvalidNodeUrl {
        NodeUrl::parse(raw).expect_err(raw)
    }

    fn hash(url: &NodeUrl) -> u64 {
        let mut hasher = DefaultHasher::new();

        url.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn accepts_http_and_https_with_or_without_a_path() {
        for raw in [
            "http://h:8732",
            "https://h/",
            "https://h/rpc",
            "http://127.0.0.1:8932",
        ] {
            assert!(NodeUrl::parse(raw).is_ok(), "{raw}");
        }
    }

    #[test]
    fn refuses_another_scheme() {
        assert_eq!(
            refused("ftp://h"),
            InvalidNodeUrl::Scheme {
                url: "ftp://h/".to_string(),
                found: "ftp".to_string(),
            }
        );
    }

    #[test]
    fn refuses_a_query() {
        assert_eq!(
            refused("http://h:8732?x=1"),
            InvalidNodeUrl::Query {
                url: "http://h:8732/?x=1".to_string(),
            }
        );
    }

    #[test]
    fn refuses_a_fragment() {
        assert_eq!(
            refused("http://h:8732/#f"),
            InvalidNodeUrl::Fragment {
                url: "http://h:8732/#f".to_string(),
            }
        );
    }

    #[test]
    fn refuses_a_url_without_a_host() {
        assert_eq!(
            refused("file:///tmp/node"),
            InvalidNodeUrl::NoHost {
                url: "file:///tmp/node".to_string(),
            }
        );
    }

    #[test]
    fn refuses_what_is_not_a_url() {
        // An `http` URL cannot even parse without a host.
        for raw in ["http://", ""] {
            assert!(
                matches!(refused(raw), InvalidNodeUrl::NotAUrl { raw: ref r, .. } if r == raw),
                "{raw}"
            );
        }
    }

    #[test]
    fn every_refusal_names_the_url_and_no_field() {
        for (raw, shown) in [
            ("ftp://h", "ftp://h/"),
            ("http://h:8732?x=1", "http://h:8732/?x=1"),
            ("http://h:8732/#f", "http://h:8732/#f"),
            ("file:///tmp/node", "file:///tmp/node"),
            ("http://", "\"http://\""),
            ("", "\"\""),
        ] {
            let message = refused(raw).to_string();

            assert!(message.contains(shown), "{message}");

            for label in [
                "node URL",
                "l1_node_url",
                "rollup_node_url",
                "--l1-node-url",
                "--rollup-node-url",
            ] {
                assert!(!message.contains(label), "{message}");
            }
        }
    }

    #[test]
    fn a_trailing_slash_does_not_make_another_node() {
        let with = NodeUrl::parse("http://h/rpc/").expect("valid");
        let without = NodeUrl::parse("http://h/rpc").expect("valid");

        assert_eq!(with, without);
        assert_eq!(hash(&with), hash(&without));
        assert_eq!(with.as_str(), "http://h/rpc");

        assert_eq!(
            NodeUrl::parse("http://h").expect("valid"),
            NodeUrl::parse("http://h/").expect("valid")
        );
    }

    #[test]
    fn deserialises_validated_and_round_trips() {
        #[derive(Debug, PartialEq, Deserialize, Serialize)]
        struct Settings {
            required: NodeUrl,
            #[serde(default)]
            optional: Option<NodeUrl>,
        }

        let settings: Settings =
            serde_json::from_str(r#"{"required": "http://h:8732"}"#).expect("valid");

        assert_eq!(settings.required.as_str(), "http://h:8732/");
        assert!(settings.optional.is_none());

        let error = serde_json::from_str::<Settings>(r#"{"required": ""}"#)
            .expect_err("an empty URL is refused");

        assert!(error.to_string().contains("is not a URL"), "{error}");

        let error =
            serde_json::from_str::<Settings>(r#"{"required": "http://h", "optional": "ftp://h"}"#)
                .expect_err("the optional field is validated too");

        assert!(error.to_string().contains("scheme"), "{error}");

        let both = Settings {
            required: NodeUrl::parse("http://h:8732/rpc/").expect("valid"),
            optional: Some(NodeUrl::parse("https://r").expect("valid")),
        };
        let json = serde_json::to_string(&both).expect("serialises");

        assert_eq!(
            serde_json::from_str::<Settings>(&json).expect("round-trips"),
            both
        );
    }
}
