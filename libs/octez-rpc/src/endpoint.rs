use crate::NodeUrl;
use url::Url;

/// `base` with `segments` appended to its path, each one percent-encoded as a
/// single segment (`/`, `?`, `#` and `%` are escaped; `~` and `+`, which block
/// identifiers use, pass through).
///
/// A trailing slash on `base` is dropped first, so a root base (`http://h/`)
/// gives `http://h/chains`, not `http://h//chains`. Relative-reference
/// resolution (the `Url` method that takes a reference string) is not used on
/// purpose: it drops the base's last path segment when the base has no
/// trailing slash (`chains` against `http://h/rpc` resolves to
/// `http://h/chains`).
pub(crate) fn endpoint<S: AsRef<str>>(base: &NodeUrl, segments: &[S]) -> Url {
    let mut url = base.as_url().clone();

    // An `http(s)` URL with a host always carries a path; the branch only
    // keeps this total.
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty().extend(segments);
    }

    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> NodeUrl {
        NodeUrl::parse(raw).expect("a test URL")
    }

    #[test]
    fn keeps_the_base_path_prefix() {
        assert_eq!(
            endpoint(&url("http://h:8732/rpc"), &["chains", "main"]).as_str(),
            "http://h:8732/rpc/chains/main"
        );
    }

    #[test]
    fn tolerates_a_trailing_slash_on_the_base() {
        assert_eq!(
            endpoint(&url("http://h:8732/rpc/"), &["chains", "main"]).as_str(),
            "http://h:8732/rpc/chains/main"
        );
        assert_eq!(
            endpoint(&url("http://h:8732/"), &["chains", "main"]).as_str(),
            "http://h:8732/chains/main"
        );
        assert_eq!(
            endpoint(&url("http://h:8732"), &["chains", "main"]).as_str(),
            "http://h:8732/chains/main"
        );
    }

    #[test]
    fn encodes_a_separator_inside_a_segment_and_passes_block_steps_through() {
        assert_eq!(
            endpoint(
                &url("http://h:8732"),
                &["a/b", "c?d", "head~1", "genesis+1"]
            )
            .as_str(),
            "http://h:8732/a%2Fb/c%3Fd/head~1/genesis+1"
        );
    }

    #[test]
    fn no_segments_is_the_base_without_its_trailing_slash() {
        assert_eq!(
            endpoint::<&str>(&url("http://h:8732/rpc/"), &[]).as_str(),
            "http://h:8732/rpc"
        );
    }
}
