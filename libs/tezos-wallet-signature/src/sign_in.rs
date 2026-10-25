//! The wallet sign-in message (ADR 0029 amendment 2026-10-10): the CAIP-122
//! Tezos profile of "Sign-In with X", wrapped as a Micheline string. One
//! builder, pinned by `testdata/sign-in-vectors.json`.
//!
//! ```text
//! text  = "Tezos Signed Message: " + LINE_SEPARATOR + lines.join(LINE_SEPARATOR)
//! lines = "<domain> wants you to sign in with your Tezos account:"
//!         "<address>"
//!         ""
//!         "<statement>"
//!         ""
//!         "Uri: <uri>"
//!         "Version: 1"
//!         "Chain ID: <NetX…>"
//!         "Nonce: <nonce>"
//!         "Issued At: <RFC 3339, seconds, Z>"
//!         "Expiration Time: <RFC 3339, seconds, Z>"
//! bytes = 0x05 ‖ 0x01 ‖ u32_be(len(text)) ‖ text
//! ```
//!
//! The prefix stands on its own line and the URI label is `Uri:`, matching the
//! deployed Sign-In-with-Tezos reference (the StakeNow SIWT SDK, which
//! prepends the prefix and joins every line with `\n`) and the TZIP-33 draft's
//! labels; the draft's `0x80` off-chain-message envelope is not used, since no
//! wallet recognises it. Kukai renders the line breaks; Temple shows them as
//! spaces (display only — the signed bytes are the same).
//!
//! The wallet signs `blake2b-256(bytes)` (Taquito `SigningType.MICHELINE`).
//! The CAIP-122 profile leaves the encoding open; the Micheline wrap is ours,
//! and its `0x05` watermark keeps the signature from ever being a valid
//! operation or block signature. The server rebuilds `bytes` from its own
//! values and the request's fields; it never parses wallet text.

/// The packed-data watermark: never an operation (`0x03`) or block watermark.
pub const PACKED_DATA_WATERMARK: u8 = 0x05;
/// The Micheline string node tag.
pub const MICHELINE_STRING_TAG: u8 = 0x01;
/// What every Tezos wallet-signed text opens with.
pub const MESSAGE_PREFIX: &str = "Tezos Signed Message: ";
/// The one place the lines (the prefix included) are joined: a raw `\n`,
/// measured to sign in Kukai and Temple. Changing it means regenerating the
/// vectors and nothing else.
pub const LINE_SEPARATOR: &str = "\n";
/// The statement of the gaming-history scope. Never contains a line break.
pub const HISTORY_STATEMENT: &str = "View your game history.";
/// The statement of the wallet-registration scope (ADR 0027 §4.4): what a
/// wallet acknowledges by registering, which is also the disclosure ADR 0027
/// §4.5 asks for before the first deposit. Never contains a line break. The
/// wording is a placeholder until the compliance adviser confirms it (ADR
/// 0027 §6).
pub const REGISTER_STATEMENT: &str = "Register this wallet to play. Refunds are paid only to the wallet you deposit from; deposits from exchanges or other custodial wallets are not supported.";
/// The CAIP-122 message version.
pub const VERSION: &str = "1";

/// The fields a sign-in message binds. Every value has a grammar without line
/// breaks, enforced by the caller before the message is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInFields<'a> {
    /// The RFC 3986 authority (`host[:port]`) of the page asking to sign in.
    pub domain: &'a str,
    pub address: &'a str,
    pub statement: &'a str,
    /// The page's URI; its origin is the domain's.
    pub uri: &'a str,
    /// The tenant's chain id (`NetX…`), taken from server config.
    pub chain_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds, rendered as RFC 3339.
    pub issued_at: u64,
    /// Unix seconds, rendered as RFC 3339.
    pub expiration_time: u64,
}

/// The human-readable text the wallet displays.
pub fn message_text(fields: &SignInFields<'_>) -> String {
    let lines = [
        format!(
            "{} wants you to sign in with your Tezos account:",
            fields.domain
        ),
        fields.address.to_owned(),
        String::new(),
        fields.statement.to_owned(),
        String::new(),
        format!("Uri: {}", fields.uri),
        format!("Version: {VERSION}"),
        format!("Chain ID: {}", fields.chain_id),
        format!("Nonce: {}", fields.nonce),
        format!("Issued At: {}", format_timestamp(fields.issued_at)),
        format!(
            "Expiration Time: {}",
            format_timestamp(fields.expiration_time)
        ),
    ];

    format!(
        "{MESSAGE_PREFIX}{LINE_SEPARATOR}{}",
        lines.join(LINE_SEPARATOR)
    )
}

/// The Micheline-wrapped bytes whose `blake2b-256` the wallet signs.
pub fn message_bytes(fields: &SignInFields<'_>) -> Vec<u8> {
    let text = message_text(fields);
    // The text is bounded by the field grammars (well under 2 KiB), so the
    // length always fits a u32.
    let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
    let mut bytes = Vec::with_capacity(6 + text.len());

    bytes.push(PACKED_DATA_WATERMARK);
    bytes.push(MICHELINE_STRING_TAG);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339, UTC, whole seconds).
/// Years past 9999 are not representable in this shape and are clamped.
pub fn format_timestamp(unix_seconds: u64) -> String {
    let unix_seconds = unix_seconds.min(MAX_TIMESTAMP);
    let days = unix_seconds / 86_400;
    let rem = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The inverse of [`format_timestamp`], and nothing else: exactly
/// `YYYY-MM-DDTHH:MM:SSZ`, a real calendar date, no offset, no fraction, no
/// lowercase `t`/`z`. Anything that would not format back to itself is `None`,
/// so a parsed value always rebuilds the text it came from.
pub fn parse_timestamp(text: &str) -> Option<u64> {
    let b = text.as_bytes();

    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }

    let number = |range: core::ops::Range<usize>| -> Option<u64> {
        b[range].iter().try_fold(0u64, |acc, &digit| {
            digit
                .is_ascii_digit()
                .then(|| acc * 10 + u64::from(digit - b'0'))
        })
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);

    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let unix_seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;

    // Refuses 31 April, 29 February of a common year, and so on.
    (format_timestamp(unix_seconds) == text).then_some(unix_seconds)
}

/// 9999-12-31T23:59:59Z.
const MAX_TIMESTAMP: u64 = 253_402_300_799;

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`, restricted to non-negative days).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);

    (year, month, day)
}

/// (year ≥ 1970, month, day) → days since 1970-01-01 (`days_from_civil`).
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let yoe = year % 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_at_the_edges() {
        for (unix, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_790_000_000, "2026-09-21T14:13:20Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
            (MAX_TIMESTAMP, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(format_timestamp(unix), text);
            assert_eq!(parse_timestamp(text), Some(unix), "{text}");
        }
        assert_eq!(format_timestamp(u64::MAX), "9999-12-31T23:59:59Z");
    }

    #[test]
    fn only_the_canonical_shape_parses() {
        for text in [
            "",
            "2026-09-21T14:13:20",
            "2026-09-21T14:13:20.000Z",
            "2026-09-21t14:13:20Z",
            "2026-09-21T14:13:20z",
            "2026-09-21 14:13:20Z",
            "2026-09-21T14:13:20+00:00",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-09-00T00:00:00Z",
            "2026-09-21T24:00:00Z",
            "2026-09-21T23:60:00Z",
            "2026-09-21T23:59:60Z",
            "1969-12-31T23:59:59Z",
            "+026-09-21T14:13:20Z",
            "2026-09-2１T14:13:2Z",
        ] {
            assert_eq!(parse_timestamp(text), None, "{text:?}");
        }
    }
}
