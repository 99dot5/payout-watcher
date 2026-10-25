//! Shared observability init for the 99dot5 runtime services.
//!
//! Installs a global [`tracing`] subscriber that emits **one JSON object per
//! line** to stdout, sized for a log aggregator's query language (`parse`/`stats`
//! queries and metric filters). Every first-party service calls [`init`] once
//! at startup and holds the returned [`ObservabilityGuard`] for the process
//! lifetime.
//!
//! # JSON field-shape contract (load-bearing — downstream code depends on it)
//!
//! Every emitted line is a flat JSON object with these **root** keys:
//!
//! | key         | source                                              |
//! |-------------|-----------------------------------------------------|
//! | `timestamp` | RFC3339 UTC (e.g. `2026-06-28T12:34:56.789Z`)       |
//! | `level`     | log severity (`INFO`/`WARN`/`ERROR`/`DEBUG`/`TRACE`)|
//! | `target`    | event target (module path)                          |
//! | `message`   | the event's format-string message                   |
//! | `service`   | the `service_name` passed to [`init`]               |
//! | `version`   | the `service_version` passed to [`init`]            |
//!
//! **Event-direct fields are root keys.** Fields attached to the event itself —
//! `tracing::info!(reference = %r, "indexed deposit")` — are flattened to the
//! top level (`reference` is a root key alongside `message`).
//!
//! **Span fields are nested under `span`.** Fields attached to a span — set via
//! `#[instrument(fields(...))]` or `info_span!("x", tenant_id = %t)` — are
//! collected (root span → leaf span, leaf wins on key collision) into a single
//! nested `span` object. Query them in the log aggregator as
//! `span.tenant_id`, `span.pool_id`, etc. There is no per-span array; only the
//! merged current scope is serialized (the `with_span_list` stack is
//! intentionally dropped for hot-path cost).
//!
//! Lines emitted with no active span (e.g. bridged dependency `log` lines) carry
//! `service`/`version` at root but no `span` object.
//!
//! # Canonical field vocabulary
//!
//! To keep log queries consistent across the fleet, use these field names
//! (consistency is the whole point):
//!
//! - `tenant_id`, `pool_id`, `session_id`, `round_id` — multi-tenant scope.
//! - `l1_level` — Tezos block height. **Never** `level` (that's the log
//!   severity in the JSON).
//! - `reference`, `error`, `count`, `strategy`, `end_reason` — common payloads.
//!
//! # Dependency `log` bridge
//!
//! [`init`] finalizes with [`SubscriberInitExt::try_init`], which installs the
//! `LogTracer` so third-party crates that emit via the `log` facade (sqlx
//! slow-query, hyper/rustls internals, `config`, etc.) appear as JSON too. A
//! dependency-noise floor (`sqlx`/`hyper`/`h2`/`rustls` at `warn`) is applied on
//! top of `RUST_LOG` so the bridge cannot flood ingestion.

use serde_json::{Map, Value};
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    {Event, Subscriber},
};
use tracing_subscriber::{
    fmt::{
        format::{FormatEvent, FormatFields, Writer},
        FmtContext,
    },
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

/// Opaque guard returned by [`init`]. Today it is a zero-sized type; hold it for
/// the process lifetime (`let _guard = observability::init("svc", "1.2.3");`). It is the
/// stable seam for a future OTLP `TracerProvider` shutdown handle and/or a
/// `tracing_appender` `WorkerGuard` whose `Drop` flushes buffered logs — adding
/// those will not change [`init`]'s signature or call sites.
#[must_use]
#[derive(Debug)]
pub struct ObservabilityGuard {
    _private: (),
}

/// Initialize the global JSON tracing subscriber. Call once at startup; hold the
/// returned guard for the process lifetime. Safe to call more than once: the
/// second and later calls are no-ops (the global subscriber is already set) and
/// still return a guard, so test binaries that init repeatedly do not panic.
///
/// Pass `service_version` as `env!("CARGO_PKG_VERSION")` from the *calling*
/// service crate so the macro expands there and the root `version` field carries
/// the real per-service version (not this crate's).
pub fn init(service_name: &'static str, service_version: &'static str) -> ObservabilityGuard {
    // EnvFilter: start from RUST_LOG (default `info`), then *unconditionally*
    // layer a dependency-noise floor ON TOP — not as a fallback. A fallback-only
    // floor would be nullified whenever RUST_LOG is set (which it is in several
    // environments), so an explicit `RUST_LOG=info` would otherwise discard it.
    // Per-target RUST_LOG directives still override these (last-set wins).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("sqlx=warn".parse().expect("static directive is valid"))
        .add_directive("hyper=warn".parse().expect("static directive is valid"))
        .add_directive("h2=warn".parse().expect("static directive is valid"))
        .add_directive("rustls=warn".parse().expect("static directive is valid"));
    let formatter = JsonEventFormatter {
        service: service_name,
        version: service_version,
    };
    let fmt_layer = tracing_subscriber::fmt::layer().event_format(formatter);
    // OTEL SEAM: a future `tracing-opentelemetry` layer activates on the standard
    // `OTEL_EXPORTER_OTLP_ENDPOINT` env var and slots in here. Kept as a dormant
    // `None` so wiring it later is additive and does not reshape the layer stack.
    let otel_layer: Option<Box<dyn Layer<_> + Send + Sync>> = None;
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(JsonStorageLayer)
        .with(fmt_layer)
        .with(otel_layer);

    // `try_init` (NOT `set_global_default`) installs the `LogTracer` required by
    // the `tracing-log` bridge. Tolerate `Err` so repeated init (tests, double
    // boot) is a no-op rather than a panic. Install the panic hook only on the
    // first successful init so repeated calls (e.g. tests) don't stack hooks.
    if subscriber.try_init().is_ok() {
        install_panic_hook();
    }

    ObservabilityGuard { _private: () }
}

/// Install a process-wide panic hook that emits a structured `tracing` error
/// for every panic, then delegates to the previously-installed hook (which
/// still prints the standard message + backtrace to stderr when
/// `RUST_BACKTRACE` is set). This makes a crash-by-panic an indexable JSON line
/// instead of only unstructured stderr text. Installed once, on the first
/// successful [`init`].
fn install_panic_hook() {
    let previous = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_owned());
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");

        tracing::error!(error = message, location = %location, "fatal: panic");
        previous(info);
    }));
}

/// Visitor that collects `tracing` fields into a `serde_json` object, mapping
/// each typed value to its natural JSON representation.
#[derive(Default)]
struct JsonVisitor {
    fields: Map<String, Value>,
}

impl JsonVisitor {
    fn insert(&mut self, field: &Field, value: Value) {
        self.fields.insert(field.name().to_owned(), value);
    }
}

impl Visit for JsonVisitor {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::from(value));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        match i64::try_from(value) {
            Ok(v) => self.insert(field, Value::from(v)),
            Err(_) => self.insert(field, Value::from(value.to_string())),
        }
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        match u64::try_from(value) {
            Ok(v) => self.insert(field, Value::from(v)),
            Err(_) => self.insert(field, Value::from(value.to_string())),
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, Value::from(format!("{value:?}")));
    }
}

/// Per-span storage of a span's fields as a JSON object, kept in the span's
/// extensions so the event formatter can render the merged span scope.
struct SpanFields(Map<String, Value>);

/// Layer that records each span's fields into its extensions as JSON. The
/// formatting layer reads these back to build the nested `span` object.
struct JsonStorageLayer;

impl<S> Layer<S> for JsonStorageLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span must exist for new id");
        let mut visitor = JsonVisitor::default();

        attrs.record(&mut visitor);
        span.extensions_mut().insert(SpanFields(visitor.fields));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span must exist for recorded id");
        let mut visitor = JsonVisitor::default();

        values.record(&mut visitor);

        let mut ext = span.extensions_mut();

        if let Some(SpanFields(existing)) = ext.get_mut::<SpanFields>() {
            for (key, value) in visitor.fields {
                existing.insert(key, value);
            }
        } else {
            ext.insert(SpanFields(visitor.fields));
        }
    }
}

/// Custom event formatter that emits the flat JSON contract documented at the
/// crate root, injecting constant `service`/`version` root keys on every line
/// (including bridged dependency `log` lines, which carry no span).
struct JsonEventFormatter {
    service: &'static str,
    version: &'static str,
}

impl<S, N> FormatEvent<S, N> for JsonEventFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut root = Map::new();
        // Event-direct fields (including `message`) flatten to the root FIRST,
        // so the reserved keys inserted below always win on collision — a stray
        // `info!(service = …)` / `level = …` can never clobber a reserved key
        // and corrupt the metric filters that key off them.
        let mut visitor = JsonVisitor::default();

        event.record(&mut visitor);

        for (key, value) in visitor.fields {
            root.insert(key, value);
        }

        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();

        root.insert("timestamp".to_owned(), Value::from(timestamp));
        root.insert("level".to_owned(), Value::from(metadata.level().as_str()));
        root.insert("target".to_owned(), Value::from(metadata.target()));
        root.insert("service".to_owned(), Value::from(self.service));
        root.insert("version".to_owned(), Value::from(self.version));

        // Span scope: merge ancestor → current span fields into one `span`
        // object (leaf wins on collision). No span list / array.
        if let Some(scope) = ctx.event_scope() {
            let mut span_fields = Map::new();

            for span in scope.from_root() {
                if let Some(SpanFields(fields)) = span.extensions().get::<SpanFields>() {
                    for (key, value) in fields {
                        span_fields.insert(key.clone(), value.clone());
                    }
                }
            }

            if !span_fields.is_empty() {
                root.insert("span".to_owned(), Value::Object(span_fields));
            }
        }

        let line = serde_json::to_string(&Value::Object(root)).map_err(|_| fmt::Error)?;

        writeln!(writer, "{line}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    /// `io::Write` sink that appends to a shared buffer, for capturing the JSON
    /// the subscriber emits in tests.
    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);

            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture<F: FnOnce()>(emit: F) -> Vec<Value> {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = VecWriter(buf.clone());
        let subscriber = tracing_subscriber::registry().with(JsonStorageLayer).with(
            tracing_subscriber::fmt::layer()
                .event_format(JsonEventFormatter {
                    service: "test-svc",
                    version: "9.9.9",
                })
                .with_writer(move || sink.clone()),
        );

        tracing::subscriber::with_default(subscriber, emit);

        let bytes = buf.lock().unwrap().clone();

        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each line must be valid JSON"))
            .collect()
    }

    #[test]
    fn init_is_double_init_safe() {
        // Second call must be a no-op, not a panic.
        let _g1 = init("test-service", "0.0.0-test");
        let _g2 = init("test-service", "0.0.0-test");
    }

    #[test]
    fn event_line_has_root_contract_keys() {
        let lines = capture(|| {
            tracing::info!(reference = "abc-123", "indexed deposit");
        });

        assert_eq!(lines.len(), 1);

        let value = &lines[0];

        assert_eq!(value["service"], "test-svc");
        assert_eq!(value["version"], "9.9.9");
        assert_eq!(value["message"], "indexed deposit");
        assert_eq!(value["level"], "INFO");
        assert_eq!(
            value["reference"], "abc-123",
            "event-direct fields are root keys"
        );
        assert!(
            value["timestamp"].is_string(),
            "timestamp present (RFC3339)"
        );
        assert!(value["target"].is_string());
        assert!(
            value.get("span").is_none(),
            "no span object outside any span"
        );
    }

    #[test]
    fn span_fields_nest_under_span_object() {
        let lines = capture(|| {
            let conn = tracing::info_span!("conn", tenant_id = "t1", pool_id = "p1");
            let _conn = conn.enter();
            let cmd = tracing::info_span!("cmd", session_id = "s1");
            let _cmd = cmd.enter();

            tracing::info!("inside spans");
        });

        assert_eq!(lines.len(), 1);

        let span = &lines[0]["span"];

        assert_eq!(span["tenant_id"], "t1");
        assert_eq!(span["pool_id"], "p1");
        assert_eq!(span["session_id"], "s1", "leaf span fields merge in");
    }

    #[test]
    fn reserved_keys_win_over_event_fields() {
        // A stray event field named like a reserved key must NOT clobber the
        // reserved value — reserved keys are inserted after the event merge.
        let lines = capture(|| {
            tracing::info!(service = "evil", level = "evil", "msg");
        });

        assert_eq!(lines.len(), 1);

        let value = &lines[0];

        assert_eq!(value["service"], "test-svc", "reserved `service` wins");
        assert_eq!(value["level"], "INFO", "reserved `level` (severity) wins");
        assert_eq!(value["message"], "msg");
    }
}
