use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request as HyperRequest, Response as HyperResponse, Server as HyperServer};
use lattice_flatbuf::{self as flatbuf, fb as fbs};
use lattice_proto::latticev1::{
    AuditRequest, AuditResponse, CrackedHash, Error, HashBatch, Status,
    audit_request::Payload as RequestPayload,
    audit_response::Payload as ResponsePayload,
    lattice_audit_server::{LatticeAudit, LatticeAuditServer},
};
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::{Resource, trace as sdktrace};
use prometheus::{Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, TextEncoder};
use rainbowkv::Table;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status as TonicStatus};
use tracing::{info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "lattice-worker",
    version,
    about = "Lattice worker (streaming skeleton)"
)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:50052")]
    addr: String,

    /// Worker node id
    #[arg(long, default_value = "worker-1")]
    node_id: String,

    /// Path to RainbowKV table
    #[arg(long)]
    table: PathBuf,

    /// Metrics bind address (empty to disable)
    #[arg(long, default_value = ":2113")]
    metrics_addr: String,

    /// OTLP gRPC endpoint (host:port)
    #[arg(long, default_value = "")]
    otel_endpoint: String,

    /// Disable OTLP TLS
    #[arg(long, default_value_t = false)]
    otel_insecure: bool,

    /// TLS server cert (PEM)
    #[arg(long)]
    tls_cert: PathBuf,

    /// TLS server key (PEM)
    #[arg(long)]
    tls_key: PathBuf,

    /// Client CA for mTLS (PEM)
    #[arg(long)]
    tls_client_ca: PathBuf,
}

#[derive(Clone, Copy)]
enum ReplyEncoding {
    Proto,
    Flatbuf,
}

#[derive(Clone)]
struct WorkerState {
    node_id: String,
    table: Arc<Table>,
    processed: Arc<AtomicU64>,
    cracked: Arc<AtomicU64>,
    started: Instant,
    metrics: Metrics,
}

#[derive(Clone)]
struct Metrics {
    processed: IntCounter,
    cracked: IntCounter,
    lookup_errors: IntCounter,
    batches: IntCounter,
    hash_rate: Gauge,
    inflight_batches: IntGauge,
    streams: IntGauge,
    batch_latency: Histogram,
}

#[derive(Clone, Debug, Default)]
struct TraceContext {
    traceparent: Option<String>,
    baggage: Option<String>,
}

impl TraceContext {
    fn from_proto(req: &AuditRequest) -> Self {
        Self {
            traceparent: (!req.traceparent.is_empty()).then(|| req.traceparent.clone()),
            baggage: (!req.baggage.is_empty()).then(|| req.baggage.clone()),
        }
    }

    fn from_flatbuf(req: &fbs::AuditRequest<'_>) -> Self {
        Self {
            traceparent: req.traceparent().map(|s| s.to_string()),
            baggage: req.baggage().map(|s| s.to_string()),
        }
    }

    fn to_otel_context(&self) -> opentelemetry::Context {
        let carrier = TraceCarrier { trace: self };
        global::get_text_map_propagator(|prop| prop.extract(&carrier))
    }

    fn as_flatbuf(&self) -> flatbuf::TraceContext<'_> {
        flatbuf::TraceContext {
            traceparent: self.traceparent.as_deref(),
            baggage: self.baggage.as_deref(),
        }
    }
}

struct TraceCarrier<'a> {
    trace: &'a TraceContext,
}

impl Extractor for TraceCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "traceparent" => self.trace.traceparent.as_deref(),
            "baggage" => self.trace.baggage.as_deref(),
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        vec!["traceparent", "baggage"]
    }
}

#[tonic::async_trait]
impl LatticeAudit for WorkerState {
    type AuditStreamStream = ReceiverStream<Result<AuditResponse, TonicStatus>>;

    async fn audit_stream(
        &self,
        request: Request<tonic::Streaming<AuditRequest>>,
    ) -> Result<Response<Self::AuditStreamStream>, TonicStatus> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let state = self.clone();
        let metrics = self.metrics.clone();
        metrics.streams.inc();

        tokio::spawn(async move {
            while let Ok(Some(msg)) = inbound.message().await {
                let trace = TraceContext::from_proto(&msg);
                match msg.payload {
                    Some(RequestPayload::HashBatch(batch)) => {
                        state.handle_batch_proto(batch, trace, &tx).await;
                    }
                    Some(RequestPayload::Control(_)) => {
                        state
                            .send_status(&tx, ReplyEncoding::Proto, None, &trace)
                            .await;
                    }
                    Some(RequestPayload::Flatbuf(buf)) => {
                        state.handle_flatbuf_request(&buf, trace, &tx).await;
                    }
                    None => {}
                }
            }
            metrics.streams.dec();
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

impl WorkerState {
    async fn handle_batch_proto(
        &self,
        batch: HashBatch,
        trace: TraceContext,
        tx: &mpsc::Sender<Result<AuditResponse, TonicStatus>>,
    ) {
        let span = tracing::info_span!(
            "hash_batch",
            batch_id = %batch.batch_id,
            hashes = batch.raw_hashes.len()
        );
        span.set_parent(trace.to_otel_context());
        let _guard = span.enter();

        self.metrics.batches.inc();
        self.metrics.inflight_batches.inc();
        let started = Instant::now();

        self.processed
            .fetch_add(batch.raw_hashes.len() as u64, Ordering::Relaxed);
        self.metrics.processed.inc_by(batch.raw_hashes.len() as u64);

        for raw in &batch.raw_hashes {
            if raw.len() != 16 {
                continue;
            }
            let mut hash = [0u8; 16];
            hash.copy_from_slice(raw);

            match self.table.lookup_ntlm(hash) {
                Ok(Some(result)) => {
                    self.cracked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.cracked.inc();
                    let plaintext = String::from_utf8_lossy(&result.plaintext).to_string();
                    let chain_info = ((result.chain_index as u64) << 32) | (result.position as u64);

                    let cracked = CrackedHash {
                        original_hash: raw.clone(),
                        username: "".to_string(),
                        plaintext,
                        chain_info,
                        batch_id: batch.batch_id.clone(),
                    };
                    let _ = tx
                        .send(Ok(AuditResponse {
                            traceparent: trace.traceparent.clone().unwrap_or_default(),
                            baggage: trace.baggage.clone().unwrap_or_default(),
                            payload: Some(ResponsePayload::CrackedHash(cracked)),
                        }))
                        .await;
                }
                Ok(None) => {}
                Err(err) => {
                    self.metrics.lookup_errors.inc();
                    let _ = tx
                        .send(Ok(AuditResponse {
                            traceparent: trace.traceparent.clone().unwrap_or_default(),
                            baggage: trace.baggage.clone().unwrap_or_default(),
                            payload: Some(ResponsePayload::Error(Error {
                                code: 500,
                                message: "lookup failed".to_string(),
                                details: err.to_string(),
                                batch_id: batch.batch_id.clone(),
                            })),
                        }))
                        .await;
                }
            }
        }

        self.metrics.inflight_batches.dec();
        self.metrics
            .batch_latency
            .observe(started.elapsed().as_secs_f64());

        self.send_status(tx, ReplyEncoding::Proto, None, &trace)
            .await;
    }

    async fn handle_flatbuf_request(
        &self,
        buf: &[u8],
        mut trace: TraceContext,
        tx: &mpsc::Sender<Result<AuditResponse, TonicStatus>>,
    ) {
        let req = match flatbuf::parse_audit_request(buf) {
            Ok(req) => req,
            Err(err) => {
                let err_buf = flatbuf::build_error_response(
                    None,
                    trace.as_flatbuf(),
                    400,
                    "flatbuf parse failed",
                    Some(&err.to_string()),
                    None,
                );
                let _ = tx
                    .send(Ok(AuditResponse {
                        traceparent: trace.traceparent.clone().unwrap_or_default(),
                        baggage: trace.baggage.clone().unwrap_or_default(),
                        payload: Some(ResponsePayload::Flatbuf(err_buf)),
                    }))
                    .await;
                return;
            }
        };

        let fb_trace = TraceContext::from_flatbuf(&req);
        if fb_trace.traceparent.is_some() {
            trace.traceparent = fb_trace.traceparent;
        }
        if fb_trace.baggage.is_some() {
            trace.baggage = fb_trace.baggage;
        }

        let stream_id = req.stream_id();
        match req.payload_type() {
            fbs::RequestPayload::HashBatch => {
                if let Some(batch) = req.payload_as_hash_batch() {
                    let batch_id = batch.batch_id().unwrap_or("");
                    if let Some(hashes) = batch.hashes() {
                        let span = tracing::info_span!(
                            "hash_batch",
                            batch_id = %batch_id,
                            hashes = hashes.len()
                        );
                        span.set_parent(trace.to_otel_context());
                        let _guard = span.enter();

                        self.metrics.batches.inc();
                        self.metrics.inflight_batches.inc();
                        let started = Instant::now();

                        self.processed
                            .fetch_add(hashes.len() as u64, Ordering::Relaxed);
                        self.metrics.processed.inc_by(hashes.len() as u64);

                        for hash in hashes {
                            let hash_bytes = flatbuf::hash16_to_bytes(hash);
                            match self.table.lookup_ntlm(hash_bytes) {
                                Ok(Some(result)) => {
                                    self.cracked.fetch_add(1, Ordering::Relaxed);
                                    self.metrics.cracked.inc();
                                    let plaintext =
                                        String::from_utf8_lossy(&result.plaintext).to_string();
                                    let chain_info = ((result.chain_index as u64) << 32)
                                        | (result.position as u64);

                                    let buf = flatbuf::build_cracked_hash_response(
                                        stream_id,
                                        trace.as_flatbuf(),
                                        &hash_bytes,
                                        None,
                                        &plaintext,
                                        chain_info,
                                        batch_id,
                                    );
                                    let _ = tx
                                        .send(Ok(AuditResponse {
                                            traceparent: trace
                                                .traceparent
                                                .clone()
                                                .unwrap_or_default(),
                                            baggage: trace.baggage.clone().unwrap_or_default(),
                                            payload: Some(ResponsePayload::Flatbuf(buf)),
                                        }))
                                        .await;
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    self.metrics.lookup_errors.inc();
                                    let buf = flatbuf::build_error_response(
                                        stream_id,
                                        trace.as_flatbuf(),
                                        500,
                                        "lookup failed",
                                        Some(&err.to_string()),
                                        Some(batch_id),
                                    );
                                    let _ = tx
                                        .send(Ok(AuditResponse {
                                            traceparent: trace
                                                .traceparent
                                                .clone()
                                                .unwrap_or_default(),
                                            baggage: trace.baggage.clone().unwrap_or_default(),
                                            payload: Some(ResponsePayload::Flatbuf(buf)),
                                        }))
                                        .await;
                                }
                            }
                        }

                        self.metrics.inflight_batches.dec();
                        self.metrics
                            .batch_latency
                            .observe(started.elapsed().as_secs_f64());
                    }

                    self.send_status(tx, ReplyEncoding::Flatbuf, stream_id, &trace)
                        .await;
                }
            }
            fbs::RequestPayload::ControlMessage => {
                self.send_status(tx, ReplyEncoding::Flatbuf, stream_id, &trace)
                    .await;
            }
            _ => {}
        }
    }

    async fn send_status(
        &self,
        tx: &mpsc::Sender<Result<AuditResponse, TonicStatus>>,
        encoding: ReplyEncoding,
        stream_id: Option<&str>,
        trace: &TraceContext,
    ) {
        let processed = self.processed.load(Ordering::Relaxed);
        let cracked = self.cracked.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            processed as f64 / elapsed
        } else {
            0.0
        };
        self.metrics.hash_rate.set(rate);

        match encoding {
            ReplyEncoding::Proto => {
                let status = Status {
                    node_id: self.node_id.clone(),
                    status: "OK".to_string(),
                    rate_hashes_per_sec: rate,
                    processed,
                    cracked,
                    in_flight: 0,
                    timestamp_unix_ms: now_unix_ms(),
                };
                let _ = tx
                    .send(Ok(AuditResponse {
                        traceparent: trace.traceparent.clone().unwrap_or_default(),
                        baggage: trace.baggage.clone().unwrap_or_default(),
                        payload: Some(ResponsePayload::Status(status)),
                    }))
                    .await;
            }
            ReplyEncoding::Flatbuf => {
                let buf = flatbuf::build_status_response(
                    stream_id,
                    trace.as_flatbuf(),
                    &self.node_id,
                    fbs::StatusKind::Ok,
                    rate,
                    processed,
                    cracked,
                    0,
                    now_unix_ms(),
                );
                let _ = tx
                    .send(Ok(AuditResponse {
                        traceparent: trace.traceparent.clone().unwrap_or_default(),
                        baggage: trace.baggage.clone().unwrap_or_default(),
                        payload: Some(ResponsePayload::Flatbuf(buf)),
                    }))
                    .await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args.otel_endpoint, args.otel_insecure, "lattice-worker")?;
    let metrics = init_metrics().context("init metrics")?;

    if !args.metrics_addr.is_empty() {
        let addr = parse_listen_addr(&args.metrics_addr).context("parse metrics addr")?;
        tokio::spawn(async move {
            serve_metrics(addr).await;
        });
    }

    let table = Arc::new(Table::open(&args.table).context("open table")?);

    let cert = tokio::fs::read(&args.tls_cert)
        .await
        .with_context(|| format!("read cert: {}", args.tls_cert.display()))?;
    let key = tokio::fs::read(&args.tls_key)
        .await
        .with_context(|| format!("read key: {}", args.tls_key.display()))?;
    let ca = tokio::fs::read(&args.tls_client_ca)
        .await
        .with_context(|| format!("read client CA: {}", args.tls_client_ca.display()))?;

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca));

    let worker = WorkerState {
        node_id: args.node_id.clone(),
        table,
        processed: Arc::new(AtomicU64::new(0)),
        cracked: Arc::new(AtomicU64::new(0)),
        started: Instant::now(),
        metrics,
    };

    info!(addr = %args.addr, "lattice-worker listening");
    Server::builder()
        .tls_config(tls)
        .context("tls config")?
        .add_service(LatticeAuditServer::new(worker))
        .serve(args.addr.parse().context("parse addr")?)
        .await
        .context("serve worker")?;

    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}

fn init_metrics() -> Result<Metrics> {
    let processed = IntCounter::new("lattice_worker_processed_total", "Total hashes processed")?;
    let cracked = IntCounter::new("lattice_worker_cracked_total", "Total hashes cracked")?;
    let lookup_errors = IntCounter::new(
        "lattice_worker_lookup_errors_total",
        "Lookup errors returned by RainbowKV",
    )?;
    let batches = IntCounter::new("lattice_worker_batches_total", "Total batches processed")?;
    let hash_rate = Gauge::new("lattice_worker_hash_rate", "Current hash rate (hashes/sec)")?;
    let inflight_batches = IntGauge::new(
        "lattice_worker_inflight_batches",
        "Batches currently in flight",
    )?;
    let streams = IntGauge::new("lattice_worker_streams", "Active worker gRPC streams")?;
    let batch_latency = Histogram::with_opts(HistogramOpts::new(
        "lattice_worker_batch_latency_seconds",
        "Batch processing latency",
    ))?;

    prometheus::register(Box::new(processed.clone()))?;
    prometheus::register(Box::new(cracked.clone()))?;
    prometheus::register(Box::new(lookup_errors.clone()))?;
    prometheus::register(Box::new(batches.clone()))?;
    prometheus::register(Box::new(hash_rate.clone()))?;
    prometheus::register(Box::new(inflight_batches.clone()))?;
    prometheus::register(Box::new(streams.clone()))?;
    prometheus::register(Box::new(batch_latency.clone()))?;

    Ok(Metrics {
        processed,
        cracked,
        lookup_errors,
        batches,
        hash_rate,
        inflight_batches,
        streams,
        batch_latency,
    })
}

async fn serve_metrics(addr: SocketAddr) {
    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(metrics_handler)) });

    if let Err(err) = HyperServer::bind(&addr).serve(make_svc).await {
        warn!(error = %err, "metrics server failed");
    }
}

async fn metrics_handler(_req: HyperRequest<Body>) -> Result<HyperResponse<Body>, Infallible> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
        let body = format!("metrics encode failed: {err}");
        let resp = HyperResponse::builder()
            .status(500)
            .body(Body::from(body))
            .unwrap();
        return Ok(resp);
    }

    let resp = HyperResponse::builder()
        .status(200)
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    Ok(resp)
}

fn init_tracing(endpoint: &str, insecure: bool, service: &str) -> Result<()> {
    global::set_text_map_propagator(TraceContextPropagator::new());
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let fmt_layer = tracing_subscriber::fmt::layer();

    if endpoint.is_empty() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
        return Ok(());
    }

    let endpoint = normalize_endpoint(endpoint, insecure);
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let tracer =
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(sdktrace::config().with_resource(Resource::new(vec![
                KeyValue::new("service.name", service.to_string()),
            ])))
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    Ok(())
}

fn normalize_endpoint(endpoint: &str, insecure: bool) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else if insecure {
        format!("http://{endpoint}")
    } else {
        format!("https://{endpoint}")
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn parse_listen_addr(addr: &str) -> Result<SocketAddr> {
    let normalized = if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    };
    normalized.parse().context("invalid socket address syntax")
}
