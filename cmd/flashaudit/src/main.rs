use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, ValueEnum};
use lattice_flatbuf::{self as flatbuf, fb as fbs};
use lattice_input::extract_ntlm_hash;
use lattice_proto::latticev1::{
    AuditRequest, ControlKind, ControlMessage, HashBatch, audit_request::Payload as RequestPayload,
    audit_response::Payload as ResponsePayload, lattice_audit_client::LatticeAuditClient,
};
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::propagation::Injector;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::{Resource, trace as sdktrace};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod ui;
use ui::AppEvent;

#[derive(Parser, Debug)]
#[command(
    name = "flashaudit",
    version,
    about = "FlashAudit client (streaming skeleton)"
)]
struct Args {
    /// Orchestrator address (must include scheme, e.g. https://127.0.0.1:50051)
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    addr: String,

    /// Path to CA certificate (PEM)
    #[arg(long)]
    ca: PathBuf,

    /// Path to client certificate (PEM)
    #[arg(long)]
    cert: PathBuf,

    /// Path to client private key (PEM)
    #[arg(long)]
    key: PathBuf,

    /// TLS server name (SNI)
    #[arg(long, default_value = "lattice-orchestrator")]
    server_name: String,

    /// Input file with NTLM hashes (defaults to stdin)
    #[arg(long)]
    input: Option<PathBuf>,

    /// Hashes per batch
    #[arg(long, default_value_t = 1024)]
    batch_size: usize,

    /// Payload encoding for the data plane
    #[arg(long, value_enum, default_value_t = PayloadEncoding::Flatbuf)]
    payload: PayloadEncoding,

    /// OTLP gRPC endpoint (host:port)
    #[arg(long, default_value = "")]
    otel_endpoint: String,

    /// Disable OTLP TLS
    #[arg(long, default_value_t = false)]
    otel_insecure: bool,

    /// Disable TUI (log-only mode)
    #[arg(long = "no-tui", action = ArgAction::SetFalse, default_value_t = true)]
    tui: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PayloadEncoding {
    Flatbuf,
    Proto,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args.otel_endpoint, args.otel_insecure, "flashaudit")?;
    let channel = connect_tls(&args).await?;
    let mut client = LatticeAuditClient::new(channel);

    let (tx, rx) = mpsc::channel::<AuditRequest>(8);
    let outbound = ReceiverStream::new(rx);

    let response = client
        .audit_stream(outbound)
        .await
        .context("audit_stream")?;

    let mut inbound = response.into_inner();
    let (ui_tx, ui_rx) = mpsc::unbounded_channel::<AppEvent>();

    let response_ui = ui_tx.clone();
    let response_task = tokio::spawn(async move {
        while let Ok(Some(msg)) = inbound.message().await {
            match msg.payload {
                Some(ResponsePayload::Status(status)) => {
                    let _ = response_ui.send(AppEvent::Status {
                        node_id: status.node_id,
                        rate: status.rate_hashes_per_sec,
                        processed: status.processed,
                        cracked: status.cracked,
                        in_flight: status.in_flight,
                    });
                }
                Some(ResponsePayload::CrackedHash(cracked)) => {
                    let _ = response_ui.send(AppEvent::Cracked {
                        username: cracked.username,
                        plaintext: cracked.plaintext,
                    });
                }
                Some(ResponsePayload::Error(err)) => {
                    let _ = response_ui.send(AppEvent::Error {
                        code: err.code,
                        message: err.message,
                    });
                }
                Some(ResponsePayload::Flatbuf(buf)) => match flatbuf::parse_audit_response(&buf) {
                    Ok(resp) => match resp.payload_type() {
                        fbs::ResponsePayload::CrackedHash => {
                            if let Some(cracked) = resp.payload_as_cracked_hash() {
                                let _ = response_ui.send(AppEvent::Cracked {
                                    username: cracked.username().unwrap_or("").to_string(),
                                    plaintext: cracked.plaintext().unwrap_or("").to_string(),
                                });
                            }
                        }
                        fbs::ResponsePayload::Status => {
                            if let Some(status) = resp.payload_as_status() {
                                let _ = response_ui.send(AppEvent::Status {
                                    node_id: status.node_id().unwrap_or("").to_string(),
                                    rate: status.rate_hashes_per_sec(),
                                    processed: status.processed(),
                                    cracked: status.cracked(),
                                    in_flight: status.in_flight(),
                                });
                            }
                        }
                        fbs::ResponsePayload::Error => {
                            if let Some(err) = resp.payload_as_error() {
                                let _ = response_ui.send(AppEvent::Error {
                                    code: err.code(),
                                    message: err.message().unwrap_or("").to_string(),
                                });
                            }
                        }
                        _ => {}
                    },
                    Err(err) => {
                        let _ = response_ui.send(AppEvent::Error {
                            code: 400,
                            message: format!("flatbuf parse failed: {err}"),
                        });
                    }
                },
                _ => {}
            }
        }
    });

    send_control(&tx, args.payload).await?;

    let input_tx = tx.clone();
    let input_ui = ui_tx.clone();
    let input_path = args.input.clone();
    let batch_size = args.batch_size;
    let payload = args.payload;

    let input_task = tokio::spawn(async move {
        let mut reader = open_input(input_path).await?;
        let mut line = String::new();
        let mut batch = Vec::with_capacity(batch_size);
        let mut batch_index: u64 = 0;
        let mut total: u64 = 0;

        loop {
            line.clear();
            let read = reader.read_line(&mut line).await?;
            if read == 0 {
                break;
            }

            if let Some(hash) = extract_ntlm_hash(&line) {
                batch.push(hash);
                if batch.len() >= batch_size {
                    let batch_id = format!("batch-{batch_index}");
                    send_batch(&input_tx, &batch_id, &batch, payload).await?;
                    total += batch.len() as u64;
                    let _ = input_ui.send(AppEvent::SentBatch {
                        count: batch.len() as u64,
                    });
                    batch.clear();
                    batch_index += 1;
                }
            }
        }

        if !batch.is_empty() {
            let batch_id = format!("batch-{batch_index}");
            send_batch(&input_tx, &batch_id, &batch, payload).await?;
            total += batch.len() as u64;
            let _ = input_ui.send(AppEvent::SentBatch {
                count: batch.len() as u64,
            });
        }

        let _ = input_ui.send(AppEvent::InputDone);
        info!(total_hashes = total, "input drained");
        Ok::<(), anyhow::Error>(())
    });

    drop(tx);
    drop(ui_tx);

    if args.tui {
        let ui_outcome = ui::run(ui_rx).await?;
        if ui_outcome.quit {
            input_task.abort();
            response_task.abort();
        }
        let _ = input_task.await;
        let _ = response_task.await;
    } else {
        let _ = input_task.await;
        // Give the response stream a short window to flush statuses/cracks in log mode.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        response_task.abort();
        let _ = response_task.await;
        log_events(ui_rx).await;
    }

    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}

async fn log_events(mut rx: mpsc::UnboundedReceiver<AppEvent>) {
    while let Some(event) = rx.recv().await {
        match event {
            AppEvent::Status {
                node_id,
                rate,
                processed,
                cracked,
                ..
            } => {
                info!(node_id = %node_id, rate, processed, cracked, "status");
            }
            AppEvent::Cracked {
                username,
                plaintext,
            } => {
                info!(user = %username, plaintext = %plaintext, "cracked");
            }
            AppEvent::Error { code, message } => {
                warn!(code, message = %message, "error");
            }
            AppEvent::SentBatch { count } => {
                info!(count, "batch sent");
            }
            AppEvent::InputDone => {
                info!("input done");
            }
        }
    }
}

async fn connect_tls(args: &Args) -> Result<Channel> {
    let ca = tokio::fs::read(&args.ca)
        .await
        .with_context(|| format!("read CA cert: {}", args.ca.display()))?;
    let cert = tokio::fs::read(&args.cert)
        .await
        .with_context(|| format!("read client cert: {}", args.cert.display()))?;
    let key = tokio::fs::read(&args.key)
        .await
        .with_context(|| format!("read client key: {}", args.key.display()))?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(args.server_name.clone());

    Channel::from_shared(args.addr.clone())
        .map_err(|e| anyhow!("invalid addr: {e}"))?
        .tls_config(tls)?
        .connect()
        .await
        .context("connect TLS")
}

async fn open_input(path: Option<PathBuf>) -> Result<Box<dyn AsyncBufRead + Unpin + Send>> {
    if let Some(path) = path {
        let file = tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("open input: {}", path.display()))?;
        Ok(Box::new(BufReader::new(file)))
    } else {
        Ok(Box::new(BufReader::new(tokio::io::stdin())))
    }
}

async fn send_control(tx: &mpsc::Sender<AuditRequest>, encoding: PayloadEncoding) -> Result<()> {
    let span = tracing::info_span!("control", kind = "start");
    let _guard = span.enter();
    let trace = TraceContext::from_span(&span);
    match encoding {
        PayloadEncoding::Proto => {
            tx.send(AuditRequest {
                traceparent: trace.traceparent.clone().unwrap_or_default(),
                baggage: trace.baggage.clone().unwrap_or_default(),
                payload: Some(RequestPayload::Control(ControlMessage {
                    kind: ControlKind::Start as i32,
                    reason: "client_start".to_string(),
                    metadata: Default::default(),
                    batch_id: "".to_string(),
                })),
            })
            .await
            .context("send start control")?;
        }
        PayloadEncoding::Flatbuf => {
            let buf = flatbuf::build_control_request(
                None,
                flatbuf::TraceContext {
                    traceparent: trace.traceparent.as_deref(),
                    baggage: trace.baggage.as_deref(),
                },
                fbs::ControlKind::Start,
                Some("client_start"),
                None,
            );
            tx.send(AuditRequest {
                traceparent: trace.traceparent.clone().unwrap_or_default(),
                baggage: trace.baggage.clone().unwrap_or_default(),
                payload: Some(RequestPayload::Flatbuf(buf)),
            })
            .await
            .context("send start control (flatbuf)")?;
        }
    }
    Ok(())
}

async fn send_batch(
    tx: &mpsc::Sender<AuditRequest>,
    batch_id: &str,
    batch: &[[u8; 16]],
    encoding: PayloadEncoding,
) -> Result<()> {
    let span = tracing::info_span!("hash_batch", batch_id = %batch_id, hashes = batch.len());
    let _guard = span.enter();
    let trace = TraceContext::from_span(&span);
    match encoding {
        PayloadEncoding::Proto => {
            let raw_hashes = batch.iter().map(|h| h.to_vec()).collect();
            let payload = HashBatch {
                raw_hashes,
                batch_id: batch_id.to_string(),
                sent_unix_ms: now_unix_ms(),
            };

            tx.send(AuditRequest {
                traceparent: trace.traceparent.clone().unwrap_or_default(),
                baggage: trace.baggage.clone().unwrap_or_default(),
                payload: Some(RequestPayload::HashBatch(payload)),
            })
            .await
            .context("send hash batch")?;
        }
        PayloadEncoding::Flatbuf => {
            let buf = flatbuf::build_hash_batch_request(
                None,
                flatbuf::TraceContext {
                    traceparent: trace.traceparent.as_deref(),
                    baggage: trace.baggage.as_deref(),
                },
                batch_id,
                batch,
                now_unix_ms(),
            );
            tx.send(AuditRequest {
                traceparent: trace.traceparent.clone().unwrap_or_default(),
                baggage: trace.baggage.clone().unwrap_or_default(),
                payload: Some(RequestPayload::Flatbuf(buf)),
            })
            .await
            .context("send hash batch (flatbuf)")?;
        }
    }

    Ok(())
}

#[derive(Clone, Debug, Default)]
struct TraceContext {
    traceparent: Option<String>,
    baggage: Option<String>,
}

impl TraceContext {
    fn from_span(span: &tracing::Span) -> Self {
        let cx = span.context();
        let mut carrier = TraceCarrier::default();
        global::get_text_map_propagator(|prop| prop.inject_context(&cx, &mut carrier));
        Self {
            traceparent: carrier.traceparent,
            baggage: carrier.baggage,
        }
    }
}

#[derive(Default)]
struct TraceCarrier {
    traceparent: Option<String>,
    baggage: Option<String>,
}

impl Injector for TraceCarrier {
    fn set(&mut self, key: &str, value: String) {
        match key {
            "traceparent" => self.traceparent = Some(value),
            "baggage" => self.baggage = Some(value),
            _ => {}
        }
    }
}

fn init_tracing(endpoint: &str, insecure: bool, service: &str) -> Result<()> {
    global::set_text_map_propagator(TraceContextPropagator::new());
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

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
        .unwrap_or_default()
        .as_millis() as u64
}
