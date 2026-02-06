//! FlatBuffers helpers for Lattice audit payloads.

pub mod fb {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(unused_imports)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proto/gen/rust/lattice_generated.rs"
    ));
    pub use lattice::fb::*;
}

use fb::{
    AuditRequest, AuditRequestArgs, AuditResponse, AuditResponseArgs, ControlKind,
    ControlMessageArgs, CrackedHashArgs, ErrorArgs, Hash16, HashBatchArgs, RequestPayload,
    ResponsePayload, StatusArgs,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceContext<'a> {
    pub traceparent: Option<&'a str>,
    pub baggage: Option<&'a str>,
}

pub fn hash16_from_bytes(bytes: &[u8; 16]) -> Hash16 {
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Hash16::new(lo, hi)
}

pub fn hash16_to_bytes(hash: &Hash16) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hash.lo().to_le_bytes());
    out[8..].copy_from_slice(&hash.hi().to_le_bytes());
    out
}

pub fn build_hash_batch_request(
    stream_id: Option<&str>,
    trace: TraceContext<'_>,
    batch_id: &str,
    hashes: &[[u8; 16]],
    sent_unix_ms: u64,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let stream_id = stream_id.map(|s| builder.create_string(s));
    let traceparent = trace.traceparent.map(|s| builder.create_string(s));
    let baggage = trace.baggage.map(|s| builder.create_string(s));
    let batch_id = builder.create_string(batch_id);

    let hash_structs: Vec<Hash16> = hashes.iter().map(hash16_from_bytes).collect();
    let hashes_vec = builder.create_vector(&hash_structs);

    let batch = fb::HashBatch::create(
        &mut builder,
        &HashBatchArgs {
            batch_id: Some(batch_id),
            hashes: Some(hashes_vec),
            sent_unix_ms,
        },
    );

    let payload = flatbuffers::WIPOffset::new(batch.value());
    let req = AuditRequest::create(
        &mut builder,
        &AuditRequestArgs {
            stream_id,
            traceparent,
            baggage,
            payload_type: RequestPayload::HashBatch,
            payload: Some(payload),
        },
    );

    builder.finish(req, None);
    builder.finished_data().to_vec()
}

pub fn build_control_request(
    stream_id: Option<&str>,
    trace: TraceContext<'_>,
    kind: ControlKind,
    reason: Option<&str>,
    batch_id: Option<&str>,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let stream_id = stream_id.map(|s| builder.create_string(s));
    let traceparent = trace.traceparent.map(|s| builder.create_string(s));
    let baggage = trace.baggage.map(|s| builder.create_string(s));
    let reason = reason.map(|s| builder.create_string(s));
    let batch_id = batch_id.map(|s| builder.create_string(s));

    let control = fb::ControlMessage::create(
        &mut builder,
        &ControlMessageArgs {
            kind,
            reason,
            metadata: None,
            batch_id,
        },
    );

    let payload = flatbuffers::WIPOffset::new(control.value());
    let req = AuditRequest::create(
        &mut builder,
        &AuditRequestArgs {
            stream_id,
            traceparent,
            baggage,
            payload_type: RequestPayload::ControlMessage,
            payload: Some(payload),
        },
    );

    builder.finish(req, None);
    builder.finished_data().to_vec()
}

pub fn build_cracked_hash_response(
    stream_id: Option<&str>,
    trace: TraceContext<'_>,
    original_hash: &[u8; 16],
    username: Option<&str>,
    plaintext: &str,
    chain_info: u64,
    batch_id: &str,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let stream_id = stream_id.map(|s| builder.create_string(s));
    let traceparent = trace.traceparent.map(|s| builder.create_string(s));
    let baggage = trace.baggage.map(|s| builder.create_string(s));
    let username = username.map(|s| builder.create_string(s));
    let plaintext = builder.create_string(plaintext);
    let batch_id = builder.create_string(batch_id);

    let hash_struct = hash16_from_bytes(original_hash);
    let cracked = fb::CrackedHash::create(
        &mut builder,
        &CrackedHashArgs {
            original_hash: Some(&hash_struct),
            username,
            plaintext: Some(plaintext),
            chain_info,
            batch_id: Some(batch_id),
        },
    );

    let payload = flatbuffers::WIPOffset::new(cracked.value());
    let resp = AuditResponse::create(
        &mut builder,
        &AuditResponseArgs {
            stream_id,
            traceparent,
            baggage,
            payload_type: ResponsePayload::CrackedHash,
            payload: Some(payload),
        },
    );

    builder.finish(resp, None);
    builder.finished_data().to_vec()
}

pub fn build_status_response(
    stream_id: Option<&str>,
    trace: TraceContext<'_>,
    node_id: &str,
    status: fb::StatusKind,
    rate: f64,
    processed: u64,
    cracked: u64,
    in_flight: u64,
    timestamp_unix_ms: u64,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let stream_id = stream_id.map(|s| builder.create_string(s));
    let traceparent = trace.traceparent.map(|s| builder.create_string(s));
    let baggage = trace.baggage.map(|s| builder.create_string(s));
    let node_id = builder.create_string(node_id);

    let status = fb::Status::create(
        &mut builder,
        &StatusArgs {
            node_id: Some(node_id),
            status,
            rate_hashes_per_sec: rate,
            processed,
            cracked,
            in_flight,
            timestamp_unix_ms,
        },
    );

    let payload = flatbuffers::WIPOffset::new(status.value());
    let resp = AuditResponse::create(
        &mut builder,
        &AuditResponseArgs {
            stream_id,
            traceparent,
            baggage,
            payload_type: ResponsePayload::Status,
            payload: Some(payload),
        },
    );

    builder.finish(resp, None);
    builder.finished_data().to_vec()
}

pub fn build_error_response(
    stream_id: Option<&str>,
    trace: TraceContext<'_>,
    code: i32,
    message: &str,
    details: Option<&str>,
    batch_id: Option<&str>,
) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let stream_id = stream_id.map(|s| builder.create_string(s));
    let traceparent = trace.traceparent.map(|s| builder.create_string(s));
    let baggage = trace.baggage.map(|s| builder.create_string(s));
    let message = builder.create_string(message);
    let details = details.map(|s| builder.create_string(s));
    let batch_id = batch_id.map(|s| builder.create_string(s));

    let error = fb::Error::create(
        &mut builder,
        &ErrorArgs {
            code,
            message: Some(message),
            details,
            batch_id,
        },
    );

    let payload = flatbuffers::WIPOffset::new(error.value());
    let resp = AuditResponse::create(
        &mut builder,
        &AuditResponseArgs {
            stream_id,
            traceparent,
            baggage,
            payload_type: ResponsePayload::Error,
            payload: Some(payload),
        },
    );

    builder.finish(resp, None);
    builder.finished_data().to_vec()
}

pub fn parse_audit_request(buf: &[u8]) -> Result<AuditRequest<'_>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root::<AuditRequest<'_>>(buf)
}

pub fn parse_audit_response(
    buf: &[u8],
) -> Result<AuditResponse<'_>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root::<AuditResponse<'_>>(buf)
}
