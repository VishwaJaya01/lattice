#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = lattice_flatbuf::parse_audit_request(data) {
        match req.payload_type() {
            lattice_flatbuf::fb::RequestPayload::HashBatch => {
                if let Some(batch) = req.payload_as_hash_batch() {
                    let _ = batch.batch_id();
                    if let Some(hashes) = batch.hashes() {
                        let cap = hashes.len().min(32);
                        for i in 0..cap {
                            let hash = hashes.get(i);
                            let _ = lattice_flatbuf::hash16_to_bytes(&hash);
                        }
                    }
                }
            }
            lattice_flatbuf::fb::RequestPayload::ControlMessage => {
                if let Some(control) = req.payload_as_control_message() {
                    let _ = control.kind();
                    let _ = control.reason();
                }
            }
            _ => {}
        }
        let _ = req.traceparent();
        let _ = req.baggage();
    }

    if let Ok(resp) = lattice_flatbuf::parse_audit_response(data) {
        match resp.payload_type() {
            lattice_flatbuf::fb::ResponsePayload::CrackedHash => {
                if let Some(cracked) = resp.payload_as_cracked_hash() {
                    if let Some(hash) = cracked.original_hash() {
                        let _ = lattice_flatbuf::hash16_to_bytes(hash);
                    }
                    let _ = cracked.username();
                    let _ = cracked.plaintext();
                    let _ = cracked.chain_info();
                    let _ = cracked.batch_id();
                }
            }
            lattice_flatbuf::fb::ResponsePayload::Status => {
                if let Some(status) = resp.payload_as_status() {
                    let _ = status.node_id();
                    let _ = status.status();
                    let _ = status.rate_hashes_per_sec();
                }
            }
            lattice_flatbuf::fb::ResponsePayload::Error => {
                if let Some(err) = resp.payload_as_error() {
                    let _ = err.code();
                    let _ = err.message();
                    let _ = err.details();
                    let _ = err.batch_id();
                }
            }
            _ => {}
        }
        let _ = resp.traceparent();
        let _ = resp.baggage();
    }
});
