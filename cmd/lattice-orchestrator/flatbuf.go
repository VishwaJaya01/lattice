package main

import (
	"errors"

	latticefb "github.com/VishwaJaya01/lattice/proto/gen/go/lattice/fb"
	flatbuffers "github.com/google/flatbuffers/go"
)

func parseAuditRequest(buf []byte) (*latticefb.AuditRequest, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty flatbuf")
	}
	return latticefb.GetRootAsAuditRequest(buf, 0), nil
}

func parseAuditResponse(buf []byte) (*latticefb.AuditResponse, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty flatbuf")
	}
	return latticefb.GetRootAsAuditResponse(buf, 0), nil
}

func traceContextFromRequest(req *latticefb.AuditRequest) (string, string) {
	return string(req.Traceparent()), string(req.Baggage())
}

func hashBatchFromRequest(req *latticefb.AuditRequest) (*latticefb.HashBatch, string, bool) {
	if req.PayloadType() != latticefb.RequestPayloadHashBatch {
		return nil, "", false
	}
	var tbl flatbuffers.Table
	if !req.Payload(&tbl) {
		return nil, "", false
	}
	batch := &latticefb.HashBatch{}
	batch.Init(tbl.Bytes, tbl.Pos)
	return batch, string(batch.BatchId()), true
}

func controlFromRequest(req *latticefb.AuditRequest) (*latticefb.ControlMessage, bool) {
	if req.PayloadType() != latticefb.RequestPayloadControlMessage {
		return nil, false
	}
	var tbl flatbuffers.Table
	if !req.Payload(&tbl) {
		return nil, false
	}
	msg := &latticefb.ControlMessage{}
	msg.Init(tbl.Bytes, tbl.Pos)
	return msg, true
}

func batchIDFromResponse(resp *latticefb.AuditResponse) (string, bool) {
	var tbl flatbuffers.Table
	switch resp.PayloadType() {
	case latticefb.ResponsePayloadCrackedHash:
		if !resp.Payload(&tbl) {
			return "", false
		}
		ch := &latticefb.CrackedHash{}
		ch.Init(tbl.Bytes, tbl.Pos)
		return string(ch.BatchId()), true
	case latticefb.ResponsePayloadError:
		if !resp.Payload(&tbl) {
			return "", false
		}
		errMsg := &latticefb.Error{}
		errMsg.Init(tbl.Bytes, tbl.Pos)
		return string(errMsg.BatchId()), true
	default:
		return "", false
	}
}

func buildStatusFlatbuf(nodeID string, processed, cracked, inFlight uint64, rate float64, ts uint64, traceparent string, baggage string) []byte {
	b := flatbuffers.NewBuilder(256)
	id := b.CreateString(nodeID)
	var traceOff flatbuffers.UOffsetT
	if traceparent != "" {
		traceOff = b.CreateString(traceparent)
	}
	var bagOff flatbuffers.UOffsetT
	if baggage != "" {
		bagOff = b.CreateString(baggage)
	}

	latticefb.StatusStart(b)
	latticefb.StatusAddNodeId(b, id)
	latticefb.StatusAddStatus(b, latticefb.StatusKindOk)
	latticefb.StatusAddRateHashesPerSec(b, rate)
	latticefb.StatusAddProcessed(b, processed)
	latticefb.StatusAddCracked(b, cracked)
	latticefb.StatusAddInFlight(b, inFlight)
	latticefb.StatusAddTimestampUnixMs(b, ts)
	status := latticefb.StatusEnd(b)

	latticefb.AuditResponseStart(b)
	latticefb.AuditResponseAddPayloadType(b, latticefb.ResponsePayloadStatus)
	latticefb.AuditResponseAddPayload(b, status)
	if traceOff != 0 {
		latticefb.AuditResponseAddTraceparent(b, traceOff)
	}
	if bagOff != 0 {
		latticefb.AuditResponseAddBaggage(b, bagOff)
	}
	resp := latticefb.AuditResponseEnd(b)

	b.Finish(resp)
	return b.FinishedBytes()
}

func buildErrorFlatbuf(code int32, message string, details string, batchID string, traceparent string, baggage string) []byte {
	b := flatbuffers.NewBuilder(256)
	msg := b.CreateString(message)
	var detailsOff flatbuffers.UOffsetT
	if details != "" {
		detailsOff = b.CreateString(details)
	}
	var batchOff flatbuffers.UOffsetT
	if batchID != "" {
		batchOff = b.CreateString(batchID)
	}
	var traceOff flatbuffers.UOffsetT
	if traceparent != "" {
		traceOff = b.CreateString(traceparent)
	}
	var bagOff flatbuffers.UOffsetT
	if baggage != "" {
		bagOff = b.CreateString(baggage)
	}

	latticefb.ErrorStart(b)
	latticefb.ErrorAddCode(b, int32(code))
	latticefb.ErrorAddMessage(b, msg)
	if detailsOff != 0 {
		latticefb.ErrorAddDetails(b, detailsOff)
	}
	if batchOff != 0 {
		latticefb.ErrorAddBatchId(b, batchOff)
	}
	errMsg := latticefb.ErrorEnd(b)

	latticefb.AuditResponseStart(b)
	latticefb.AuditResponseAddPayloadType(b, latticefb.ResponsePayloadError)
	latticefb.AuditResponseAddPayload(b, errMsg)
	if traceOff != 0 {
		latticefb.AuditResponseAddTraceparent(b, traceOff)
	}
	if bagOff != 0 {
		latticefb.AuditResponseAddBaggage(b, bagOff)
	}
	resp := latticefb.AuditResponseEnd(b)

	b.Finish(resp)
	return b.FinishedBytes()
}
