package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	latticev1 "github.com/VishwaJaya01/lattice/proto/latticev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockWorkerServer struct {
	latticev1.UnimplementedLatticeAuditServer
	nodeID          string
	received        chan string
	receivedTrace   chan string
	receivedBaggage chan string
}

func newMockWorkerServer(nodeID string) *mockWorkerServer {
	return &mockWorkerServer{
		nodeID:          nodeID,
		received:        make(chan string, 32),
		receivedTrace:   make(chan string, 32),
		receivedBaggage: make(chan string, 32),
	}
}

func (m *mockWorkerServer) AuditStream(stream latticev1.LatticeAudit_AuditStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch payload := req.Payload.(type) {
		case *latticev1.AuditRequest_HashBatch:
			select {
			case m.received <- payload.HashBatch.BatchId:
			default:
			}
			select {
			case m.receivedTrace <- req.Traceparent:
			default:
			}
			select {
			case m.receivedBaggage <- req.Baggage:
			default:
			}
			if err := stream.Send(&latticev1.AuditResponse{
				Traceparent: req.Traceparent,
				Baggage:     req.Baggage,
				Payload: &latticev1.AuditResponse_Status{
					Status: &latticev1.Status{
						NodeId:          m.nodeID,
						Status:          "OK",
						TimestampUnixMs: uint64(time.Now().UnixMilli()),
					},
				},
			}); err != nil {
				return err
			}
		case *latticev1.AuditRequest_Control:
			if err := stream.Send(&latticev1.AuditResponse{
				Traceparent: req.Traceparent,
				Baggage:     req.Baggage,
				Payload: &latticev1.AuditResponse_Status{
					Status: &latticev1.Status{
						NodeId:          m.nodeID,
						Status:          "OK",
						TimestampUnixMs: uint64(time.Now().UnixMilli()),
					},
				},
			}); err != nil {
				return err
			}
		}
	}
}

func startMockWorker(t *testing.T, nodeID string) (addr string, worker *mockWorkerServer, stop func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock worker: %v", err)
	}

	worker, stop = serveMockWorker(t, nodeID, lis)
	return lis.Addr().String(), worker, stop
}

func startMockWorkerAtAddr(t *testing.T, nodeID, addr string) (*mockWorkerServer, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen mock worker: %v", err)
	}

	worker, stop := serveMockWorker(t, nodeID, lis)
	return worker, stop
}

func serveMockWorker(t *testing.T, nodeID string, lis net.Listener) (worker *mockWorkerServer, stop func()) {
	t.Helper()

	grpcServer := grpc.NewServer()
	worker = newMockWorkerServer(nodeID)
	latticev1.RegisterLatticeAuditServer(grpcServer, worker)

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			grpcServer.Stop()
			_ = lis.Close()
		})
	}
	t.Cleanup(stop)

	return worker, stop
}

func connectWorkerForTest(t *testing.T, state *serverState, workerID, addr string) *workerConn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial worker %s: %v", workerID, err)
	}

	client := latticev1.NewLatticeAuditClient(conn)
	stream, err := client.AuditStream(context.Background())
	if err != nil {
		_ = conn.Close()
		t.Fatalf("open worker stream %s: %v", workerID, err)
	}

	now := time.Now().Unix()
	worker := &workerConn{
		id:     workerID,
		addr:   addr,
		conn:   conn,
		stream: stream,
		sendCh: make(chan *latticev1.AuditRequest, 64),
		done:   make(chan struct{}),
	}
	worker.alive.Store(true)
	worker.lastSeen.Store(now)
	state.addWorker(worker)

	go workerSendLoop(state, worker)
	go workerRecvLoop(state, worker)

	return worker
}

func findBatchIDForWorker(t *testing.T, state *serverState, workerID string) string {
	t.Helper()
	for i := 0; i < 20000; i++ {
		batchID := fmt.Sprintf("failover-batch-%d", i)
		worker, ok := state.pickWorkerFor(batchID)
		if ok && worker.id == workerID {
			return batchID
		}
	}
	t.Fatalf("could not find route key for worker %s", workerID)
	return ""
}

func waitForRouteWorker(t *testing.T, state *serverState, batchID, workerID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		worker, ok := state.pickWorkerFor(batchID)
		if ok && worker.id == workerID {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for route %q to worker %s", batchID, workerID)
}

func waitForWorkerCount(t *testing.T, state *serverState, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if state.workerCount() == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for worker count=%d, got %d", want, state.workerCount())
}

func sendHashBatch(t *testing.T, stream latticev1.LatticeAudit_AuditStreamClient, batchID string) {
	t.Helper()
	sendHashBatchWithTrace(t, stream, batchID, "", "")
}

func sendHashBatchWithTrace(
	t *testing.T,
	stream latticev1.LatticeAudit_AuditStreamClient,
	batchID string,
	traceparent string,
	baggage string,
) {
	t.Helper()
	err := stream.Send(&latticev1.AuditRequest{
		Traceparent: traceparent,
		Baggage:     baggage,
		Payload: &latticev1.AuditRequest_HashBatch{
			HashBatch: &latticev1.HashBatch{
				BatchId:    batchID,
				RawHashes:  [][]byte{make([]byte, 16)},
				SentUnixMs: uint64(time.Now().UnixMilli()),
			},
		},
	})
	if err != nil {
		t.Fatalf("send batch %s: %v", batchID, err)
	}
}

func waitForBatchReceived(t *testing.T, ch <-chan string, want string, timeout time.Duration, source string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("%s got batch %q, want %q", source, got, want)
		}
	case <-time.After(timeout):
		t.Fatalf("%s did not receive batch", source)
	}
}

func TestAuditStreamReassignsAfterWorkerFailure(t *testing.T) {
	state := newServerState("orchestrator-test", 64)

	addrA, workerA, stopA := startMockWorker(t, "worker-a")
	addrB, workerB, _ := startMockWorker(t, "worker-b")

	wcA := connectWorkerForTest(t, state, "worker-a", addrA)
	wcB := connectWorkerForTest(t, state, "worker-b", addrB)
	t.Cleanup(func() {
		state.removeWorker(wcA.id)
		state.removeWorker(wcB.id)
	})

	orchLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen orchestrator: %v", err)
	}
	orchServer := grpc.NewServer()
	latticev1.RegisterLatticeAuditServer(orchServer, &auditServer{state: state})
	go func() {
		_ = orchServer.Serve(orchLis)
	}()
	t.Cleanup(func() {
		orchServer.Stop()
		_ = orchLis.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	clientConn, err := grpc.DialContext(
		ctx,
		orchLis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial orchestrator: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	client := latticev1.NewLatticeAuditClient(clientConn)
	stream, err := client.AuditStream(ctx)
	if err != nil {
		t.Fatalf("open client stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.CloseSend() })

	batchID := findBatchIDForWorker(t, state, wcA.id)
	sendHashBatch(t, stream, batchID)
	waitForBatchReceived(t, workerA.received, batchID, 5*time.Second, "worker A")

	// Kill worker A while client stream remains open.
	stopA()

	waitForRouteWorker(t, state, batchID, wcB.id, 5*time.Second)

	sendHashBatch(t, stream, batchID)
	waitForBatchReceived(t, workerB.received, batchID, 5*time.Second, "worker B")
}

func TestAuditStreamPropagatesTraceContext(t *testing.T) {
	state := newServerState("orchestrator-test", 64)

	addr, worker, _ := startMockWorker(t, "worker-trace")
	wc := connectWorkerForTest(t, state, "worker-trace", addr)
	t.Cleanup(func() {
		state.removeWorker(wc.id)
	})

	orchLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen orchestrator: %v", err)
	}
	orchServer := grpc.NewServer()
	latticev1.RegisterLatticeAuditServer(orchServer, &auditServer{state: state})
	go func() {
		_ = orchServer.Serve(orchLis)
	}()
	t.Cleanup(func() {
		orchServer.Stop()
		_ = orchLis.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	clientConn, err := grpc.DialContext(
		ctx,
		orchLis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial orchestrator: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	client := latticev1.NewLatticeAuditClient(clientConn)
	stream, err := client.AuditStream(ctx)
	if err != nil {
		t.Fatalf("open client stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.CloseSend() })

	batchID := findBatchIDForWorker(t, state, wc.id)
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	baggage := "engagement=lattice,operator=jayasankha"

	sendHashBatchWithTrace(t, stream, batchID, traceparent, baggage)
	waitForBatchReceived(t, worker.received, batchID, 5*time.Second, "worker")

	select {
	case got := <-worker.receivedTrace:
		if got != traceparent {
			t.Fatalf("worker got traceparent %q, want %q", got, traceparent)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("worker did not receive traceparent")
	}

	select {
	case got := <-worker.receivedBaggage:
		if got != baggage {
			t.Fatalf("worker got baggage %q, want %q", got, baggage)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("worker did not receive baggage")
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("did not receive response with propagated trace context")
		default:
			resp, err := stream.Recv()
			if err != nil {
				t.Fatalf("recv response: %v", err)
			}
			if resp.Traceparent == traceparent && resp.Baggage == baggage {
				return
			}
		}
	}
}

func TestWorkerConnectorReconnectsAfterRestart(t *testing.T) {
	state := newServerState("orchestrator-test", 64)

	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve addr: %v", err)
	}
	addr := reserve.Addr().String()
	_ = reserve.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dialer := grpcWorkerDialer(grpc.WithTransportCredentials(insecure.NewCredentials()))
	go runWorkerConnector(ctx, state, "worker-1", addr, 0, dialer)

	workerA, stopA := startMockWorkerAtAddr(t, "worker-a", addr)
	waitForWorkerCount(t, state, 1, 5*time.Second)
	batchID := findBatchIDForWorker(t, state, "worker-1")

	orchLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen orchestrator: %v", err)
	}
	orchServer := grpc.NewServer()
	latticev1.RegisterLatticeAuditServer(orchServer, &auditServer{state: state})
	go func() {
		_ = orchServer.Serve(orchLis)
	}()
	t.Cleanup(func() {
		orchServer.Stop()
		_ = orchLis.Close()
	})

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer clientCancel()

	clientConn, err := grpc.DialContext(
		clientCtx,
		orchLis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial orchestrator: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	client := latticev1.NewLatticeAuditClient(clientConn)
	stream, err := client.AuditStream(clientCtx)
	if err != nil {
		t.Fatalf("open client stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.CloseSend() })

	sendHashBatch(t, stream, batchID)
	waitForBatchReceived(t, workerA.received, batchID, 5*time.Second, "worker A")

	stopA()
	waitForWorkerCount(t, state, 0, 5*time.Second)

	workerB, _ := startMockWorkerAtAddr(t, "worker-b", addr)
	waitForWorkerCount(t, state, 1, 5*time.Second)
	waitForRouteWorker(t, state, batchID, "worker-1", 5*time.Second)

	sendHashBatch(t, stream, batchID)
	waitForBatchReceived(t, workerB.received, batchID, 5*time.Second, "worker B")
}
