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
	nodeID   string
	received chan string
}

func newMockWorkerServer(nodeID string) *mockWorkerServer {
	return &mockWorkerServer{
		nodeID:   nodeID,
		received: make(chan string, 32),
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
			if err := stream.Send(&latticev1.AuditResponse{
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

	return lis.Addr().String(), worker, stop
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

func sendHashBatch(t *testing.T, stream latticev1.LatticeAudit_AuditStreamClient, batchID string) {
	t.Helper()
	err := stream.Send(&latticev1.AuditRequest{
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

	select {
	case got := <-workerA.received:
		if got != batchID {
			t.Fatalf("worker A got batch %q, want %q", got, batchID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("worker A did not receive initial batch")
	}

	// Kill worker A while client stream remains open.
	stopA()

	waitForRouteWorker(t, state, batchID, wcB.id, 5*time.Second)

	sendHashBatch(t, stream, batchID)

	select {
	case got := <-workerB.received:
		if got != batchID {
			t.Fatalf("worker B got batch %q, want %q", got, batchID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("worker B did not receive reassigned batch")
	}
}
