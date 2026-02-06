package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	latticev1 "github.com/VishwaJaya01/lattice/proto/latticev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type config struct {
	addr             string
	metricsAddr      string
	nodeID           string
	tlsCertPath      string
	tlsKeyPath       string
	tlsClientCAPath  string
	workerAddrs      multiFlag
	workerCAPath     string
	workerServerName string
	workerHeartbeat  time.Duration
	workerTimeout    time.Duration
	hashReplicas     int
	otelEndpoint     string
	otelInsecure     bool
}

type auditServer struct {
	latticev1.UnimplementedLatticeAuditServer
	state *serverState
}

type serverState struct {
	nodeID        string
	ring          *hashRing
	mu            sync.RWMutex
	workers       []*workerConn
	clients       map[string]*clientConn
	batchToClient map[string]string
	clientCounter atomic.Uint64
	batchCounter  atomic.Uint64
	workerCounter atomic.Uint64
}

type workerConn struct {
	id       string
	addr     string
	conn     *grpc.ClientConn
	stream   latticev1.LatticeAudit_AuditStreamClient
	sendCh   chan *latticev1.AuditRequest
	done     chan struct{}
	alive    atomic.Bool
	lastSeen atomic.Int64
}

type clientConn struct {
	id     string
	sendCh chan *latticev1.AuditResponse
}

var (
	errNoWorkers          = errors.New("no workers available")
	errWorkerNotAlive     = errors.New("worker not alive")
	errWorkerBackpressure = errors.New("worker backpressure")
)

func main() {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", ":50051", "listen address")
	flag.StringVar(&cfg.metricsAddr, "metrics-addr", ":2112", "metrics bind address")
	flag.StringVar(&cfg.nodeID, "node-id", "orchestrator-1", "node identifier")
	flag.StringVar(&cfg.tlsCertPath, "tls-cert", "", "server TLS cert (PEM)")
	flag.StringVar(&cfg.tlsKeyPath, "tls-key", "", "server TLS key (PEM)")
	flag.StringVar(&cfg.tlsClientCAPath, "tls-client-ca", "", "client CA (PEM)")
	flag.Var(&cfg.workerAddrs, "worker", "worker address (repeatable)")
	flag.StringVar(&cfg.workerCAPath, "worker-ca", "", "worker CA (PEM); defaults to --tls-client-ca")
	flag.StringVar(&cfg.workerServerName, "worker-server-name", "lattice-worker", "worker TLS server name (SNI)")
	flag.DurationVar(&cfg.workerHeartbeat, "worker-heartbeat", 2*time.Second, "worker heartbeat interval")
	flag.DurationVar(&cfg.workerTimeout, "worker-timeout", 0, "worker liveness timeout before eviction (default: 3x --worker-heartbeat)")
	flag.IntVar(&cfg.hashReplicas, "hash-replicas", 128, "virtual nodes per worker")
	flag.StringVar(&cfg.otelEndpoint, "otel-endpoint", "", "OTLP gRPC endpoint (host:port)")
	flag.BoolVar(&cfg.otelInsecure, "otel-insecure", false, "disable OTLP TLS")
	flag.Parse()

	if cfg.tlsCertPath == "" || cfg.tlsKeyPath == "" || cfg.tlsClientCAPath == "" {
		slog.Error("mTLS required: --tls-cert, --tls-key, --tls-client-ca")
		os.Exit(2)
	}

	if cfg.workerCAPath == "" {
		cfg.workerCAPath = cfg.tlsClientCAPath
	}
	if cfg.workerTimeout == 0 && cfg.workerHeartbeat > 0 {
		cfg.workerTimeout = cfg.workerHeartbeat * 3
	}

	if cfg.metricsAddr != "" {
		go startMetricsServer(cfg.metricsAddr)
	}

	shutdown, err := initTracing(context.Background(), cfg.otelEndpoint, cfg.otelInsecure, "lattice-orchestrator")
	if err != nil {
		slog.Error("tracing init failed", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			slog.Error("tracing shutdown failed", "err", err)
		}
	}()

	creds, err := loadServerTLS(cfg.tlsCertPath, cfg.tlsKeyPath, cfg.tlsClientCAPath)
	if err != nil {
		slog.Error("TLS setup failed", "err", err)
		os.Exit(1)
	}

	state := newServerState(cfg.nodeID, cfg.hashReplicas)

	if len(cfg.workerAddrs) > 0 {
		workerTLS, err := loadClientTLS(cfg.tlsCertPath, cfg.tlsKeyPath, cfg.workerCAPath, cfg.workerServerName)
		if err != nil {
			slog.Error("worker TLS setup failed", "err", err)
			os.Exit(1)
		}
		connectWorkers(state, cfg.workerAddrs, workerTLS, cfg.workerHeartbeat)
		if cfg.workerTimeout > 0 {
			go workerHealthLoop(state, cfg.workerTimeout)
		}
	}

	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		slog.Error("listen failed", "err", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(grpcServerOptions(creds)...)
	latticev1.RegisterLatticeAuditServer(grpcServer, &auditServer{state: state})

	slog.Info("lattice-orchestrator listening", "addr", cfg.addr, "node_id", cfg.nodeID)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}

func loadServerTLS(certPath, keyPath, clientCAPath string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	caBytes, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("append client CA")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsConfig), nil
}

func loadClientTLS(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read worker CA: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("append worker CA")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func newServerState(nodeID string, replicas int) *serverState {
	return &serverState{
		nodeID:        nodeID,
		ring:          newHashRing(replicas),
		clients:       make(map[string]*clientConn),
		batchToClient: make(map[string]string),
	}
}

func connectWorkers(state *serverState, addrs []string, tlsConfig *tls.Config, heartbeat time.Duration) {
	for _, addr := range addrs {
		addr := addr
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := grpc.DialContext(ctx, addr, grpcClientOptions(credentials.NewTLS(tlsConfig))...)
		cancel()
		if err != nil {
			slog.Error("worker dial failed", "addr", addr, "err", err)
			metricWorkerErrors.WithLabelValues("dial").Inc()
			continue
		}

		client := latticev1.NewLatticeAuditClient(conn)
		stream, err := client.AuditStream(context.Background())
		if err != nil {
			slog.Error("worker stream failed", "addr", addr, "err", err)
			metricWorkerErrors.WithLabelValues("stream").Inc()
			_ = conn.Close()
			continue
		}

		workerID := fmt.Sprintf("worker-%d", state.workerCounter.Add(1))
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
		if heartbeat > 0 {
			go workerHeartbeatLoop(state, worker, heartbeat)
		}
	}
}

func workerSendLoop(state *serverState, worker *workerConn) {
	defer state.removeWorker(worker.id)
	for {
		select {
		case <-worker.done:
			return
		case req := <-worker.sendCh:
			if req == nil || !worker.alive.Load() {
				continue
			}
			if err := worker.stream.Send(req); err != nil {
				slog.Error("worker send failed", "worker", worker.id, "err", err)
				metricWorkerErrors.WithLabelValues("send").Inc()
				return
			}
		}
	}
}

func workerRecvLoop(state *serverState, worker *workerConn) {
	defer state.removeWorker(worker.id)
	for {
		resp, err := worker.stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			slog.Error("worker recv failed", "worker", worker.id, "err", err)
			metricWorkerErrors.WithLabelValues("recv").Inc()
			return
		}
		worker.lastSeen.Store(time.Now().Unix())
		metricWorkerLastSeen.WithLabelValues(worker.id).Set(float64(time.Now().Unix()))
		state.handleWorkerResponse(resp)
	}
}

func workerHeartbeatLoop(state *serverState, worker *workerConn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-worker.done:
			return
		case <-ticker.C:
			req := &latticev1.AuditRequest{
				Payload: &latticev1.AuditRequest_Control{Control: &latticev1.ControlMessage{
					Kind:   latticev1.ControlKind_CONTROL_KIND_UNSPECIFIED,
					Reason: "heartbeat",
				}},
			}
			_ = enqueueWorker(worker, req)
		}
	}
}

func workerHealthLoop(state *serverState, timeout time.Duration) {
	interval := timeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		for _, worker := range state.snapshotWorkers() {
			lastSeen := worker.lastSeen.Load()
			if now-lastSeen <= int64(timeout.Seconds()) {
				continue
			}
			slog.Warn(
				"worker heartbeat timeout",
				"worker", worker.id,
				"addr", worker.addr,
				"last_seen_unix", lastSeen,
				"timeout", timeout,
			)
			metricWorkerErrors.WithLabelValues("heartbeat_timeout").Inc()
			state.removeWorker(worker.id)
		}
	}
}

func (s *serverState) addWorker(worker *workerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workers = append(s.workers, worker)
	s.ring.rebuild(s.workers)
	metricWorkers.Set(float64(len(s.workers)))
	slog.Info("worker registered", "worker", worker.id, "addr", worker.addr)
}

func (s *serverState) removeWorker(workerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.workers {
		if w.id == workerID {
			w.alive.Store(false)
			select {
			case <-w.done:
			default:
				close(w.done)
			}
			if w.conn != nil {
				_ = w.conn.Close()
			}
			s.workers = append(s.workers[:i], s.workers[i+1:]...)
			s.ring.rebuild(s.workers)
			metricWorkers.Set(float64(len(s.workers)))
			slog.Warn("worker removed", "worker", workerID)
			return
		}
	}
}

func (s *serverState) pickWorkerFor(key string) (*workerConn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ring.pick(key)
}

func (s *serverState) pickWorkerForExcluding(key string, excluded map[string]struct{}) (*workerConn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ring.pickExcluding(key, excluded)
}

func (s *serverState) workerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.workers)
}

func (s *serverState) snapshotWorkers() []*workerConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*workerConn, len(s.workers))
	copy(out, s.workers)
	return out
}

func (s *serverState) registerClient() *clientConn {
	id := fmt.Sprintf("client-%d", s.clientCounter.Add(1))
	client := &clientConn{
		id:     id,
		sendCh: make(chan *latticev1.AuditResponse, 64),
	}
	s.mu.Lock()
	s.clients[id] = client
	metricClients.Set(float64(len(s.clients)))
	s.mu.Unlock()
	return client
}

func (s *serverState) unregisterClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, clientID)
	metricClients.Set(float64(len(s.clients)))
	for batchID, cid := range s.batchToClient {
		if cid == clientID {
			delete(s.batchToClient, batchID)
		}
	}
	metricInflight.Set(float64(len(s.batchToClient)))
	if len(s.clients) == 0 {
		s.batchToClient = make(map[string]string)
	}
}

func (s *serverState) routeBatch(batchID, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchToClient[batchID] = clientID
	metricInflight.Set(float64(len(s.batchToClient)))
	metricBatchesRouted.Inc()
}

func (s *serverState) clientForBatch(batchID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID, ok := s.batchToClient[batchID]
	return clientID, ok
}

func (s *serverState) sendToClient(clientID string, resp *latticev1.AuditResponse) {
	s.mu.RLock()
	client := s.clients[clientID]
	s.mu.RUnlock()
	if client == nil {
		return
	}
	select {
	case client.sendCh <- resp:
	default:
		metricBackpressure.WithLabelValues("client").Inc()
		slog.Warn("dropping response (client backpressure)", "client", clientID)
	}
}

func (s *serverState) broadcast(resp *latticev1.AuditResponse) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, client := range s.clients {
		select {
		case client.sendCh <- resp:
		default:
			metricBackpressure.WithLabelValues("client").Inc()
			slog.Warn("dropping response (client backpressure)", "client", id)
		}
	}
}

func (s *serverState) nextBatchID() string {
	return fmt.Sprintf("batch-%d", s.batchCounter.Add(1))
}

func (s *serverState) handleWorkerResponse(resp *latticev1.AuditResponse) {
	switch payload := resp.Payload.(type) {
	case *latticev1.AuditResponse_CrackedHash:
		batchID := payload.CrackedHash.BatchId
		if batchID != "" {
			if clientID, ok := s.clientForBatch(batchID); ok {
				s.sendToClient(clientID, resp)
				return
			}
		}
		s.broadcast(resp)
	case *latticev1.AuditResponse_Error:
		batchID := payload.Error.BatchId
		if batchID != "" {
			if clientID, ok := s.clientForBatch(batchID); ok {
				s.sendToClient(clientID, resp)
				return
			}
		}
		s.broadcast(resp)
	case *latticev1.AuditResponse_Status:
		s.broadcast(resp)
	case *latticev1.AuditResponse_Flatbuf:
		fbResp, err := parseAuditResponse(payload.Flatbuf)
		if err != nil {
			s.broadcast(resp)
			return
		}
		if batchID, ok := batchIDFromResponse(fbResp); ok && batchID != "" {
			if clientID, ok := s.clientForBatch(batchID); ok {
				s.sendToClient(clientID, resp)
				return
			}
		}
		s.broadcast(resp)
	default:
		s.broadcast(resp)
	}
}

func (s *auditServer) enqueueWithFailover(routeKey string, req *latticev1.AuditRequest) error {
	attempts := s.state.workerCount()
	if attempts == 0 {
		return errNoWorkers
	}

	excluded := make(map[string]struct{}, attempts)
	var lastErr error
	failedAttempts := 0

	for i := 0; i < attempts; i++ {
		worker, ok := s.state.pickWorkerForExcluding(routeKey, excluded)
		if !ok {
			break
		}
		excluded[worker.id] = struct{}{}

		if err := enqueueWorker(worker, req); err != nil {
			lastErr = err
			failedAttempts++
			if errors.Is(err, errWorkerNotAlive) {
				s.state.removeWorker(worker.id)
			}
			continue
		}

		if failedAttempts > 0 {
			metricWorkerErrors.WithLabelValues("reroute").Inc()
			slog.Warn("request rerouted after worker failure", "route_key", routeKey, "worker", worker.id, "attempts", failedAttempts+1)
		}
		return nil
	}

	if lastErr == nil {
		return errNoWorkers
	}
	return lastErr
}

func routeErrorStatus(err error) (int32, string) {
	switch {
	case errors.Is(err, errWorkerBackpressure):
		return 429, errWorkerBackpressure.Error()
	case errors.Is(err, errNoWorkers), errors.Is(err, errWorkerNotAlive):
		return 503, errNoWorkers.Error()
	default:
		return 500, err.Error()
	}
}

func (s *auditServer) AuditStream(stream latticev1.LatticeAudit_AuditStreamServer) error {
	client := s.state.registerClient()
	defer s.state.unregisterClient(client.id)

	ctx := stream.Context()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case resp := <-client.sendCh:
				if resp == nil {
					continue
				}
				if err := stream.Send(resp); err != nil {
					slog.Error("client send failed", "client", client.id, "err", err)
					return
				}
			}
		}
	}()

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
			batch := payload.HashBatch
			if batch.BatchId == "" {
				batch.BatchId = s.state.nextBatchID()
			}
			s.state.routeBatch(batch.BatchId, client.id)
			if err := s.enqueueWithFailover(batch.BatchId, req); err != nil {
				code, message := routeErrorStatus(err)
				s.state.sendToClient(client.id, &latticev1.AuditResponse{
					Traceparent: req.Traceparent,
					Baggage:     req.Baggage,
					Payload: &latticev1.AuditResponse_Error{Error: &latticev1.Error{
						Code:    code,
						Message: message,
						Details: err.Error(),
						BatchId: batch.BatchId,
					}},
				})
			}
		case *latticev1.AuditRequest_Control:
			status := &latticev1.Status{
				NodeId:           s.state.nodeID,
				Status:           "OK",
				RateHashesPerSec: 0,
				Processed:        0,
				Cracked:          0,
				InFlight:         0,
				TimestampUnixMs:  uint64(time.Now().UnixMilli()),
			}
			s.state.sendToClient(client.id, &latticev1.AuditResponse{
				Traceparent: req.Traceparent,
				Baggage:     req.Baggage,
				Payload:     &latticev1.AuditResponse_Status{Status: status},
			})
		case *latticev1.AuditRequest_Flatbuf:
			fbReq, err := parseAuditRequest(payload.Flatbuf)
			if err != nil {
				errBuf := buildErrorFlatbuf(400, "flatbuf parse failed", err.Error(), "", "", "")
				s.state.sendToClient(client.id, &latticev1.AuditResponse{
					Payload: &latticev1.AuditResponse_Flatbuf{Flatbuf: errBuf},
				})
				continue
			}
			traceparent, baggage := traceContextFromRequest(fbReq)

			if _, batchID, ok := hashBatchFromRequest(fbReq); ok {
				if batchID == "" {
					errBuf := buildErrorFlatbuf(400, "missing batch_id", "", "", traceparent, baggage)
					s.state.sendToClient(client.id, &latticev1.AuditResponse{
						Traceparent: traceparent,
						Baggage:     baggage,
						Payload:     &latticev1.AuditResponse_Flatbuf{Flatbuf: errBuf},
					})
					continue
				}

				s.state.routeBatch(batchID, client.id)
				forward := &latticev1.AuditRequest{
					Payload: &latticev1.AuditRequest_Flatbuf{Flatbuf: payload.Flatbuf},
				}
				if err := s.enqueueWithFailover(batchID, forward); err != nil {
					code, message := routeErrorStatus(err)
					errBuf := buildErrorFlatbuf(code, message, err.Error(), batchID, traceparent, baggage)
					s.state.sendToClient(client.id, &latticev1.AuditResponse{
						Traceparent: traceparent,
						Baggage:     baggage,
						Payload:     &latticev1.AuditResponse_Flatbuf{Flatbuf: errBuf},
					})
				}
				continue
			}

			if _, ok := controlFromRequest(fbReq); ok {
				statusBuf := buildStatusFlatbuf(
					s.state.nodeID,
					0,
					0,
					0,
					0,
					uint64(time.Now().UnixMilli()),
					traceparent,
					baggage,
				)
				s.state.sendToClient(client.id, &latticev1.AuditResponse{
					Traceparent: traceparent,
					Baggage:     baggage,
					Payload:     &latticev1.AuditResponse_Flatbuf{Flatbuf: statusBuf},
				})
				continue
			}
		default:
			// Ignore unknown payloads.
		}
	}
}

func enqueueWorker(worker *workerConn, req *latticev1.AuditRequest) error {
	if !worker.alive.Load() {
		return errWorkerNotAlive
	}
	select {
	case worker.sendCh <- req:
		return nil
	default:
		metricBackpressure.WithLabelValues("worker").Inc()
		return errWorkerBackpressure
	}
}
