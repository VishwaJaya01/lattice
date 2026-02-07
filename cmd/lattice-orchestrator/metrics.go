package main

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricClients = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "clients",
		Help:      "Active client streams",
	})
	metricWorkers = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "workers",
		Help:      "Active worker streams",
	})
	metricInflight = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "inflight_batches",
		Help:      "Batches routed but not yet released",
	})
	metricBatchesRouted = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "batches_routed_total",
		Help:      "Total batches routed to workers",
	})
	metricBackpressure = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "backpressure_total",
		Help:      "Dropped messages due to backpressure",
	}, []string{"target"})
	metricWorkerErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "worker_errors_total",
		Help:      "Worker stream errors",
	}, []string{"reason"})
	metricWorkerLastSeen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "lattice",
		Subsystem: "orchestrator",
		Name:      "worker_last_seen_unix",
		Help:      "Last worker activity timestamp (unix seconds)",
	}, []string{"worker"})
)

func startMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(addr, nil); err != nil {
		slog.Error("metrics server failed", "err", err)
	}
}
