// Package httpserver exposes Prometheus metrics over HTTP.
package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServer serves the Prometheus registry on an HTTP endpoint.
type MetricsServer struct {
	server *http.Server
	logger *slog.Logger
}

// NewMetricsServer creates an HTTP server exposing /metrics and /healthz.
func NewMetricsServer(address string, registry *prometheus.Registry, logger *slog.Logger) *MetricsServer {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	return &MetricsServer{
		server: &http.Server{
			Addr:              address,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// Start starts the HTTP server in a background goroutine.
func (s *MetricsServer) Start(errCh chan<- error) {
	s.logger.Info("metrics http server started", "address", s.server.Addr)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics http server: %w", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP server.
func (s *MetricsServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
