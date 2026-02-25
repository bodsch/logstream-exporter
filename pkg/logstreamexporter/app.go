// Package logstreamexporter provides the public application API for the exporter runtime.
package logstreamexporter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"bodsch.me/logstream-exporter/internal/config"
	"bodsch.me/logstream-exporter/internal/httpserver"
	"bodsch.me/logstream-exporter/internal/ingest"
	"bodsch.me/logstream-exporter/internal/metrics"
	"bodsch.me/logstream-exporter/internal/parser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Application is the main runtime object coordinating parser, ingest server, and metric export.
type Application struct {
	cfg           config.Config
	logger        *slog.Logger
	registry      *prometheus.Registry
	parser        parser.Parser
	metrics       *metrics.Manager
	metricsServer *httpserver.MetricsServer
	ingestServer  ingest.Server
}

// New creates a fully initialized exporter application from validated configuration.
func New(cfg config.Config) (*Application, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	logger, err := newLogger(cfg.Logging)
	if err != nil {
		return nil, err
	}

	p, err := newParser(cfg.Parser)
	if err != nil {
		return nil, err
	}

	readTimeout, err := cfg.Server.ReadTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("parse read timeout: %w", err)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	metricManager, err := metrics.NewManager(cfg.Metrics, registry, logger)
	if err != nil {
		return nil, fmt.Errorf("create metrics manager: %w", err)
	}

	app := &Application{
		cfg:           cfg,
		logger:        logger,
		registry:      registry,
		parser:        p,
		metrics:       metricManager,
		metricsServer: httpserver.NewMetricsServer(cfg.Server.MetricsListenAddress, registry, logger),
	}

	app.ingestServer, err = newIngestServer(cfg, readTimeout, logger, app.handleLine)
	if err != nil {
		return nil, err
	}

	app.logger.Info(
		"application initialized",
		"log_transport", strings.ToLower(strings.TrimSpace(cfg.Server.LogTransport)),
		"log_listen", cfg.Server.LogListenAddress,
		"metrics_listen", cfg.Server.MetricsListenAddress,
		"parser_format", p.Format(),
		"payload_format", strings.ToLower(strings.TrimSpace(cfg.Parser.PayloadFormat)),
		"log_level", strings.ToLower(strings.TrimSpace(cfg.Logging.Level)),
		"log_output", strings.ToLower(strings.TrimSpace(cfg.Logging.Format)),
	)

	return app, nil
}

// Run starts all servers and blocks until the context is cancelled or a server returns an error.
func (a *Application) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	a.metricsServer.Start(errCh)
	if err := a.ingestServer.Start(ctx); err != nil {
		return a.shutdownWithCause(err)
	}

	select {
	case <-ctx.Done():
		a.logger.Info("shutdown requested", "reason", ctx.Err())
	case err := <-errCh:
		if err != nil {
			a.logger.Error("server error", "error", err)
			return a.shutdownWithCause(err)
		}
	}

	return a.shutdownWithCause(nil)
}

// handleLine parses a single raw line and updates metrics.
func (a *Application) handleLine(ctx context.Context, line []byte) {
	_ = ctx

	record, err := a.parser.ParseLine(line)
	if err != nil {
		a.metrics.RecordParseError()
		a.logger.Debug(
			"failed to parse line",
			"parser", a.parser.Format(),
			"heuristic_format", heuristicLineFormat(line),
			"error", err,
			"line", truncateForLog(string(line), 512),
		)
		return
	}

	a.metrics.Process(record)

	a.logger.Debug(
		"processed log line",
		"parser", a.parser.Format(),
		"detected_format", firstNonEmpty(
			record[parser.MetaInputFormatKey],
			record["_meta_input_format"],
		),
		"payload_format", firstNonEmpty(
			record[parser.MetaPayloadFormatKey],
			record["_meta_payload_format"],
		),
		"parser_mode", firstNonEmpty(
			record[parser.MetaParserKey],
			record["_meta_parser"],
		),
		"status", record["status"],
		"method", firstNonEmpty(record["request_method"], record["REQUEST_METHOD"]),
		"server_name", firstNonEmpty(record["server_name"], record["http_host"], record["HOST"], record["syslog_host"]),
		"program", firstNonEmpty(record["PROGRAM"], record["syslog_tag"], record["syslogng_program"]),
		"request_uri", firstNonEmpty(record["request_uri"], record["uri"]),
	)
}

// shutdownWithCause stops both servers and merges shutdown errors with an optional root cause.
func (a *Application) shutdownWithCause(cause error) error {
	var errs []error

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.metricsServer.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("shutdown metrics server: %w", err))
	}
	if a.ingestServer != nil {
		if err := a.ingestServer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("shutdown ingest server: %w", err))
		}
	}

	if cause != nil {
		errs = append([]error{cause}, errs...)
	}

	return errors.Join(errs...)
}

// newLogger creates a slog logger according to configuration.
func newLogger(cfg config.LoggingConfig) (*slog.Logger, error) {
	level := new(slog.LevelVar)
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "info":
		level.Set(slog.LevelInfo)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		return nil, fmt.Errorf("unsupported log level %q", cfg.Level)
	}

	handlerOptions := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, handlerOptions)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, handlerOptions)
	default:
		return nil, fmt.Errorf("unsupported log output format %q", cfg.Format)
	}

	return slog.New(handler), nil
}

// newParser builds the requested parser implementation.
func newParser(cfg config.ParserConfig) (parser.Parser, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "auto":
		return parser.NewAutoParser(cfg.PayloadFormat)
	case "json":
		return parser.NewJSONParser(), nil
	case "syslog_rfc3164":
		return parser.NewRFC3164SyslogParser(cfg.PayloadFormat)
	case "syslog_ng_json":
		return parser.NewSyslogNGJSONEnvelopeParser(cfg.PayloadFormat)
	default:
		return nil, fmt.Errorf("unsupported parser format %q", cfg.Format)
	}
}

// newIngestServer builds the configured ingest transport server.
func newIngestServer(cfg config.Config, readTimeout time.Duration, logger *slog.Logger, handler ingest.LineHandler) (ingest.Server, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Server.LogTransport)) {
	case "", "tcp":
		return ingest.NewTCPServer(
			cfg.Server.LogListenAddress,
			readTimeout,
			cfg.Server.LineMaxBytes,
			logger,
			handler,
		), nil

	case "udp":
		return ingest.NewUDPServer(
			cfg.Server.LogListenAddress,
			readTimeout,
			cfg.Server.LineMaxBytes,
			logger,
			handler,
		), nil

	default:
		return nil, fmt.Errorf("unsupported log transport %q", cfg.Server.LogTransport)
	}
}

// truncateForLog limits logged payload size to protect logs from large line content.
func truncateForLog(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

// heuristicLineFormat provides a lightweight best-effort classification for debug logs.
func heuristicLineFormat(line []byte) string {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return "empty"
	}

	if strings.HasPrefix(trimmed, "{") {
		return "json-like"
	}
	if strings.HasPrefix(trimmed, "<") {
		return "syslog-pri-like"
	}
	if looksLikeRFC3164Prefix(trimmed) {
		return "rfc3164-like"
	}
	return "unknown"
}

// looksLikeRFC3164Prefix checks a common RFC3164 timestamp prefix without full parsing.
func looksLikeRFC3164Prefix(value string) bool {
	if len(value) < 16 {
		return false
	}
	months := []string{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	}
	prefix := value[:3]
	for _, month := range months {
		if prefix == month {
			return true
		}
	}
	return false
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
