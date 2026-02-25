// Package metrics creates and updates Prometheus metrics derived from parsed log records.
package metrics

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"bodsch.me/logstream-exporter/internal/config"
	"bodsch.me/logstream-exporter/internal/parser"
	"github.com/prometheus/client_golang/prometheus"
)

const missingLabelValue = "unknown"

// Manager owns Prometheus collectors and applies parsed records to them.
type Manager struct {
	logger          *slog.Logger
	eventCounter    *prometheus.CounterVec
	eventLabelNames []string
	compiled        []*compiledMetric
	parseErrors     prometheus.Counter
	ingestErrors    prometheus.Counter
}

// compiledMetric is the prepared runtime representation of a MetricDefinition.
type compiledMetric struct {
	name   string
	field  string
	labels []string
	kind   config.MetricType

	counter   *prometheus.CounterVec
	gauge     *prometheus.GaugeVec
	histogram *prometheus.HistogramVec
}

// NewManager builds collectors from configuration and registers them in the provided registry.
func NewManager(cfg config.MetricsConfig, registry *prometheus.Registry, logger *slog.Logger) (*Manager, error) {
	m := &Manager{
		logger:          logger,
		eventLabelNames: append([]string(nil), cfg.EventCounter.Labels...),
	}

	m.parseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "logstream_parse_errors_total",
		Help: "Total number of log lines that could not be parsed.",
	})
	m.ingestErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "logstream_ingest_errors_total",
		Help: "Total number of errors while processing parsed log lines.",
	})

	m.eventCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        cfg.EventCounter.Name,
			Help:        cfg.EventCounter.Help,
			ConstLabels: cfg.ConstLabels,
		},
		cfg.EventCounter.Labels,
	)

	if err := registry.Register(m.parseErrors); err != nil {
		return nil, fmt.Errorf("register parse error counter: %w", err)
	}
	if err := registry.Register(m.ingestErrors); err != nil {
		return nil, fmt.Errorf("register ingest error counter: %w", err)
	}
	if err := registry.Register(m.eventCounter); err != nil {
		return nil, fmt.Errorf("register event counter: %w", err)
	}

	for _, def := range cfg.Definitions {
		cm := &compiledMetric{
			name:   def.Name,
			field:  def.Field,
			labels: append([]string(nil), def.Labels...),
			kind:   def.Type,
		}

		switch def.Type {
		case config.MetricTypeCounterAdd:
			cm.counter = prometheus.NewCounterVec(prometheus.CounterOpts{
				Name:        def.Name,
				Help:        def.Help,
				ConstLabels: cfg.ConstLabels,
			}, def.Labels)
			if err := registry.Register(cm.counter); err != nil {
				return nil, fmt.Errorf("register metric %s: %w", def.Name, err)
			}
		case config.MetricTypeGaugeSet:
			cm.gauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name:        def.Name,
				Help:        def.Help,
				ConstLabels: cfg.ConstLabels,
			}, def.Labels)
			if err := registry.Register(cm.gauge); err != nil {
				return nil, fmt.Errorf("register metric %s: %w", def.Name, err)
			}
		case config.MetricTypeHistogram:
			cm.histogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:        def.Name,
				Help:        def.Help,
				ConstLabels: cfg.ConstLabels,
				Buckets:     def.Buckets,
			}, def.Labels)
			if err := registry.Register(cm.histogram); err != nil {
				return nil, fmt.Errorf("register metric %s: %w", def.Name, err)
			}
		default:
			return nil, fmt.Errorf("unsupported metric type %q", def.Type)
		}

		m.compiled = append(m.compiled, cm)
	}

	return m, nil
}

// RecordParseError increments the parse error metric.
func (m *Manager) RecordParseError() {
	m.parseErrors.Inc()
}

// Process applies one parsed record to all configured metrics.
func (m *Manager) Process(record parser.Record) {
	m.eventCounter.WithLabelValues(labelValuesByNames(record, m.eventLabelNames)...).Inc()

	for _, metric := range m.compiled {
		raw, ok := record[metric.field]
		if !ok {
			continue
		}

		value, parseOK := parseNumeric(raw)
		if !parseOK {
			continue
		}

		labels := labelValuesByNames(record, metric.labels)
		switch metric.kind {
		case config.MetricTypeCounterAdd:
			metric.counter.WithLabelValues(labels...).Add(value)
		case config.MetricTypeGaugeSet:
			metric.gauge.WithLabelValues(labels...).Set(value)
		case config.MetricTypeHistogram:
			metric.histogram.WithLabelValues(labels...).Observe(value)
		default:
			m.ingestErrors.Inc()
			m.logger.Warn("unsupported runtime metric type", "metric", metric.name, "type", string(metric.kind))
		}
	}
}

// labelValuesByNames maps configured label fields to Prometheus label values.
func labelValuesByNames(record parser.Record, names []string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		value := strings.TrimSpace(record[name])
		if value == "" || value == "-" {
			value = missingLabelValue
		}
		result = append(result, value)
	}
	return result
}

// parseNumeric parses numeric strings and ignores common placeholder values.
func parseNumeric(raw string) (float64, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "-" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
