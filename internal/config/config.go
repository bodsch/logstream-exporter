// Package config provides application configuration loading, defaults, and validation.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// Config contains the complete runtime configuration of the exporter.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Parser  ParserConfig  `yaml:"parser"`
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics"`
}

// ServerConfig contains network settings for ingest and metrics endpoints.
type ServerConfig struct {
	LogListenAddress     string `yaml:"log_listen_address"`
	LogTransport         string `yaml:"log_transport"`
	MetricsListenAddress string `yaml:"metrics_listen_address"`
	ReadTimeout          string `yaml:"read_timeout"`
	LineMaxBytes         int    `yaml:"line_max_bytes"`
}

// ParserConfig contains parser format settings.
type ParserConfig struct {
	Format        string `yaml:"format"`
	PayloadFormat string `yaml:"payload_format"`
}

// LoggingConfig contains log level and output formatting settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig contains all metric definitions and label settings.
type MetricsConfig struct {
	ConstLabels  map[string]string  `yaml:"const_labels"`
	EventCounter EventCounterConfig `yaml:"event_counter"`
	Definitions  []MetricDefinition `yaml:"definitions"`
}

// EventCounterConfig defines the base event counter for processed log lines.
type EventCounterConfig struct {
	Name   string   `yaml:"name"`
	Help   string   `yaml:"help"`
	Labels []string `yaml:"labels"`
}

// MetricDefinition defines a single dynamic metric derived from one log field.
type MetricDefinition struct {
	Name    string     `yaml:"name"`
	Help    string     `yaml:"help"`
	Field   string     `yaml:"field"`
	Type    MetricType `yaml:"type"`
	Labels  []string   `yaml:"labels"`
	Buckets []float64  `yaml:"buckets,omitempty"`
}

// MetricType defines supported metric collector types for field extraction.
type MetricType string

const (
	// MetricTypeCounterAdd adds the numeric field value to a CounterVec.
	MetricTypeCounterAdd MetricType = "counter_add"
	// MetricTypeGaugeSet sets the numeric field value on a GaugeVec.
	MetricTypeGaugeSet MetricType = "gauge_set"
	// MetricTypeHistogram observes the numeric field value in a HistogramVec.
	MetricTypeHistogram MetricType = "histogram"
)

// Default returns a complete default configuration.
func Default() Config {
	return Config{
		Server: ServerConfig{
			LogListenAddress:     "127.0.0.1:2212",
			LogTransport:         "tcp",
			MetricsListenAddress: "127.0.0.1:9212",
			ReadTimeout:          "30s",
			LineMaxBytes:         1024 * 1024,
		},
		Parser: ParserConfig{
			Format:        "auto",
			PayloadFormat: "json",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Metrics: MetricsConfig{
			ConstLabels: map[string]string{},
			EventCounter: EventCounterConfig{
				Name:   "logstream_events_total",
				Help:   "Total number of processed log events.",
				Labels: []string{"status", "request_method", "server_name"},
			},
			Definitions: []MetricDefinition{
				{
					Name:    "logstream_request_time_seconds",
					Help:    "Observed request processing time derived from the log field request_time.",
					Field:   "request_time",
					Type:    MetricTypeHistogram,
					Labels:  []string{"status", "request_method", "server_name"},
					Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
				},
				{
					Name:   "logstream_bytes_sent_total",
					Help:   "Total bytes sent derived from the log field bytes_sent.",
					Field:  "bytes_sent",
					Type:   MetricTypeCounterAdd,
					Labels: []string{"status", "server_name"},
				},
			},
		},
	}
}

// LoadFile reads a YAML configuration file and overlays it on defaults.
func LoadFile(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	return cfg, nil
}

// Validate checks whether the configuration is internally consistent.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.LogListenAddress == "" {
		errs = append(errs, errors.New("server.log_listen_address must not be empty"))
	}
	if c.Server.MetricsListenAddress == "" {
		errs = append(errs, errors.New("server.metrics_listen_address must not be empty"))
	}
	if c.Server.LineMaxBytes <= 0 {
		errs = append(errs, errors.New("server.line_max_bytes must be > 0"))
	}
	if _, err := time.ParseDuration(c.Server.ReadTimeout); err != nil {
		errs = append(errs, fmt.Errorf("server.read_timeout invalid: %w", err))
	}
	if !isOneOfCI(c.Server.LogTransport, "tcp", "udp") {
		errs = append(errs, fmt.Errorf("server.log_transport %q is invalid (supported: tcp, udp)", c.Server.LogTransport))
	}

	switch strings.ToLower(strings.TrimSpace(c.Parser.Format)) {
	case "auto", "json", "syslog_rfc3164", "syslog_ng_json":
	default:
		errs = append(errs, fmt.Errorf("parser.format %q is not supported (supported: auto, json, syslog_rfc3164, syslog_ng_json)", c.Parser.Format))
	}

	switch strings.ToLower(strings.TrimSpace(c.Parser.PayloadFormat)) {
	case "", "json", "raw":
	default:
		errs = append(errs, fmt.Errorf("parser.payload_format %q is invalid (supported: json, raw)", c.Parser.PayloadFormat))
	}

	if !isOneOfCI(c.Logging.Level, "debug", "info", "warn", "error") {
		errs = append(errs, fmt.Errorf("logging.level %q is invalid", c.Logging.Level))
	}
	if !isOneOfCI(c.Logging.Format, "text", "json") {
		errs = append(errs, fmt.Errorf("logging.format %q is invalid", c.Logging.Format))
	}

	if err := validateMetricName(c.Metrics.EventCounter.Name); err != nil {
		errs = append(errs, fmt.Errorf("metrics.event_counter.name: %w", err))
	}
	if c.Metrics.EventCounter.Help == "" {
		errs = append(errs, errors.New("metrics.event_counter.help must not be empty"))
	}

	for i := range c.Metrics.Definitions {
		def := c.Metrics.Definitions[i]
		if err := validateMetricName(def.Name); err != nil {
			errs = append(errs, fmt.Errorf("metrics.definitions[%d].name: %w", i, err))
		}
		if strings.TrimSpace(def.Field) == "" {
			errs = append(errs, fmt.Errorf("metrics.definitions[%d].field must not be empty", i))
		}
		if strings.TrimSpace(def.Help) == "" {
			errs = append(errs, fmt.Errorf("metrics.definitions[%d].help must not be empty", i))
		}
		switch def.Type {
		case MetricTypeCounterAdd, MetricTypeGaugeSet, MetricTypeHistogram:
		default:
			errs = append(errs, fmt.Errorf("metrics.definitions[%d].type %q is invalid", i, def.Type))
		}
		if def.Type == MetricTypeHistogram && len(def.Buckets) == 0 {
			c.Metrics.Definitions[i].Buckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5}
		}
	}

	return errors.Join(errs...)
}

// ReadTimeoutDuration parses the configured read timeout.
func (s ServerConfig) ReadTimeoutDuration() (time.Duration, error) {
	return time.ParseDuration(s.ReadTimeout)
}

// ExampleYAML returns a documented minimal example configuration.
func ExampleYAML() string {
	return `server:
  log_listen_address: "127.0.0.1:2212"
  log_transport: "udp"       # tcp | udp
  metrics_listen_address: "127.0.0.1:9212"
  read_timeout: "30s"
  line_max_bytes: 1048576

parser:
  format: "auto"            # auto | json | syslog_rfc3164 | syslog_ng_json
  payload_format: "json"    # json | raw (used for syslog-based payloads)

logging:
  level: "info"   # debug|info|warn|error
  format: "text"  # text|json

metrics:
  const_labels:
    app: "logstream-exporter"

  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name", "syslog_host", "syslog_tag", "geoip_country_code"]

  definitions:
    - name: "logstream_request_time_seconds"
      help: "Observed request_time values from the log stream."
      field: "request_time"
      type: "histogram"
      labels: ["status", "request_method", "server_name", "syslog_host"]
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]

    - name: "logstream_bytes_sent_total"
      help: "Accumulated bytes_sent values from the log stream."
      field: "bytes_sent"
      type: "counter_add"
      labels: ["status", "server_name", "syslog_host"]
`
}

// validateMetricName validates Prometheus metric name syntax.
func validateMetricName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("must not be empty")
	}
	if !metricNameRE.MatchString(name) {
		return fmt.Errorf("invalid metric name %q", name)
	}
	return nil
}

// isOneOfCI checks whether value matches any candidate case-insensitively.
func isOneOfCI(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}
