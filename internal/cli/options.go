// Package cli parses command-line options and applies them as config overrides.
package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"bodsch.me/logstream-exporter/internal/config"
)

// Options contains parsed command-line arguments.
type Options struct {
	Version            bool
	ConfigPath         string
	PrintExampleConfig bool
	LogListenAddress   string
	LogTransport       string
	MetricsAddress     string
	ParserFormat       string
	PayloadFormat      string
	LogLevel           string
	LogFormat          string
	EventLabelsCSV     string
}

// Parse parses the command-line arguments into an Options struct.
func Parse(args []string) (Options, error) {
	var opts Options

	fs := flag.NewFlagSet("logstream-exporter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.BoolVar(&opts.Version, "version", false, "Print version and exit")
	fs.StringVar(&opts.ConfigPath, "config", "", "Path to YAML config file")
	fs.BoolVar(&opts.PrintExampleConfig, "print-example-config", false, "Print example YAML config and exit")
	fs.StringVar(&opts.LogListenAddress, "log-listen", "", "Listen address for log stream (e.g. 127.0.0.1:2212)")
	fs.StringVar(&opts.LogTransport, "log-transport", "", "Log transport: tcp|udp")
	fs.StringVar(&opts.MetricsAddress, "metrics-listen", "", "HTTP listen address for /metrics endpoint (e.g. 127.0.0.1:9212)")
	fs.StringVar(&opts.ParserFormat, "log-format", "", "Input log parser format (auto|json|syslog_rfc3164|syslog_ng_json)")
	fs.StringVar(&opts.PayloadFormat, "payload-format", "", "Payload parser format for syslog-based messages (json|raw)")
	fs.StringVar(&opts.LogLevel, "log-level", "", "Logger level: debug|info|warn|error")
	fs.StringVar(&opts.LogFormat, "log-output", "", "Logger output format: text|json")
	fs.StringVar(&opts.EventLabelsCSV, "event-labels", "", "Comma-separated label fields for the base event counter")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n", fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}

	if fs.NArg() > 0 {
		return Options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	return opts, nil
}

// ApplyOverrides mutates cfg with explicit CLI values only.
func (o Options) ApplyOverrides(cfg *config.Config) {
	if o.LogListenAddress != "" {
		cfg.Server.LogListenAddress = o.LogListenAddress
	}
	if o.LogTransport != "" {
		cfg.Server.LogTransport = o.LogTransport
	}
	if o.MetricsAddress != "" {
		cfg.Server.MetricsListenAddress = o.MetricsAddress
	}
	if o.ParserFormat != "" {
		cfg.Parser.Format = o.ParserFormat
	}
	if o.PayloadFormat != "" {
		cfg.Parser.PayloadFormat = o.PayloadFormat
	}
	if o.LogLevel != "" {
		cfg.Logging.Level = o.LogLevel
	}
	if o.LogFormat != "" {
		cfg.Logging.Format = o.LogFormat
	}
	if o.EventLabelsCSV != "" {
		cfg.Metrics.EventCounter.Labels = splitCSV(o.EventLabelsCSV)
	}
}

// splitCSV splits a comma-separated list into trimmed non-empty values.
func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}
