// Command logstream-exporter receives line-based logs and exposes derived Prometheus metrics.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"bodsch.me/logstream-exporter/internal/cli"
	"bodsch.me/logstream-exporter/internal/config"
	"bodsch.me/logstream-exporter/pkg/logstreamexporter"
	"bodsch.me/logstream-exporter/pkg/version"
)

// main is the CLI entry point.
func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// run parses configuration, constructs the application, and blocks until shutdown.
func run() error {

	opts, err := cli.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	if opts.Version {
		printVersion()
		return nil
	}

	if opts.PrintExampleConfig {
		_, _ = fmt.Fprintln(os.Stdout, config.ExampleYAML())
		return nil
	}

	cfg, err := config.LoadFile(opts.ConfigPath)
	if err != nil {
		return err
	}
	opts.ApplyOverrides(&cfg)

	app, err := logstreamexporter.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func printVersion() {
	fmt.Println("logstream-exporter")
	fmt.Printf("Version:   %s\n", version.Version)
	fmt.Printf("Commit:    %s\n", version.GitCommit)
	fmt.Printf("BuildDate: %s\n", version.BuildDate)
}
