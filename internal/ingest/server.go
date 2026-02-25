// Package ingest provides log stream transport servers (TCP, UDP) for line-based ingestion.
package ingest

import "context"

// Server defines the common lifecycle interface for ingest transports.
type Server interface {
	// Start starts the ingest server and returns once the listener is active.
	Start(ctx context.Context) error
	// Stop stops the ingest server and releases resources.
	Stop() error
}
