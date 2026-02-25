// Package ingest implements the UDP datagram-based log stream receiver.
package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// UDPServer receives log messages over UDP and forwards them to a line handler.
//
// Each datagram is treated as one message payload. If a datagram contains multiple
// newline-separated messages, they are split and forwarded individually.
type UDPServer struct {
	address      string
	readTimeout  time.Duration
	lineMaxBytes int
	handler      LineHandler
	logger       *slog.Logger

	conn net.PacketConn
	wg   sync.WaitGroup
}

// NewUDPServer creates a configured UDP ingest server.
func NewUDPServer(address string, readTimeout time.Duration, lineMaxBytes int, logger *slog.Logger, handler LineHandler) *UDPServer {
	return &UDPServer{
		address:      address,
		readTimeout:  readTimeout,
		lineMaxBytes: lineMaxBytes,
		handler:      handler,
		logger:       logger,
	}
}

// Start begins listening and serving UDP datagrams until Stop is called or the context is cancelled.
func (s *UDPServer) Start(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", s.address)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.address, err)
	}
	s.conn = conn

	s.logger.Info(
		"log ingest server started",
		"transport", "udp",
		"address", s.address,
		"read_timeout", s.readTimeout.String(),
		"line_max_bytes", s.lineMaxBytes,
	)

	s.wg.Add(1)
	go s.readLoop(ctx)

	return nil
}

// Stop closes the UDP socket and waits for the read loop to terminate.
func (s *UDPServer) Stop() error {
	if s.conn != nil {
		if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.wg.Wait()
			return err
		}
	}
	s.wg.Wait()
	return nil
}

// readLoop receives datagrams and forwards one or more lines to the handler.
func (s *UDPServer) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, s.lineMaxBytes)

	for {
		if s.readTimeout > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}

		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Warn("udp read error", "error", err)
				continue
			}
		}

		if n <= 0 {
			continue
		}

		// Note: If n == len(buf), the datagram may have been truncated.
		// We cannot reliably distinguish "exact fit" from "truncated" here.
		if n == len(buf) {
			s.logger.Debug("udp datagram reached buffer limit and may be truncated", "remote_addr", addr.String(), "bytes", n)
		}

		payload := append([]byte(nil), buf[:n]...)
		lines := splitDatagramLines(payload)

		for _, line := range lines {
			s.handler(ctx, line)
		}
	}
}

// splitDatagramLines normalizes one UDP datagram into one or more non-empty lines.
func splitDatagramLines(payload []byte) [][]byte {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil
	}

	parts := bytes.Split(trimmed, []byte{'\n'})
	result := make([][]byte, 0, len(parts))

	for _, part := range parts {
		line := bytes.TrimSpace(part)
		if len(line) == 0 {
			continue
		}
		result = append(result, append([]byte(nil), line...))
	}

	return result
}
