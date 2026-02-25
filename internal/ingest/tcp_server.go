// Package ingest implements the TCP line-based log stream receiver.
package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// LineHandler processes one received log line.
type LineHandler func(ctx context.Context, line []byte)

// TCPServer receives line-delimited logs over TCP and forwards them to a handler.
type TCPServer struct {
	address      string
	readTimeout  time.Duration
	lineMaxBytes int
	handler      LineHandler
	logger       *slog.Logger

	listener net.Listener
	wg       sync.WaitGroup
	conns    sync.Map
}

// NewTCPServer creates a configured TCP ingest server.
func NewTCPServer(address string, readTimeout time.Duration, lineMaxBytes int, logger *slog.Logger, handler LineHandler) *TCPServer {
	return &TCPServer{
		address:      address,
		readTimeout:  readTimeout,
		lineMaxBytes: lineMaxBytes,
		handler:      handler,
		logger:       logger,
	}
}

// Start begins listening and serving connections until Stop is called or the context is cancelled.
func (s *TCPServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", s.address, err)
	}
	s.listener = ln

	s.logger.Info("log ingest server started", "address", s.address, "read_timeout", s.readTimeout.String(), "line_max_bytes", s.lineMaxBytes)

	s.wg.Add(1)
	go s.acceptLoop(ctx)
	return nil
}

// Stop closes the listener, actively closes client connections, and waits for handlers.
func (s *TCPServer) Stop() error {
	var errs []error

	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	s.conns.Range(func(key, _ any) bool {
		if conn, ok := key.(net.Conn); ok {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		return true
	})

	s.wg.Wait()
	return errors.Join(errs...)
}

// acceptLoop accepts TCP connections and starts a goroutine per connection.
func (s *TCPServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("accept failed", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

// handleConnection reads line-delimited payloads from one TCP client.
func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	s.conns.Store(conn, struct{}{})
	defer s.conns.Delete(conn)

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug("client connected", "remote_addr", remoteAddr)
	defer s.logger.Debug("client disconnected", "remote_addr", remoteAddr)

	scanner := bufio.NewScanner(conn)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, s.lineMaxBytes)

	for {
		if s.readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}

		ok := scanner.Scan()
		if !ok {
			break
		}

		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 {
			continue
		}

		s.handler(ctx, line)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			s.logger.Debug("connection idle timeout", "remote_addr", remoteAddr, "error", err)
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		s.logger.Warn("connection read error", "remote_addr", remoteAddr, "error", err)
	}
}
