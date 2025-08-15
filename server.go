package main

import (
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
)

// Server manages connections from the host
type Server struct {
	connections       []*IPC
	mutex             sync.RWMutex
	connectionCounter uint64
	listener          net.Listener
	enclave           *VPNEnclave
}

// NewServer creates a new server
func NewServer(enclave *VPNEnclave) *Server {
	return &Server{
		enclave: enclave,
	}
}

// AddConnection adds a connection to the pool
func (cm *Server) AddConnection(conn *IPC) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.connections = append(cm.connections, conn)
}

// RemoveConnection removes a connection from the pool
func (cm *Server) RemoveConnection(conn *IPC) bool {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for i, c := range cm.connections {
		if c == conn {
			cm.connections = slices.Delete(cm.connections, i, i+1)
			slog.Info("Removed connection from pool", "remaining", len(cm.connections))
			return true
		}
	}

	return false // Connection not found
}

// GetNextConnection returns the next connection in round-robin fashion
// for efficient load balancing
func (cm *Server) GetNextConnection() *IPC {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	count := len(cm.connections)
	if count == 0 {
		return nil // No connections available
	}

	if count == 1 {
		return cm.connections[0] // Just one connection, no need for load balancing
	}

	idx := atomic.AddUint64(&cm.connectionCounter, 1) % uint64(count)

	return cm.connections[idx]
}

// CreateListener creates and initializes the Unix socket listener
func (s *Server) CreateListener(socketPath string) error {
	slog.Info("Creating Unix socket server", "path", socketPath)

	// Remove any existing socket file
	os.Remove(socketPath)

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	s.listener = listener
	return nil
}

// Start begins accepting connections on the listener
func (s *Server) Start() error {
	if s.listener == nil {
		return &net.OpError{Op: "listen", Net: "unix", Err: net.ErrClosed}
	}

	slog.Info("Unix socket server started, waiting for connections...")

	connectionID := 0
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if listener was closed
			if opErr, ok := err.(*net.OpError); ok && opErr.Err == net.ErrClosed {
				return nil
			}
			slog.Error("Failed to accept connection", "error", err)
			continue
		}

		connectionID++
		slog.Info("Accepted new connection", "connectionID", connectionID)

		// Handle each connection in a new goroutine
		go s.handleConnection(conn, connectionID)
	}
}

// handleConnection handles an individual client connection
func (s *Server) handleConnection(conn net.Conn, connectionID int) {
	defer func() {
		conn.Close()
	}()

	// Wrap connection in IPC
	ipcConn := NewIPC(conn)

	// Register the connection
	s.AddConnection(ipcConn)
	defer s.RemoveConnection(ipcConn)

	// Start reading from this connection
	s.enclave.StartConnectionReader(ipcConn, connectionID)
}

// Close closes the listener
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
