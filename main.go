package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Initialize logger and set as default
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	slog.Info("Starting VPNet enclave with SGX Attestation...")

	// Create new enclave instance
	vpnEnclave, err := NewVPNEnclave()
	if err != nil {
		slog.Error("Failed to create enclave", "error", err)
		os.Exit(1)
	}

	// Start HTTP server with the enclave reference
	go func() {
		if err := vpnEnclave.StartWgHttpServer(); err != nil {
			slog.Error("failed to start wgHttp", "error", err)
		}
	}()

	// Setup socket path for server
	socketPath := "/var/run/vpnet/vpnetd-sgx.sock"

	// Create listener through server
	if err := vpnEnclave.connectionManager.CreateListener(socketPath); err != nil {
		slog.Error("Failed to create Unix socket listener", "error", err)
		os.Exit(1)
	}
	defer vpnEnclave.connectionManager.Close()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup error channel for fatal errors
	errChan := make(chan error, 1)

	// Start accepting connections
	go func() {
		if err := vpnEnclave.connectionManager.Start(); err != nil {
			select {
			case errChan <- err:
			default:
				slog.Error("Server stopped", "error", err)
			}
		}
	}()

	// Main processing loop
	for {
		select {
		case err := <-errChan:
			slog.Error("Fatal error", "error", err)
			os.Exit(1)

		case <-sigChan:
			slog.Info("Received signal, shutting down...")
			return
		}
	}
}
