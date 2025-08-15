// File: server/enclave/obfuscation.go
package main

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"
)

// ObfuscationManager manages all traffic obfuscation features
type ObfuscationManager struct {
	wireGuard     *WireGuardHandler
	identityVault *IdentityVault
	vpnEnclave    *VPNEnclave // Reference to the enclave for UDP access

	// For dummy traffic
	dummyTimer *time.Timer
	isRunning  bool
	wg         sync.WaitGroup
}

// NewObfuscationManager creates a new obfuscation manager
func NewObfuscationManager(wireGuard *WireGuardHandler, identityVault *IdentityVault, vpnEnclave *VPNEnclave) *ObfuscationManager {
	om := &ObfuscationManager{
		wireGuard:     wireGuard,
		identityVault: identityVault,
		vpnEnclave:    vpnEnclave,
		isRunning:     true,
	}

	// Start dummy traffic generator if enabled
	if DefaultEnableDummyTraffic {
		// Calculate initial delay - random to avoid predictable patterns
		delay, _ := randomInt(1, DefaultDummyTrafficRateSec+1)
		initialDelay := time.Duration(delay) * time.Second

		// Start timer
		om.dummyTimer = time.AfterFunc(initialDelay, om.generateDummyTraffic)

		slog.Info("Dummy traffic generation enabled",
			"rate_sec", DefaultDummyTrafficRateSec,
			"min_size", DefaultDummyTrafficMinSize,
			"max_size", DefaultDummyTrafficMaxSize)
	}

	return om
}

// ProcessOutgoingPacket processes an outgoing packet with obfuscation
// conn is the connection to use for sending, or nil to use the default hostWriter
func (om *ObfuscationManager) ProcessOutgoingPacket(sessionID SessionKey, data []byte) error {
	// Look up the client address from the session ID
	sessionInfo, err := om.identityVault.GetSessionInfo(sessionID)
	if err != nil {
		// Silently drop packets to unknown sessions
		return nil
	}

	// TODO where is the obfuscation here?
	nextConn := om.vpnEnclave.connectionManager.GetNextConnection()
	if nextConn == nil {
		// drop silently
		return nil
	}
	return nextConn.sendToClient(sessionInfo.RemoteAddr, data)
}

// ApplyPadding adds padding to a packet to mask its true size
func (om *ObfuscationManager) ApplyPadding(data []byte) []byte {
	if !DefaultEnablePadding {
		return data
	}

	blockSize := DefaultPaddingBlockSize
	if blockSize <= 0 {
		blockSize = 16 // Default block size
	}

	// Calculate how much padding to add
	// Round up to the next multiple of blockSize
	originalSize := len(data)
	paddedSize := ((originalSize + blockSize - 1) / blockSize) * blockSize

	// Add padding
	if paddedSize > originalSize {
		padding := make([]byte, paddedSize-originalSize)

		// Fill padding with random data to avoid patterns
		if _, err := rand.Read(padding); err != nil {
			// If random generation fails, use a simple pattern
			for i := range padding {
				padding[i] = byte(i % 256)
			}
		}

		// Return padded data
		return append(data, padding...)
	}

	return data
}

// generateDummyTraffic generates and sends a dummy packet
func (om *ObfuscationManager) generateDummyTraffic() {
	if !om.isRunning {
		return
	}

	// Get all active sessions
	sessionIDs := om.identityVault.GetAllSessions()
	if len(sessionIDs) == 0 {
		// No active clients, reschedule timer
		if om.isRunning {
			om.dummyTimer.Reset(time.Duration(DefaultDummyTrafficRateSec) * time.Second)
		}
		return
	}

	// Select a random session
	randomIndex, err := randomInt(0, len(sessionIDs))
	if err != nil {
		randomIndex = 0
	}
	sessionID := sessionIDs[randomIndex]

	// Get session info
	sessionInfo, err := om.identityVault.GetSessionInfo(sessionID)
	if err != nil {
		slog.Error("Failed to get session info for dummy traffic", "error", err)
		if om.isRunning {
			om.dummyTimer.Reset(time.Duration(DefaultDummyTrafficRateSec) * time.Second)
		}
		return
	}

	// Generate random packet size between min and max
	minSize := DefaultDummyTrafficMinSize
	maxSize := DefaultDummyTrafficMaxSize
	if minSize <= 0 {
		minSize = 64
	}
	if maxSize <= minSize {
		maxSize = minSize + 960
	}

	size, err := randomInt(minSize, maxSize+1)
	if err != nil {
		size = minSize
	}

	// Create dummy packet with random content
	dummyPacket := make([]byte, size)
	if _, err := rand.Read(dummyPacket); err != nil {
		slog.Error("Failed to generate random data for dummy traffic", "error", err)
		if om.isRunning {
			om.dummyTimer.Reset(DefaultDummyTrafficRate)
		}
		return
	}

	// Make it look like a legitimate packet by setting message type to 4 (DATA)
	// but using a reserved counter value that will be discarded by the client
	binary.LittleEndian.PutUint32(dummyPacket[0:4], MessageTransportType) // 4 for Transport (data)

	// Use reserved counter values (highest bits set) which real packets won't use
	// This allows clients to identify and drop these packets without breaking protocol
	if len(dummyPacket) >= 16 {
		binary.LittleEndian.PutUint64(dummyPacket[8:16], 0xFFFFFFFFFFFFFFFF)
	}

	// Apply padding if enabled
	if DefaultEnablePadding {
		dummyPacket = om.ApplyPadding(dummyPacket)
	}

	// Encrypt the dummy packet
	encryptedPacket, err := om.wireGuard.EncryptDataPacket(
		dummyPacket, sessionInfo.PeerPublicKey, sessionInfo.RemoteIndex)
	if err != nil {
		slog.Error("Failed to encrypt dummy packet", "error", err)
		if om.isRunning {
			om.dummyTimer.Reset(time.Duration(DefaultDummyTrafficRateSec) * time.Second)
		}
		return
	}

	// Get a connection from the connection manager
	if om.vpnEnclave != nil && om.vpnEnclave.connectionManager != nil {
		conn := om.vpnEnclave.connectionManager.GetNextConnection()
		if conn != nil {
			conn.sendToClient(sessionInfo.RemoteAddr, encryptedPacket)
		}
		// If no connection is available, give up on sending the dummy packet
		// This is acceptable since dummy traffic is not critical
	}
	// No fallback to hostWriter as it will not exist anymore

	// Schedule next dummy packet with slight randomization to avoid patterns
	if om.isRunning {
		// Vary the interval by ±10% to avoid patterns
		baseInterval := DefaultDummyTrafficRate
		jitter, _ := randomInt(-int(baseInterval)/10, int(baseInterval)/10+1)
		nextInterval := baseInterval + time.Duration(jitter)

		om.dummyTimer.Reset(nextInterval)
	}
}

// Close stops all obfuscation activities
func (om *ObfuscationManager) Close() {
	om.isRunning = false

	// Stop dummy traffic timer
	if om.dummyTimer != nil {
		om.dummyTimer.Stop()
	}

	// Wait for goroutines to finish
	om.wg.Wait()
}
