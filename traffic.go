// File: enclave/traffic.go

package main

import (
	"fmt"
	"net"
	"sync/atomic"
)

// TrafficProcessor handles packet handling
type TrafficProcessor struct {
	vpnEnclave *VPNEnclave // Reference to enclave for NAT

	// WireGuard handler for encryption/decryption
	wireGuardHandler *WireGuardHandler

	// Statistics using atomic operations
	stats struct {
		packetsProcessed uint64
		bytesProcessed   uint64
		packetsEncrypted uint64
		packetsDecrypted uint64
	}
}

// NewTrafficProcessor creates a new traffic processor
func (e *VPNEnclave) NewTrafficProcessor() *TrafficProcessor {
	tp := &TrafficProcessor{
		vpnEnclave: e,
	}

	return tp
}

// Set WireGuard handler for encryption/decryption
func (tp *TrafficProcessor) SetWireGuardHandler(wg *WireGuardHandler) {
	tp.wireGuardHandler = wg
}

// HandleTUNToClientPacket processes packets from the TUN interface (Internet) to WireGuard clients
// These are INBOUND packets (Internet → WireGuard clients)
func (tp *TrafficProcessor) HandleTUNToClientPacket(packet []byte, conn *IPC) error {
	// Update statistics using atomic operations
	atomic.AddUint64(&tp.stats.packetsProcessed, 1)
	atomic.AddUint64(&tp.stats.bytesProcessed, uint64(len(packet)))

	// IP extraction removed as debug logging was removed for performance in hot path

	// These are INBOUND packets (from Internet/TUN to WireGuard clients)
	// We use HandleInboundPacket from the NAT table to translate and route
	// them to the appropriate WireGuard client
	processedPacket, session, ok := tp.vpnEnclave.natTable.HandleInboundPacket(packet)
	if !ok {
		// NAT rejected the packet, drop it
		return nil
	}

	// IP extraction after NAT removed as debug logging was removed for performance in hot path

	// Detailed NAT routing logging removed for performance in hot path

	return tp.vpnEnclave.SendToSessionKey(processedPacket, session)
}

// HandleClientToTUNPacket processes a decrypted packet from a WireGuard client and sends it to Internet (TUN)
// These are OUTBOUND packets (WireGuard clients → Internet)
func (tp *TrafficProcessor) HandleClientToTUNPacket(packet []byte, sess SessionKey) error {
	// Update statistics using atomic operations
	atomic.AddUint64(&tp.stats.packetsProcessed, 1)
	atomic.AddUint64(&tp.stats.bytesProcessed, uint64(len(packet)))

	// IP extraction removed as debug logging was removed for performance in hot path

	// Debug logging removed for performance in hot path

	// Check if this packet should be ignored (e.g., link-local IPv6)
	if tp.shouldIgnorePacket(packet) {
		// Packet ignored, debug logging removed for performance
		return nil
	}

	// Process packet through NAT
	// For outbound packets (WireGuard clients → Internet), we use HandleOutboundPacket
	// to translate client's private IP to a masquerade IP
	processedPacket, ok := tp.vpnEnclave.natTable.HandleOutboundPacket(packet, sess)
	if !ok {
		// NAT processing failed or packet was dropped
		return nil
	}

	// NAT transformation logging removed for performance in hot path

	// Use processed packet after NAT
	packet = processedPacket

	// For outbound packets (WireGuard clients → Internet), we send directly to TUN (Internet)
	// This completely bypasses the routing engine to avoid "no route found" errors
	nextConn := tp.vpnEnclave.connectionManager.GetNextConnection()
	if nextConn == nil {
		// drop silently if no connection available
		return nil
	}
	return nextConn.sendToTUN(packet)
}

// shouldIgnorePacket determines if a packet should be ignored based on IP addresses
func (tp *TrafficProcessor) shouldIgnorePacket(packet []byte) bool {
	if len(packet) < 20 {
		return true
	}

	// Parse the packet
	version := packet[0] >> 4
	if version != 4 {
		// ignore anything else than ipv4
		return true
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Ignore multicast addresses
	if srcIP.IsMulticast() || dstIP.IsMulticast() {
		return true
	}

	// Ignore localhost addresses
	if srcIP.IsLoopback() || dstIP.IsLoopback() {
		return true
	}

	return false
}

// HandleWireGuardEncryptedData processes encrypted WireGuard protocol data from a client
// Decrypts WireGuard packets and forwards them for further processing
// conn is the connection that received the packet and should be used for sending responses
func (tp *TrafficProcessor) HandleWireGuardEncryptedData(sessionID string, data []byte, sessionInfo *SessionInfo, conn *IPC) error {
	// Update statistics using atomic operations
	atomic.AddUint64(&tp.stats.packetsProcessed, 1)
	atomic.AddUint64(&tp.stats.bytesProcessed, uint64(len(data)))

	// Check packet type for WireGuard
	if len(data) > 0 {
		packetType := data[0]

		switch packetType {
		case MessageTransportType: // Data packet
			// For WireGuard data packets, process directly with WireGuard handler
			plaintext, err := tp.wireGuardHandler.ProcessDataPacket(data, sessionInfo.PeerPublicKey)
			if err != nil {
				return fmt.Errorf("failed to process WireGuard data packet: %v", err)
			}

			// Process immediately
			return tp.HandleTUNToClientPacket(plaintext, conn)
		case MessageResponseType:
			// Client sending a handshake response
			// This is unusual as the server is normally the one sending responses
			return fmt.Errorf("unexpected handshake response from client")

		case MessageCookieReplyType:
			// Cookie message (for DoS mitigation)
			// We don't process these yet
			return fmt.Errorf("cookie messages not yet supported")
		}
	}

	return fmt.Errorf("no send callback set or invalid packet type")
}

// GetStatsPacketsProcessed returns the number of packets processed
func (tp *TrafficProcessor) GetStatsPacketsProcessed() uint64 {
	return atomic.LoadUint64(&tp.stats.packetsProcessed)
}

// GetStatsBytesProcessed returns the number of bytes processed
func (tp *TrafficProcessor) GetStatsBytesProcessed() uint64 {
	return atomic.LoadUint64(&tp.stats.bytesProcessed)
}

// Close closes the traffic processor
func (tp *TrafficProcessor) Close() error {
	return nil
}
