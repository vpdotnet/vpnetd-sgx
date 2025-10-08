package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"runtime/debug"
	"slices"
	"sync/atomic"
	"time"
)

// VPNEnclave is the main enclave structure
type VPNEnclave struct {
	// Core components
	isRunning        bool
	identityVault    *IdentityVault
	trafficProcessor *TrafficProcessor
	keyManager       *KeyManager
	wireGuardHandler *WireGuardHandler
	natTable         *NatTable

	// Traffic obfuscation
	obfuscationManager *ObfuscationManager

	// Multi-connection management
	connectionManager *Server

	// Stats for diagnostics using atomic operations
	stats struct {
		handshakesProcessed  uint64
		dataPacketsProcessed uint64
		errorCount           uint64
	}
}

// NewVPNEnclave creates a new VPN enclave
func NewVPNEnclave() (*VPNEnclave, error) {
	// Initialize enclave
	e := &VPNEnclave{
		isRunning: false,
	}

	// Initialize connection manager
	e.connectionManager = NewServer(e)

	// Initialize key manager for WireGuard authentication
	keyManager, err := NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %v", err)
	}
	e.keyManager = keyManager
	e.identityVault = NewIdentityVault(e.keyManager)
	// Initialize WireGuard handler (pass connectionManager which is the Server)
	e.wireGuardHandler = NewWireGuardHandler(e.keyManager, e.identityVault, e.connectionManager)
	// Initialize core components - Note the order is important!
	// IdentityVault now requires KeyManager
	e.trafficProcessor = e.NewTrafficProcessor()

	// Connect components
	e.trafficProcessor.SetWireGuardHandler(e.wireGuardHandler)

	slog.Info("WireGuard-compatible authentication initialized")

	// Initialize NAT table
	e.natTable = NewNatTable()
	e.natTable.StartCleanupRoutine()
	slog.Info("NAT table initialized")

	// Initialize obfuscation features if enabled
	if DefaultEnablePadding || DefaultEnableTrafficMixing || DefaultEnableDummyTraffic {
		slog.Info("Initializing traffic obfuscation features...")
		e.obfuscationManager = NewObfuscationManager(
			e.wireGuardHandler,
			e.identityVault,
			e, // Pass the enclave reference for UDP access
		)

		// Log which features are enabled
		if DefaultEnablePadding {
			slog.Info("Packet padding enabled", "blockSize", DefaultPaddingBlockSize)
		}
		if DefaultEnableTrafficMixing {
			slog.Info("Traffic mixing enabled", "delayMs", DefaultTrafficMixingDelayMS)
		}
		if DefaultEnableDummyTraffic {
			slog.Info("Dummy traffic enabled", "rateSec", DefaultDummyTrafficRateSec, "minSize", DefaultDummyTrafficMinSize, "maxSize", DefaultDummyTrafficMaxSize)
		}
	}

	// Start maintenance goroutine for WireGuard
	go func() {
		maintenanceTicker := time.NewTicker(30 * time.Second)
		defer maintenanceTicker.Stop()

		var memStat runtime.MemStats

		for _ = range maintenanceTicker.C {
			runtime.ReadMemStats(&memStat)
			e.wireGuardHandler.Maintenance()
			slog.Info("Maintenance performed",
				"handshakes", atomic.LoadUint64(&e.stats.handshakesProcessed),
				"dataPackets", atomic.LoadUint64(&e.stats.dataPacketsProcessed),
				"errors", atomic.LoadUint64(&e.stats.errorCount),
				"memAlloc", memStat.Alloc,
				"mallocs", memStat.Mallocs)
		}
	}()

	return e, nil
}

// SendToSessionKey will encrypt packet and send it to the appropriate session
func (e *VPNEnclave) SendToSessionKey(packet []byte, sessionID SessionKey) error {
	// Get session info for remote address
	sessionInfo, err := e.identityVault.GetSessionInfo(sessionID)
	if err != nil {
		slog.Error("Failed to send packet to session", "error", err)
		return nil // silently drop packets to sessions that do not exist anymore
	}

	// encrypt packet
	packet, err = e.wireGuardHandler.EncryptDataPacket(packet, sessionInfo.PeerPublicKey, sessionInfo.RemoteIndex)
	if err != nil {
		slog.Error("Cannot encrypt packet", "error", err)
		return err
	}

	if e.obfuscationManager != nil {
		return e.obfuscationManager.ProcessOutgoingPacket(sessionID, packet)
	} else {
		// Add detailed diagnostic logging
		if sessionInfo.RemoteAddr == nil {
			slog.Error("Cannot send packet to session: RemoteAddr is nil")
			return fmt.Errorf("remote address is nil for session %v", sessionID)
		}

		slog.Debug("Sending packet to client",
			"sessionID", sessionID,
			"ip", sessionInfo.RemoteAddr.IP.String(),
			"port", sessionInfo.RemoteAddr.Port,
			"packetSize", len(packet))

		// Use the provided connection if available
		nextConn := e.connectionManager.GetNextConnection()
		if nextConn == nil {
			// we're not connected, drop silently
			return nil
		}
		err = nextConn.sendToClient(sessionInfo.RemoteAddr, packet)
		if err != nil {
			slog.Error("Failed to send packet to client",
				"sessionID", sessionID,
				"ip", sessionInfo.RemoteAddr.IP.String(),
				"port", sessionInfo.RemoteAddr.Port,
				"error", err)
			return err
		}

		return nil
	}
}

// ProcessOutboundPacket processes a packet from the TUN device (Internet) to WireGuard clients
func (e *VPNEnclave) ProcessOutboundPacket(packet []byte, conn *IPC) error {
	// Process packet in the traffic processor
	if err := e.trafficProcessor.HandleTUNToClientPacket(packet, conn); err != nil {
		atomic.AddUint64(&e.stats.errorCount, 1)
		return fmt.Errorf("failed to process outbound packet: %v", err)
	}

	return nil
}

// ProcessEncryptedPacket processes an encrypted packet from a client
// conn is the connection that received the packet and should be used for sending responses
func (e *VPNEnclave) ProcessEncryptedPacket(sessionID SessionKey, remoteAddr *net.UDPAddr, encryptedData []byte) error {
	// Check packet type based on first 4 bytes (message type is uint32 little endian)
	if len(encryptedData) < 4 {
		return fmt.Errorf("packet too short to determine type")
	}

	msgType := binary.LittleEndian.Uint32(encryptedData[0:4])

	switch msgType {
	case MessageInitiationType:
		// Update stats using atomic operations
		atomic.AddUint64(&e.stats.handshakesProcessed, 1)

		// This is a handshake initiation - Pass the remoteAddr to ProcessHandshakeInitiation
		response, clientPublicKey, err := e.wireGuardHandler.ProcessHandshakeInitiation(encryptedData, remoteAddr)
		if err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			return fmt.Errorf("handshake processing failed: %v", err)
		}

		// Create session if it doesn't exist
		if !e.identityVault.IsSessionValid(sessionID) {
			if err := e.identityVault.CreateSession(sessionID, remoteAddr); err != nil {
				atomic.AddUint64(&e.stats.errorCount, 1)
				return fmt.Errorf("failed to create session: %v", err)
			}
		} else {
			// Update remote address in case it changed
			if err := e.identityVault.UpdateSessionRemoteAddr(sessionID, remoteAddr); err != nil {
				atomic.AddUint64(&e.stats.errorCount, 1)
				return fmt.Errorf("failed to update session remote address: %v", err)
			}
		}

		// Update session with client's public key
		if err := e.identityVault.UpdateSessionPeerKey(sessionID, clientPublicKey); err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			return fmt.Errorf("failed to update session peer key: %v", err)
		}

		// Mark session as established
		if err := e.identityVault.MarkSessionEstablished(sessionID); err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			return fmt.Errorf("failed to mark session as established: %v", err)
		}

		// Verify response size is correct for a handshake response message
		if len(response) != MessageResponseSize {
			slog.Error("Response size mismatch",
				"gotSize", len(response),
				"expectedSize", MessageResponseSize)
			return fmt.Errorf("handshake response has invalid size")
		}

		// Store the client's sender index as our receiver index
		if len(encryptedData) >= 8 {
			clientSenderIdx := binary.LittleEndian.Uint32(encryptedData[4:8])
			if err := e.identityVault.UpdateSessionRemoteIndex(sessionID, clientSenderIdx); err != nil {
				slog.Error("Failed to update initial remote index", "error", err)
			}
		}

		// Use next connection for handshake response
		nextConn := e.connectionManager.GetNextConnection()
		if nextConn == nil {
			slog.Error("No available connections to send handshake response")
			return fmt.Errorf("no available connections")
		}
		return nextConn.sendToClient(remoteAddr, response)
	case MessageTransportType:
		// Update stats using atomic operations
		atomic.AddUint64(&e.stats.dataPacketsProcessed, 1)

		// Check if session exists
		if !e.identityVault.IsSessionValid(sessionID) {
			atomic.AddUint64(&e.stats.errorCount, 1)
			return fmt.Errorf("no valid session for ID: %s", sessionID)
		}

		// Get session info
		sessionInfo, err := e.identityVault.GetSessionInfo(sessionID)
		if err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			return fmt.Errorf("session not found: %v", err)
		}

		// Process data packet directly with the WireGuard handler
		plaintext, err := e.wireGuardHandler.ProcessDataPacket(encryptedData, sessionInfo.PeerPublicKey)
		if err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			slog.Error("Failed to process data packet", "error", err)
			return fmt.Errorf("failed to process data packet: %v", err)
		}

		// Check if this is a control packet
		if len(plaintext) > 0 && plaintext[0] == PacketTypeControl {
			// This is a control packet, handle it with the control packet processor
			if len(plaintext) > 1 {
				slog.Debug("Received control packet from client")
				return e.processControlPacket(sessionID, plaintext[1:])
			}
			slog.Error("Received control packet that is too short")
			return fmt.Errorf("control packet too short")
		}

		// Forward the decrypted packet directly to the TUN device
		// Use HandleClientToTUNPacket to bypass routing engine and send directly to TUN
		if err := e.trafficProcessor.HandleClientToTUNPacket(plaintext, sessionInfo.SessionID); err != nil {
			atomic.AddUint64(&e.stats.errorCount, 1)
			slog.Error("Failed to forward decrypted packet to TUN", "error", err)
			return fmt.Errorf("failed to forward decrypted packet: %v", err)
		}

		// Check if this is the first data packet received after handshake
		// This confirms the handshake was successful
		if !sessionInfo.HasCompletedHandshake {
			e.HandleSuccessfulHandshake(sessionID, sessionInfo.PeerPublicKey)
		}

		return nil

	case MessageResponseType:
		// Client is sending a response to our initiation (unusual in server mode)
		atomic.AddUint64(&e.stats.errorCount, 1)
		return fmt.Errorf("unexpected handshake response from client")

	case MessageCookieReplyType:
		// Cookie message for DoS prevention
		atomic.AddUint64(&e.stats.errorCount, 1)
		return fmt.Errorf("cookie messages not fully supported yet")

	default:
		slog.Error("Received unknown packet type from client",
			"msgType", msgType,
			"remoteAddr", remoteAddr)
		atomic.AddUint64(&e.stats.errorCount, 1)
		return fmt.Errorf("unknown packet type: %d", msgType)
	}
}

// ProcessUdpPacketWithHeader processes a single packet with its header
// conn is the connection that received the packet and should be used for responses
func (e *VPNEnclave) ProcessUdpPacketWithHeader(data []byte, conn *IPC) error {
	if len(data) <= 18 {
		// ignore empty
		return nil
	}

	ip := net.IP(data[:16])
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	// Clone the IP slice to prevent storing a reference to the reusable buffer
	// This is critical because the UDPAddr will be stored in long-lived session structures
	addr := &net.UDPAddr{
		IP:   slices.Clone(ip),
		Port: int(binary.BigEndian.Uint16(data[16:18])),
	}

	return e.processPacket(addr, data[18:], conn)
}

// processPacket processes a single packet
// conn is the connection that received the packet and should be used for sending responses
func (e *VPNEnclave) processPacket(addr *net.UDPAddr, data []byte, conn *IPC) error {
	// Check minimum size
	if len(data) < 4 {
		return fmt.Errorf("packet too small: %d bytes", len(data))
	}

	// Extract message type
	msgType := binary.LittleEndian.Uint32(data[0:4])

	// Identify the client by addr
	var sessionID SessionKey
	copy(sessionID.IP[:], addr.IP.To16()[:])
	sessionID.Port = uint16(addr.Port)

	switch msgType {
	case MessageInitiationType:
		// This is a handshake initiation
		// Process the encrypted packet directly with the enclave
		// Pass the connection that received the packet for use in responses
		return e.ProcessEncryptedPacket(sessionID, addr, data)

	case MessageTransportType:
		// Regular data packet, use address as session ID
		// Pass the connection that received the packet for use in responses
		return e.ProcessEncryptedPacket(sessionID, addr, data)

	default:
		return fmt.Errorf("unknown message type: %d", msgType)
	}
}

// HandleSuccessfulHandshake is called when the first data packet is received after handshake
// conn is the connection that received the packet and should be used for responses
func (e *VPNEnclave) HandleSuccessfulHandshake(sessionID SessionKey, peerKey [32]byte) {
	// First, check if this is the first data packet after handshake
	sessionInfo, err := e.identityVault.GetSessionInfo(sessionID)
	if err != nil {
		slog.Error("Failed to get session info for handshake tracking", "error", err)
		return
	}

	// Check if we've already marked this handshake as complete
	if !sessionInfo.HasCompletedHandshake {
		// Mark handshake as complete
		e.identityVault.MarkHandshakeComplete(sessionID)

		// Now it's safe to send a keepalive packet
		keepalivePacket, err := e.wireGuardHandler.GenerateKeepalivePacket(peerKey)
		if err != nil {
			slog.Error("Failed to generate keepalive", "error", err)
			return
		}

		// Use the provided connection to send the response

		// Process through obfuscation manager if enabled
		if e.obfuscationManager != nil {
			if err := e.obfuscationManager.ProcessOutgoingPacket(sessionID, keepalivePacket); err != nil {
				slog.Error("Failed to send keepalive through obfuscation manager", "error", err)
			}
		} else {
			// Send directly through UDP
			// Use next connection for keepalive
			nextConn := e.connectionManager.GetNextConnection()
			if nextConn == nil {
				slog.Error("No available connections to send keepalive")
				return
			}
			if err := nextConn.sendToClient(sessionInfo.RemoteAddr, keepalivePacket); err != nil {
				slog.Error("Failed to send keepalive through UDP", "error", err)
			}
		}
	}
}

// processControlPacket processes a control packet
func (e *VPNEnclave) processControlPacket(sessionID SessionKey, data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("control packet too short")
	}

	controlType := data[0]

	switch controlType {
	case ControlTypeKeepAlive:
		// Just update last active time, already done in main handler
		slog.Debug("Processed KeepAlive control packet")
		return nil

	case ControlTypeDisconnect:
		slog.Debug("Processing Disconnect control packet")

		// Terminate session
		err := e.identityVault.TerminateSession(sessionID)
		if err != nil {
			slog.Error("Error terminating session", "error", err)
		} else {
			slog.Debug("Successfully terminated session due to disconnect packet")
		}
		return err

	case ControlTypeRotateKeys:
		slog.Debug("Processed RotateKeys control packet")
		// TODO: Implement key rotation
		return nil

	default:
		slog.Error("Received unknown control type",
			"controlType", controlType,
			"sessionID", sessionID)
		return fmt.Errorf("unknown control type: %d", controlType)
	}
}

// HandleClientDisconnect handles a client disconnection notification
func (e *VPNEnclave) HandleClientDisconnect(sessionID SessionKey, hostWriter *IPC) error {
	// No need to update routing, NAT rules will expire on their own
	// Terminate session
	return e.identityVault.TerminateSession(sessionID)
}

// StartConnectionReader starts a reader goroutine for the given connection
// This handles all the command processing for the connection
func (e *VPNEnclave) StartConnectionReader(conn *IPC, connIndex int) {
	defer func() {
		// display panic
		if rec := recover(); rec != nil {
			slog.Error("PANIC in handling system", "panic", rec)
			debug.PrintStack()
		}
		slog.Info("Connection reader exiting", "connIndex", connIndex)
		conn.Close()
	}()

	reader := bufio.NewReaderSize(conn.conn, ReceiveBufferSize)
	reuseBuf := make([]byte, ReusableBufferSize)
	var cmd uint16

	for {
		err := binary.Read(reader, binary.BigEndian, &cmd)
		if err != nil {
			slog.Error("Error reading from connection, closing",
				"connIndex", connIndex,
				"error", err)
			return
		}

		ln, err := binary.ReadUvarint(reader)
		if err != nil {
			slog.Error("Error reading command length from connection, closing",
				"connIndex", connIndex,
				"error", err)
			return
		}

		var buf []byte
		if ln > 0 {
			if ln <= ReusableBufferSize {
				buf = reuseBuf[:ln]
			} else {
				buf = make([]byte, ln)
			}
			_, err := io.ReadFull(reader, buf)
			if err != nil {
				slog.Error("Error reading command body from connection, closing",
					"connIndex", connIndex,
					"error", err)
				return
			}
		}

		// Process commands
		switch cmd {
		case CmdTUN:
			// Process packet from TUN interface
			e.ProcessOutboundPacket(buf, conn)
		case CmdUDP:
			e.ProcessUdpPacketWithHeader(buf, conn)
		case WireguardAddPeer:
			// Handle WireguardAddPeer packet from host
			if err := e.wireGuardHandler.ProcessWireguardAddPeer(buf, conn); err != nil {
				slog.Error("Failed to process WireguardAddPeer", "error", err)
			}
		case RespPeerVerifyToken, RespPeerVerifyPubkey:
			// Handle response for peer verification
			if err := e.ProcessPeerVerifyResponse(cmd, buf); err != nil {
				slog.Error("Failed to process peer verify response", "error", err, "cmd", fmt.Sprintf("0x%04x", cmd))
			}
		default:
			slog.Error("Unhandled command on connection",
				"command", fmt.Sprintf("0x%04x", cmd),
				"connIndex", connIndex)
		}
	}
}

// RemoveConnection removes a connection from the enclave
func (e *VPNEnclave) RemoveConnection(conn *IPC) error {
	// Remove the connection from the connection manager
	e.connectionManager.RemoveConnection(conn)

	return nil
}

// ProcessPeerVerifyResponse handles responses for peer verification requests
func (e *VPNEnclave) ProcessPeerVerifyResponse(cmd uint16, data []byte) error {
	// Parse reqID from first 8 bytes
	if len(data) < 8 {
		return fmt.Errorf("peer verify response too short: %d bytes", len(data))
	}

	reqID := binary.BigEndian.Uint64(data[0:8])

	// Extract the response data (everything after reqID)
	responseData := data[8:]

	// Send to the waiting channel
	if !sendResponseToHandler(reqID, responseData) {
		slog.Warn("Received response for unknown request ID", "reqID", reqID, "cmd", fmt.Sprintf("0x%04x", cmd))
	}

	return nil
}
