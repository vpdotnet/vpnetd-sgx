package main

import (
	"encoding/binary"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

const (
	natMaxAge      = 300 * time.Second
	natMinPort     = 1024
	natMaxPort     = 65535
	natICMPTimeout = 60
	natTCPTimeout  = 3600
	natUDPTimeout  = 300

	// Special redirection for DNS
	natDNSRedirectPort  = 5353
	natDNSRedirectPort2 = 5354
	natDNSOriginalPort  = 53

	// Per-client, per-protocol connection limit
	natMaxConnectionsPerClient = 200
)

// IPs directly defined as byte arrays for improved performance
var (
	// 10.7.0.1 - NAT masquerade IP
	natMasqueradeIP = [4]byte{10, 7, 0, 1}

	// 10.7.0.0 - DNS redirect target
	natDNSRedirectIP = [4]byte{10, 7, 0, 0}

	// 10.0.0.243 - Original DNS server
	natDNSOriginalIP = [4]byte{10, 0, 0, 243}

	// 10.0.0.241 - Ad-blocking DNS server
	natDNSOriginalIP2 = [4]byte{10, 0, 0, 241}

	// 10.0.0.129 - HTTPS redirect IP
	natHTTPSRedirectIP = [4]byte{10, 0, 0, 129}
)

// InternalConnectionKey is used to identify a TCP/UDP/ICMP connection with a wireguard session
type InternalConnectionKey struct {
	Session SessionKey // WireGuard session
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16 // icmpid if icmp packet
	DstPort uint16 // 0 if icmp
}

// ExternalConnectionKey is used to identify a masqueraded TCP/UDP/ICMP connection
type ExternalConnectionKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16 // icmpid if icmp packet
	DstPort uint16 // 0 if icmp
}

// NatConn represents a NAT connection with a more generic structure
type NatConn struct {
	LastSeen uint32
	Protocol uint8 // ICMP, TCP, UDP

	// WireGuard session key for identifying client connections
	Session SessionKey

	// Local side (client/WireGuard side)
	LocalSrcIP   [4]byte
	LocalSrcPort uint16
	LocalDstIP   [4]byte
	LocalDstPort uint16

	// Outside side (internet side)
	OutsideSrcIP   [4]byte
	OutsideSrcPort uint16
	OutsideDstIP   [4]byte
	OutsideDstPort uint16

	// Flags for special handling
	RewriteDestination bool
}

type NatPair struct {
	In         map[ExternalConnectionKey]*NatConn
	Out        map[InternalConnectionKey]*NatConn
	countMutex sync.RWMutex
	counts     map[SessionKey]uint64
}

func NewNatPair() NatPair {
	return NatPair{
		In:     make(map[ExternalConnectionKey]*NatConn),
		Out:    make(map[InternalConnectionKey]*NatConn),
		counts: make(map[SessionKey]uint64),
	}
}

// IncrementCount increments the connection count for a session, enforcing limits
// Must be called with the main NAT table mutex already locked
func (p *NatPair) IncrementCount(sess SessionKey) {
	p.countMutex.Lock()
	defer p.countMutex.Unlock()

	currentCount := p.counts[sess]

	// If at or above limit, drop the oldest connection first
	if currentCount >= natMaxConnectionsPerClient {
		p.dropOldestConnection(sess)
		// The count stays the same since we dropped one and are adding one
		return
	}

	// Increment the count
	p.counts[sess] = currentCount + 1
}

// DecrementCount decrements the connection count for a session
func (p *NatPair) DecrementCount(sess SessionKey) {
	p.countMutex.Lock()
	defer p.countMutex.Unlock()

	if p.counts[sess] > 0 {
		p.counts[sess]--
	}
	if p.counts[sess] == 0 {
		delete(p.counts, sess)
	}
}

// dropOldestConnection finds and removes the oldest connection for a given client
// Must be called with the main NAT table mutex already locked
// This method DOES NOT modify the count - caller is responsible for that
func (p *NatPair) dropOldestConnection(sess SessionKey) {
	var oldest *NatConn
	var oldestInKey InternalConnectionKey
	var oldestOutKey ExternalConnectionKey
	oldestTime := uint32(0xFFFFFFFF)

	// Find the oldest connection for this session
	for k, conn := range p.Out {
		if conn.Session == sess && atomic.LoadUint32(&conn.LastSeen) < oldestTime {
			oldest = conn
			oldestInKey = k
			oldestTime = atomic.LoadUint32(&conn.LastSeen)
		}
	}

	if oldest != nil {
		// Find the corresponding external key
		for k, conn := range p.In {
			if conn == oldest {
				oldestOutKey = k
				break
			}
		}
		// Remove from both maps
		delete(p.Out, oldestInKey)
		delete(p.In, oldestOutKey)
	}
}

// NatTable contains all NAT state
type NatTable struct {
	mutex sync.RWMutex
	TCP   NatPair
	UDP   NatPair
	ICMP  NatPair
}

// NewNatTable creates a new NAT table
func NewNatTable() *NatTable {
	return &NatTable{
		TCP:  NewNatPair(),
		UDP:  NewNatPair(),
		ICMP: NewNatPair(),
	}
}

// getAvailablePort returns an available port for NAT given destination IP/port
// dstIP and dstPort are used to ensure that the same port can be reused for different destinations
func (n *NatTable) getAvailablePort(protocol uint8, dstIP [4]byte, dstPort uint16) uint16 {
	// Already under mutex lock from caller

	// Loop to find an available port
	for attempt := 0; attempt < 100; attempt++ {
		// Generate a random port in the high port range
		port := uint16(rand.Intn(natMaxPort-natMinPort) + natMinPort)

		// Check if this port is already used for this destination based on protocol
		portInUse := false

		// Create a test key with natMasqueradeIP as source IP and the random port
		switch protocol {
		case 6: // TCP
			testKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   dstIP,
				SrcPort: port,
				DstPort: dstPort,
			}
			_, portInUse = n.TCP.In[testKey]

		case 17: // UDP
			testKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   dstIP,
				SrcPort: port,
				DstPort: dstPort,
			}
			_, portInUse = n.UDP.In[testKey]

		case 1: // ICMP
			testKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   dstIP,
				SrcPort: port,
			}
			_, portInUse = n.ICMP.In[testKey]
		}

		// If port is not used for this specific destination, we can use it
		if !portInUse {
			return port
		}
	}

	// Fallback: just use a random port if we couldn't find one after 100 attempts
	// This could create a collision, but it's very unlikely
	return uint16(rand.Intn(natMaxPort-natMinPort) + natMinPort)
}

// CleanExpiredConnections removes expired NAT connections
func (n *NatTable) CleanExpiredConnections() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	now := Now32()

	// Clean TCP connections
	for k, v := range n.TCP.Out {
		if atomic.LoadUint32(&v.LastSeen)+natTCPTimeout < now {
			delete(n.TCP.Out, k)
			// Decrement connection count for this client
			n.TCP.DecrementCount(v.Session)
		}
	}
	for k, v := range n.TCP.In {
		if atomic.LoadUint32(&v.LastSeen)+natTCPTimeout < now {
			delete(n.TCP.In, k)
		}
	}

	// Clean UDP connections
	for k, v := range n.UDP.Out {
		if atomic.LoadUint32(&v.LastSeen)+natUDPTimeout < now {
			delete(n.UDP.Out, k)
			// Decrement connection count for this client
			n.UDP.DecrementCount(v.Session)
		}
	}
	for k, v := range n.UDP.In {
		if atomic.LoadUint32(&v.LastSeen)+natUDPTimeout < now {
			delete(n.UDP.In, k)
		}
	}

	// Clean ICMP connections
	for k, v := range n.ICMP.Out {
		if atomic.LoadUint32(&v.LastSeen)+natICMPTimeout < now {
			delete(n.ICMP.Out, k)
			// Decrement connection count for this client
			n.ICMP.DecrementCount(v.Session)
		}
	}
	for k, v := range n.ICMP.In {
		if atomic.LoadUint32(&v.LastSeen)+natICMPTimeout < now {
			delete(n.ICMP.In, k)
		}
	}
}

// checkRedirectRules checks if packet matches any special redirect rules
// Returns: newDstIP, newDstPort, shouldRedirect
func (n *NatTable) checkRedirectRules(srcIP, dstIP [4]byte, srcPort, dstPort uint16) ([4]byte, uint16, bool) {
	// Check for DNS redirection rules
	if dstPort == natDNSOriginalPort {
		// Check first DNS server (10.0.0.243 -> port 5353)
		isDNS1 := true
		for i := 0; i < 4; i++ {
			if dstIP[i] != natDNSOriginalIP[i] {
				isDNS1 = false
				break
			}
		}
		if isDNS1 {
			// Destination matches first DNS server, redirect to port 5353
			return natDNSRedirectIP, natDNSRedirectPort, true
		}

		// Check ad-blocking DNS server (10.0.0.241 -> port 5354)
		isDNS2 := true
		for i := 0; i < 4; i++ {
			if dstIP[i] != natDNSOriginalIP2[i] {
				isDNS2 = false
				break
			}
		}
		if isDNS2 {
			// Destination matches adblock DNS server, redirect to port 5354
			return natDNSRedirectIP, natDNSRedirectPort2, true
		}
	}

	// Check for HTTPS redirection rule (10.0.0.129:443 -> 10.7.0.0:21443)
	if dstPort == 443 {
		for i := 0; i < 4; i++ {
			if dstIP[i] != natHTTPSRedirectIP[i] {
				return dstIP, dstPort, false
			}
		}

		// Destination matches HTTPS redirect IP, redirect to host on port 21443
		return natDNSRedirectIP, 21443, true
	}

	// No redirection needed
	return dstIP, dstPort, false
}

// HandleOutboundPacket processes packets from WireGuard to external network
func (n *NatTable) HandleOutboundPacket(packet []byte, sess SessionKey) ([]byte, bool) {
	if len(packet) < 20 {
		return nil, false // Packet too small to be IPv4
	}

	// Check if it's IPv4
	if (packet[0] >> 4) != 4 {
		return nil, false // Not IPv4, drop packet
	}

	// Get IP header length (IHL) in bytes
	ihl := int((packet[0] & 0x0F) * 4)
	if ihl < 20 || ihl > len(packet) {
		return nil, false // Invalid IP header length
	}

	// Get total packet length from IP header
	declaredLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if declaredLength < ihl {
		return nil, false // Invalid total length (smaller than header)
	}

	// Check if declared length is larger than actual packet (truncated packet)
	if declaredLength > len(packet) {
		return nil, false // Truncated packet
	}

	// Resize packet if needed (remove padding)
	if declaredLength < len(packet) {
		// Packet has padding, resize to declared length
		packet = packet[:declaredLength]
	}

	// Extract protocol
	protocol := packet[9]

	// Extract source and destination IP
	var srcIP, dstIP [4]byte
	copy(srcIP[:], packet[12:16])
	copy(dstIP[:], packet[16:20])

	// Update packet's total length for checksum calculation later
	packetLen := uint16(len(packet))

	// Handle based on protocol
	switch protocol {
	case 1: // ICMP
		if len(packet) < int(ihl)+4 {
			return nil, false // Packet too small
		}

		// Extract ICMP ID from echo request/reply
		icmpType := packet[ihl]
		if icmpType != 8 && icmpType != 0 { // Not echo request or reply
			// TODO support more packet types
			return nil, false // Drop packet
		}

		icmpId := uint16(packet[ihl+4])<<8 | uint16(packet[ihl+5])

		// Create ICMP connection key
		inKey := InternalConnectionKey{
			Session: sess,
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: icmpId,
		}

		// Look up existing connection
		n.mutex.RLock()
		conn, exists := n.ICMP.Out[inKey]
		n.mutex.RUnlock()

		if !exists {
			// Check if ICMP should be redirected (for DNS servers)
			shouldRedirect := false
			targetDstIP := dstIP

			// Check if destination is the first DNS server IP (10.0.0.243)
			isDNSServer1 := true
			for i := 0; i < 4; i++ {
				if dstIP[i] != natDNSOriginalIP[i] {
					isDNSServer1 = false
					break
				}
			}

			// Check if destination is the ad-blocking DNS server IP (10.0.0.241)
			isDNSServer2 := true
			for i := 0; i < 4; i++ {
				if dstIP[i] != natDNSOriginalIP2[i] {
					isDNSServer2 = false
					break
				}
			}

			if isDNSServer1 || isDNSServer2 {
				// Redirect ICMP to DNS redirect IP (10.7.0.0)
				// (works for both regular and adblock DNS servers)
				targetDstIP = natDNSRedirectIP
				shouldRedirect = true
			}

			// Create new NAT entry
			n.mutex.Lock()

			// Increment count and enforce limits
			n.ICMP.IncrementCount(sess)

			// Get an available port for this specific destination
			// We use ICMP ID as port so that we can remap the ID on transit in case there is a clash
			masqPort := n.getAvailablePort(protocol, targetDstIP, 0)

			conn = &NatConn{
				LastSeen: Now32(),
				Protocol: protocol,

				// WireGuard client identification
				Session: sess,

				// Local side
				LocalSrcIP:   srcIP,
				LocalSrcPort: icmpId,
				LocalDstIP:   dstIP,
				LocalDstPort: 0,

				// Outside side
				OutsideSrcIP:   natMasqueradeIP,
				OutsideSrcPort: masqPort,
				OutsideDstIP:   targetDstIP,
				OutsideDstPort: 0,

				// Flags
				RewriteDestination: shouldRedirect,
			}

			// Store in both directions
			n.ICMP.Out[inKey] = conn

			outKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   conn.OutsideDstIP,
				SrcPort: masqPort, // Use masquerade port as ICMP ID
			}
			n.ICMP.In[outKey] = conn

			n.mutex.Unlock()
		} else {
			// Update last seen time
			atomic.StoreUint32(&conn.LastSeen, Now32())
		}

		// Rewrite packet
		// 1. Change source IP to masquerade IP
		copy(packet[12:16], natMasqueradeIP[:])

		// 2. Change ICMP ID to masquerade port
		packet[ihl+4] = byte(conn.OutsideSrcPort >> 8)
		packet[ihl+5] = byte(conn.OutsideSrcPort)

		// 3. If destination should be rewritten, do it
		if conn.RewriteDestination {
			// Change destination IP
			copy(packet[16:20], conn.OutsideDstIP[:])
		}

		// 4. Recalculate IP header checksum
		packet[10] = 0
		packet[11] = 0
		checksum := calculateIPChecksum(packet[:ihl])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)

		// 5. Recalculate ICMP checksum
		packet[ihl+2] = 0
		packet[ihl+3] = 0
		icmpChecksum := calculateICMPChecksum(packet[ihl:])
		packet[ihl+2] = byte(icmpChecksum >> 8)
		packet[ihl+3] = byte(icmpChecksum)

		return packet, true
	case 6: // TCP
		if len(packet) < int(ihl)+4 {
			return nil, false // Packet too small
		}

		// Extract ports
		srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
		dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

		// Drop TCP packets destined to port 25 (SMTP)
		if dstPort == 25 {
			return nil, false
		}

		// Create connection key
		inKey := InternalConnectionKey{
			Session: sess,
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}

		// Look up existing connection
		n.mutex.RLock()
		conn, exists := n.TCP.Out[inKey]
		n.mutex.RUnlock()

		if !exists {
			// Check if destination should be rewritten (special redirect rules)
			redirectDstIP, redirectDstPort, shouldRedirect := n.checkRedirectRules(srcIP, dstIP, srcPort, dstPort)

			// Create new NAT entry
			n.mutex.Lock()

			// Increment count and enforce limits
			n.TCP.IncrementCount(sess)

			// Determine the target destination
			targetDstIP := dstIP
			targetDstPort := dstPort

			if shouldRedirect {
				targetDstIP = redirectDstIP
				targetDstPort = redirectDstPort
			}

			// Get an available port for this specific destination
			masqPort := n.getAvailablePort(protocol, targetDstIP, targetDstPort)

			conn = &NatConn{
				LastSeen: Now32(),
				Protocol: protocol,

				// WireGuard client identification
				Session: sess,

				// Local side
				LocalSrcIP:   srcIP,
				LocalSrcPort: srcPort,
				LocalDstIP:   dstIP,
				LocalDstPort: dstPort,

				// Outside side
				OutsideSrcIP:   natMasqueradeIP,
				OutsideSrcPort: masqPort,
				OutsideDstIP:   targetDstIP,
				OutsideDstPort: targetDstPort,

				// Flags
				RewriteDestination: shouldRedirect,
			}

			// Store in both directions
			n.TCP.Out[inKey] = conn

			outKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   conn.OutsideDstIP,
				SrcPort: masqPort,
				DstPort: conn.OutsideDstPort,
			}
			n.TCP.In[outKey] = conn

			n.mutex.Unlock()
		} else {
			// Update last seen time
			atomic.StoreUint32(&conn.LastSeen, Now32())
		}

		// Rewrite packet
		// 1. Change source IP to masquerade IP
		copy(packet[12:16], natMasqueradeIP[:])

		// 2. Change source port to masquerade port
		packet[ihl] = byte(conn.OutsideSrcPort >> 8)
		packet[ihl+1] = byte(conn.OutsideSrcPort)

		// 3. If destination should be rewritten, do it
		if conn.RewriteDestination {
			// Change destination IP
			copy(packet[16:20], conn.OutsideDstIP[:])

			// Change destination port
			packet[ihl+2] = byte(conn.OutsideDstPort >> 8)
			packet[ihl+3] = byte(conn.OutsideDstPort)
		}

		// 4. Recalculate IP header checksum
		packet[10] = 0
		packet[11] = 0
		checksum := calculateIPChecksum(packet[:ihl])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)

		// 5. Recalculate TCP checksum
		tcpLength := packetLen - uint16(ihl)
		packet[ihl+16] = 0
		packet[ihl+17] = 0
		tcpChecksum := calculateTCPUDPChecksum(packet, ihl, tcpLength, protocol)
		packet[ihl+16] = byte(tcpChecksum >> 8)
		packet[ihl+17] = byte(tcpChecksum)

		return packet, true

	case 17: // UDP
		if len(packet) < int(ihl)+8 {
			return nil, false // Packet too small
		}

		// Extract ports
		srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
		dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

		// Create connection key
		inKey := InternalConnectionKey{
			Session: sess,
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}

		// Look up existing connection
		n.mutex.RLock()
		conn, exists := n.UDP.Out[inKey]
		n.mutex.RUnlock()

		if !exists {
			// Check if destination should be rewritten (special redirect rules)
			redirectDstIP, redirectDstPort, shouldRedirect := n.checkRedirectRules(srcIP, dstIP, srcPort, dstPort)

			// Create new NAT entry
			n.mutex.Lock()

			// Increment count and enforce limits
			n.UDP.IncrementCount(sess)

			// Determine the target destination
			targetDstIP := dstIP
			targetDstPort := dstPort

			if shouldRedirect {
				targetDstIP = redirectDstIP
				targetDstPort = redirectDstPort
			}

			// Get an available port for this specific destination
			masqPort := n.getAvailablePort(protocol, targetDstIP, targetDstPort)

			conn = &NatConn{
				LastSeen: Now32(),
				Protocol: protocol,

				// WireGuard client identification
				Session: sess,

				// Local side
				LocalSrcIP:   srcIP,
				LocalSrcPort: srcPort,
				LocalDstIP:   dstIP,
				LocalDstPort: dstPort,

				// Outside side
				OutsideSrcIP:   natMasqueradeIP,
				OutsideSrcPort: masqPort,
				OutsideDstIP:   targetDstIP,
				OutsideDstPort: targetDstPort,

				// Flags
				RewriteDestination: shouldRedirect,
			}

			// Store in both directions
			n.UDP.Out[inKey] = conn

			outKey := ExternalConnectionKey{
				SrcIP:   natMasqueradeIP,
				DstIP:   conn.OutsideDstIP,
				SrcPort: masqPort,
				DstPort: conn.OutsideDstPort,
			}
			n.UDP.In[outKey] = conn

			n.mutex.Unlock()
		} else {
			// Update last seen time
			atomic.StoreUint32(&conn.LastSeen, Now32())
		}

		// Rewrite packet
		// 1. Change source IP to masquerade IP
		copy(packet[12:16], natMasqueradeIP[:])

		// 2. Change source port to masquerade port
		packet[ihl] = byte(conn.OutsideSrcPort >> 8)
		packet[ihl+1] = byte(conn.OutsideSrcPort)

		// 3. If destination should be rewritten, do it
		if conn.RewriteDestination {
			// Change destination IP
			copy(packet[16:20], conn.OutsideDstIP[:])

			// Change destination port
			packet[ihl+2] = byte(conn.OutsideDstPort >> 8)
			packet[ihl+3] = byte(conn.OutsideDstPort)
		}

		// 5. Recalculate UDP checksum
		udpLength := packetLen - uint16(ihl)
		packet[ihl+6] = 0
		packet[ihl+7] = 0
		udpChecksum := calculateTCPUDPChecksum(packet, ihl, udpLength, protocol)
		packet[ihl+6] = byte(udpChecksum >> 8)
		packet[ihl+7] = byte(udpChecksum)

		// 4. Recalculate IP header checksum
		packet[10] = 0
		packet[11] = 0
		checksum := calculateIPChecksum(packet[:ihl])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)

		return packet, true
	}

	// Unhandled protocol, pass through unchanged
	return packet, true
}

// HandleInboundPacket processes packets from external network to WireGuard
func (n *NatTable) HandleInboundPacket(packet []byte) ([]byte, SessionKey, bool) {
	if len(packet) < 20 {
		return nil, SessionKey{}, false // Packet too small to be IPv4
	}

	// Check if it's IPv4
	if (packet[0] >> 4) != 4 {
		return nil, SessionKey{}, false // not ipv4 → drop
	}

	// Get IP header length (IHL) in bytes
	ihl := int((packet[0] & 0x0F) * 4)
	if ihl < 20 || ihl > len(packet) {
		return nil, SessionKey{}, false // Invalid IP header length
	}

	// Get total packet length from IP header
	declaredLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if declaredLength < ihl {
		return nil, SessionKey{}, false // Invalid total length (smaller than header)
	}

	// Check if declared length is larger than actual packet (truncated packet)
	if declaredLength > len(packet) {
		return nil, SessionKey{}, false // Truncated packet
	}

	// Resize packet if needed (remove padding)
	if declaredLength < len(packet) {
		// Packet has padding, resize to declared length
		packet = packet[:declaredLength]
	}

	// Extract protocol
	protocol := packet[9]

	// Extract source and destination IP
	var srcIP, dstIP [4]byte
	copy(srcIP[:], packet[12:16])
	copy(dstIP[:], packet[16:20])

	// Check if destination is our masquerade IP
	for i := 0; i < 4; i++ {
		if dstIP[i] != natMasqueradeIP[i] {
			return nil, SessionKey{}, false // not for us → drop
		}
	}

	// Update packet's total length for checksum calculation later
	packetLen := uint16(len(packet))

	// Handle based on protocol
	switch protocol {
	case 1: // ICMP
		if len(packet) < int(ihl)+4 {
			return nil, SessionKey{}, false // Packet too small
		}

		// Extract ICMP type
		icmpType := packet[ihl]

		switch icmpType {
		case 3: // ICMP Destination Unreachable
			// ICMP error message contains the original packet's header + 64 bits of data
			// Minimal size required for an ICMP error message with embedded IPv4 header
			if len(packet) < int(ihl)+8+20 { // ICMP header (8) + embedded IPv4 header (20)
				return nil, SessionKey{}, false // Packet too small
			}

			// Access the embedded packet (starts after 8 bytes of ICMP header)
			embeddedOffset := ihl + 8
			if embeddedOffset+20 > len(packet) {
				return nil, SessionKey{}, false // Not enough space for embedded IPv4 header
			}

			// Extract the embedded packet's source and destination IPs and ports
			var embeddedSrcIP, embeddedDstIP [4]byte
			copy(embeddedSrcIP[:], packet[embeddedOffset+12:embeddedOffset+16]) // Source IP of original packet
			copy(embeddedDstIP[:], packet[embeddedOffset+16:embeddedOffset+20]) // Destination IP of original packet

			// This should be the masquerade IP, otherwise we can't find the connection
			for i := 0; i < 4; i++ {
				if embeddedSrcIP[i] != natMasqueradeIP[i] {
					return nil, SessionKey{}, false // Not our packet
				}
			}

			// Extract protocol of embedded packet
			embeddedProtocol := packet[embeddedOffset+9]

			// Extract ports from embedded packet based on protocol
			embeddedIhl := int((packet[embeddedOffset] & 0x0F) * 4)
			if embeddedOffset+embeddedIhl+4 > len(packet) {
				return nil, SessionKey{}, false // Not enough data to extract ports
			}

			var embeddedSrcPort, embeddedDstPort uint16

			// Extract ports based on embedded protocol
			switch embeddedProtocol {
			case 1: // ICMP
				// For ICMP, we use the ICMP ID as port
				if embeddedOffset+embeddedIhl+6 > len(packet) {
					return nil, SessionKey{}, false // Not enough data
				}
				embeddedDstPort = 0 // ICMP doesn't use dst port
				embeddedSrcPort = uint16(packet[embeddedOffset+embeddedIhl+4])<<8 | uint16(packet[embeddedOffset+embeddedIhl+5])
			case 6, 17: // TCP, UDP
				if embeddedOffset+embeddedIhl+4 > len(packet) {
					return nil, SessionKey{}, false // Not enough data
				}
				embeddedSrcPort = uint16(packet[embeddedOffset+embeddedIhl])<<8 | uint16(packet[embeddedOffset+embeddedIhl+1])
				embeddedDstPort = uint16(packet[embeddedOffset+embeddedIhl+2])<<8 | uint16(packet[embeddedOffset+embeddedIhl+3])
			default:
				return nil, SessionKey{}, false // Unsupported embedded protocol
			}

			// Create connection key for lookup based on the embedded packet
			var pairTable *NatPair
			switch embeddedProtocol {
			case 1: // ICMP
				pairTable = &n.ICMP
			case 6: // TCP
				pairTable = &n.TCP
			case 17: // UDP
				pairTable = &n.UDP
			default:
				return nil, SessionKey{}, false // Unsupported protocol
			}

			// Create lookup key - this is from the original outgoing packet
			inKey := ExternalConnectionKey{
				SrcIP:   embeddedSrcIP,   // Original source (masquerade IP)
				DstIP:   embeddedDstIP,   // Original destination
				SrcPort: embeddedSrcPort, // Original source port
				DstPort: embeddedDstPort, // Original destination port
			}

			// Look up the connection
			n.mutex.RLock()
			conn, exists := pairTable.In[inKey]
			n.mutex.RUnlock()

			if !exists {
				return nil, SessionKey{}, false // No matching connection
			}

			// Update last seen time
			atomic.StoreUint32(&conn.LastSeen, Now32())

			// Rewrite embedded packet to point to the correct client address
			// 1. Update the embedded source IP to the original destination
			copy(packet[embeddedOffset+12:embeddedOffset+16], conn.LocalDstIP[:])

			// 2. Update the embedded destination IP to the original client IP
			copy(packet[embeddedOffset+16:embeddedOffset+20], conn.LocalSrcIP[:])

			// 3. Update the embedded ports based on protocol
			switch embeddedProtocol {
			case 1: // ICMP
				// Update ICMP ID in the embedded packet
				packet[embeddedOffset+embeddedIhl+4] = byte(conn.LocalSrcPort >> 8)
				packet[embeddedOffset+embeddedIhl+5] = byte(conn.LocalSrcPort)
			case 6, 17: // TCP, UDP
				// Update source port in the embedded packet to the original destination port
				packet[embeddedOffset+embeddedIhl] = byte(conn.LocalDstPort >> 8)
				packet[embeddedOffset+embeddedIhl+1] = byte(conn.LocalDstPort)

				// Update destination port in the embedded packet to the original source port
				packet[embeddedOffset+embeddedIhl+2] = byte(conn.LocalSrcPort >> 8)
				packet[embeddedOffset+embeddedIhl+3] = byte(conn.LocalSrcPort)
			}

			// Recalculate embedded packet's IP checksum
			packet[embeddedOffset+10] = 0
			packet[embeddedOffset+11] = 0
			embeddedChecksum := calculateIPChecksum(packet[embeddedOffset : embeddedOffset+embeddedIhl])
			packet[embeddedOffset+10] = byte(embeddedChecksum >> 8)
			packet[embeddedOffset+11] = byte(embeddedChecksum)

			// Update outer packet destination IP to client IP
			copy(packet[16:20], conn.LocalSrcIP[:])

			// Update outer packet source IP if this was a redirected connection
			if conn.RewriteDestination {
				copy(packet[12:16], conn.LocalDstIP[:])
			}

			// Recalculate ICMP checksum
			packet[ihl+2] = 0
			packet[ihl+3] = 0
			icmpChecksum := calculateICMPChecksum(packet[ihl:])
			packet[ihl+2] = byte(icmpChecksum >> 8)
			packet[ihl+3] = byte(icmpChecksum)

			// Recalculate outer IP header checksum
			packet[10] = 0
			packet[11] = 0
			checksum := calculateIPChecksum(packet[:ihl])
			packet[10] = byte(checksum >> 8)
			packet[11] = byte(checksum)

			return packet, conn.Session, true

		case 0, 8: // Echo reply or Echo request
			icmpId := uint16(packet[ihl+4])<<8 | uint16(packet[ihl+5])

			// Create ICMP connection key for lookup
			// The connection was stored with:
			// - SrcIP: natMasqueradeIP (our NAT IP)
			// - DstIP: remote server's IP
			// - SrcPort: our chosen ICMP ID
			//
			// But the packet arrives with:
			// - SrcIP: remote server's IP
			// - DstIP: natMasqueradeIP (our NAT IP)
			// - ICMP ID: might be original or changed by server

			// We need to use the correct lookup key for the stored connection
			inKey := ExternalConnectionKey{
				SrcIP:   dstIP,  // Our NAT IP (natMasqueradeIP)
				DstIP:   srcIP,  // Remote server IP
				SrcPort: icmpId, // Using ICMP ID for lookup
			}

			n.mutex.RLock()
			conn, exists := n.ICMP.In[inKey]
			n.mutex.RUnlock()

			if !exists {
				// No matching connection, drop packet
				return nil, SessionKey{}, false
			}

			// Update last seen time
			atomic.StoreUint32(&conn.LastSeen, Now32())

			// Rewrite packet
			// 1. Change destination IP to original client IP
			copy(packet[16:20], conn.LocalSrcIP[:])

			// 2. If this was a redirected connection, change source IP/port back to what the client expects
			if conn.RewriteDestination {
				// Change source IP to the IP the client originally tried to reach
				copy(packet[12:16], conn.LocalDstIP[:])
			}

			// 3. Change ICMP ID back to original
			packet[ihl+4] = byte(conn.LocalSrcPort >> 8)
			packet[ihl+5] = byte(conn.LocalSrcPort)

			// 5. Recalculate ICMP checksum
			packet[ihl+2] = 0
			packet[ihl+3] = 0
			icmpChecksum := calculateICMPChecksum(packet[ihl:])
			packet[ihl+2] = byte(icmpChecksum >> 8)
			packet[ihl+3] = byte(icmpChecksum)

			// 4. Recalculate IP header checksum
			packet[10] = 0
			packet[11] = 0
			checksum := calculateIPChecksum(packet[:ihl])
			packet[10] = byte(checksum >> 8)
			packet[11] = byte(checksum)

			return packet, conn.Session, true

		default:
			// Unsupported ICMP type
			return nil, SessionKey{}, false
		}

	case 6: // TCP
		if len(packet) < int(ihl)+20 {
			return nil, SessionKey{}, false // Packet too small
		}

		// Extract ports
		srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
		dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

		// Create connection key for lookup
		// The connection was stored with:
		// - SrcIP: natMasqueradeIP (our NAT IP)
		// - DstIP: remote server's IP
		// - SrcPort: our chosen NAT port
		// - DstPort: remote server's port
		//
		// But the packet arrives with:
		// - SrcIP: remote server's IP
		// - DstIP: natMasqueradeIP (our NAT IP)
		// - SrcPort: remote server's port
		// - DstPort: our chosen NAT port
		//
		// We need to use the correct lookup key for the stored connection
		inKey := ExternalConnectionKey{
			SrcIP:   dstIP,   // Our NAT IP (natMasqueradeIP)
			DstIP:   srcIP,   // Remote server IP
			SrcPort: dstPort, // Our chosen NAT port
			DstPort: srcPort, // Remote server port
		}

		// Look up existing connection
		n.mutex.RLock()
		conn, exists := n.TCP.In[inKey]
		n.mutex.RUnlock()

		if !exists {
			// No matching connection found
			return nil, SessionKey{}, false
		}

		// Update last seen time
		atomic.StoreUint32(&conn.LastSeen, Now32())

		// Rewrite packet
		// 1. Change destination IP to original client IP
		copy(packet[16:20], conn.LocalSrcIP[:])

		// 2. Change destination port to original client port
		packet[ihl+2] = byte(conn.LocalSrcPort >> 8)
		packet[ihl+3] = byte(conn.LocalSrcPort)

		// 3. If this was a redirected connection, change source IP/port back to what the client expects
		if conn.RewriteDestination {
			// Change source IP to the IP the client originally tried to reach
			copy(packet[12:16], conn.LocalDstIP[:])

			// Change source port to the port the client originally tried to reach
			packet[ihl] = byte(conn.LocalDstPort >> 8)
			packet[ihl+1] = byte(conn.LocalDstPort)
		}

		// 5. Recalculate TCP checksum
		tcpLength := packetLen - uint16(ihl)
		packet[ihl+16] = 0
		packet[ihl+17] = 0
		tcpChecksum := calculateTCPUDPChecksum(packet, ihl, tcpLength, protocol)
		packet[ihl+16] = byte(tcpChecksum >> 8)
		packet[ihl+17] = byte(tcpChecksum)

		// 4. Recalculate IP header checksum
		packet[10] = 0
		packet[11] = 0
		checksum := calculateIPChecksum(packet[:ihl])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)

		return packet, conn.Session, true

	case 17: // UDP
		if len(packet) < int(ihl)+8 {
			return nil, SessionKey{}, false // Packet too small
		}

		// Extract ports
		srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
		dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

		// Create connection key for lookup with reversed src/dst
		// The connection was stored with:
		// - SrcIP: natMasqueradeIP (our NAT IP)
		// - DstIP: remote server's IP
		// - SrcPort: our chosen NAT port
		// - DstPort: remote server's port
		//
		// But the packet arrives with:
		// - SrcIP: remote server's IP
		// - DstIP: natMasqueradeIP (our NAT IP)
		// - SrcPort: remote server's port
		// - DstPort: our chosen NAT port
		//
		// We need to use the correct lookup key for the stored connection
		inKey := ExternalConnectionKey{
			SrcIP:   dstIP,   // Our NAT IP (natMasqueradeIP)
			DstIP:   srcIP,   // Remote server IP
			SrcPort: dstPort, // Our chosen NAT port
			DstPort: srcPort, // Remote server port
		}

		// Look up existing connection
		n.mutex.RLock()
		conn, exists := n.UDP.In[inKey]
		n.mutex.RUnlock()

		if !exists {
			// No matching connection found
			return nil, SessionKey{}, false
		}

		// Update last seen time
		atomic.StoreUint32(&conn.LastSeen, Now32())

		// Rewrite packet
		// 1. Change destination IP to original client IP
		copy(packet[16:20], conn.LocalSrcIP[:])

		// 2. Change destination port to original client port
		packet[ihl+2] = byte(conn.LocalSrcPort >> 8)
		packet[ihl+3] = byte(conn.LocalSrcPort)

		// 3. If this was a redirected connection, change source IP/port back to what the client expects
		if conn.RewriteDestination {
			// Change source IP to the IP the client originally tried to reach
			copy(packet[12:16], conn.LocalDstIP[:])

			// Change source port to the port the client originally tried to reach
			packet[ihl] = byte(conn.LocalDstPort >> 8)
			packet[ihl+1] = byte(conn.LocalDstPort)
		}

		// 5. Recalculate UDP checksum
		udpLength := packetLen - uint16(ihl)
		packet[ihl+6] = 0
		packet[ihl+7] = 0
		udpChecksum := calculateTCPUDPChecksum(packet, ihl, udpLength, protocol)
		packet[ihl+6] = byte(udpChecksum >> 8)
		packet[ihl+7] = byte(udpChecksum)

		// 4. Recalculate IP header checksum
		packet[10] = 0
		packet[11] = 0
		checksum := calculateIPChecksum(packet[:ihl])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)

		return packet, conn.Session, true
	}

	// Unhandled protocol, drop
	return nil, SessionKey{}, false
}

// StartCleanupRoutine starts the background cleanup routine
func (n *NatTable) StartCleanupRoutine() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			n.CleanExpiredConnections()
		}
	}()
}

// calculateIPChecksum calculates the checksum for an IP header
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(header[i])<<8 | uint32(header[i+1])
		} else {
			sum += uint32(header[i]) << 8
		}
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Take one's complement
	return ^uint16(sum)
}

// calculateICMPChecksum calculates the checksum for an ICMP packet
func calculateICMPChecksum(icmpBytes []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(icmpBytes); i += 2 {
		if i+1 < len(icmpBytes) {
			sum += uint32(icmpBytes[i])<<8 | uint32(icmpBytes[i+1])
		} else {
			sum += uint32(icmpBytes[i]) << 8
		}
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Take one's complement
	return ^uint16(sum)
}

// calculateTCPUDPChecksum calculates the checksum for TCP/UDP packets
func calculateTCPUDPChecksum(packet []byte, ihl int, length uint16, protocol uint8) uint16 {
	var sum uint32

	// Add pseudoheader fields
	srcIP := binary.BigEndian.Uint32(packet[12:16])
	dstIP := binary.BigEndian.Uint32(packet[16:20])

	sum += (srcIP >> 16) & 0xffff
	sum += srcIP & 0xffff
	sum += (dstIP >> 16) & 0xffff
	sum += dstIP & 0xffff
	sum += uint32(protocol)
	sum += uint32(length)

	// Add TCP/UDP data
	for i := ihl; i < ihl+int(length); i += 2 {
		if i+1 < len(packet) {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		} else if i < len(packet) {
			sum += uint32(packet[i]) << 8
		}
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Take one's complement
	return ^uint16(sum)
}
