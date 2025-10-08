package main

const (
	// Data packets
	CmdTUN uint16 = 0x0100 // TUN data, read or write depending of which side sends it. Format is raw l3 IP packet
	CmdUDP uint16 = 0x0101 // UDP data, prefixed with 18 bytes session ID (16 bytes IP followed by 2 bytes port)

	// Unknown peer handling
	//
	// If a handshake packet is received from a peer for which we have no record (public key isn't known), we call
	// the host process (random connection) to ask for confirmation. The host will either drop the request if nothing
	// should be done, or respond with the WireguardAddPeer packet in case the peer is to be accepted. The host
	// will actually not care about anything after the 32 bytes public key, and just pass it as is in case it is to
	// be allowed, which means we can alter this if needed.
	// Currently we will be sending remote addr (16 bytes IP followed by 2 bytes port) followed by the actual wireguard
	// handshake that was received, allowing for a response to be sent.
	WireguardUnknownPeer uint16 = 0x0200 // (enclave to host) handshake from a unknown peer, contains: <0x0200> <32 bytes public key> <remote addr+wireguard handshake packet>
	WireguardAddPeer     uint16 = 0x0201 // (host to enclave) add a specific public key as new peer. <0x0201> <32 bytes public key> <optional remote addr+wireguard handshake packet>

	// Peer verification (token-based)
	ReqPeerVerifyToken  uint16 = 0x0202 // (enclave to host) verify peer token. <0x0202> <8 bytes reqID bigendian> <token string>
	RespPeerVerifyToken uint16 = 0x0203 // (host to enclave) response to verify token. <0x0203> <8 bytes reqID bigendian> <8 bytes expiration unix timestamp bigendian, 0 if invalid>

	// Peer verification (pubkey-based)
	ReqPeerVerifyPubkey  uint16 = 0x0204 // (enclave to host) verify peer by pubkey. <0x0204> <8 bytes reqID bigendian> <32 bytes pubkey binary>
	RespPeerVerifyPubkey uint16 = 0x0205 // (host to enclave) response to verify pubkey. <0x0205> <8 bytes reqID bigendian> <8 bytes expiration unix timestamp bigendian, 0 if invalid>
)
