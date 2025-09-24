// File: enclave/constants.go

package main

import (
	"time"
)

// WireGuard protocol constants
const (
	// WireGuard message types
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4

	// Control packet types
	ControlTypeKeepAlive  = 0x01
	ControlTypeDisconnect = 0x02
	ControlTypeRotateKeys = 0x03

	// Message response size
	MessageResponseSize = 92 // Size of handshake response message
)

// Packet type constants
const (
	PacketTypeData    byte = 0x01
	PacketTypeControl byte = 0x02
	PacketTypeAuth    byte = 0x03
)

// Various settings
const (
	ReceiveBufferSize  = 128 * 1024 // Size of buffer for data TO SGX
	ReusableBufferSize = 1500       // size of re-usable read buffer
	SendBufferSize     = 65536      // Size of buffer for data FROM SGX
	WireguardPort      = 443        // Used to be 51820
)

// Default config values from Config struct
const (
	// Server configuration
	DefaultBindAddress       = "0.0.0.0"
	DefaultOutboundInterface = ""

	// Networking parameters
	DefaultIdleTimeoutSec = 300 // 5 minutes

	// Privacy features
	DefaultEnablePadding        = true
	DefaultPaddingBlockSize     = 32 // Increased from 16 for better privacy
	DefaultEnableDummyTraffic   = true
	DefaultDummyTrafficMinSize  = 64
	DefaultDummyTrafficMaxSize  = 1024
	DefaultDummyTrafficRateSec  = 30
	DefaultEnableTrafficMixing  = true
	DefaultTrafficMixingDelayMS = 100 // Increased from 50 for better mixing

	// Memory management
	DefaultHeapSizeMB       = 400
	DefaultPacketBufferSize = 16384

	// Perfect Forward Secrecy configuration
	DefaultEnablePFS         = true
	DefaultPFSKeyRotationSec = 300 // 5 minutes

	// Privacy policy
	DefaultZeroKnowledgeMode = true
	DefaultLogLevel          = 1 // INFO
)

// Default WireGuard configuration
const (
	DefaultWireguardListenPort           = 51820
	DefaultWireguardEndpointPort         = 51820
	DefaultWireguardPersistentKeepalive  = 25
	DefaultWireguardAllowedIPs           = "10.7.0.0/16"
	DefaultWireguardKeyRotationSec       = 600
	DefaultWireguardPresharedKeysEnabled = false
)

// Default time durations
var (
	DefaultIdleTimeout              = time.Duration(DefaultIdleTimeoutSec) * time.Second
	DefaultDummyTrafficRate         = time.Duration(DefaultDummyTrafficRateSec) * time.Second
	DefaultPFSKeyRotationTime       = time.Duration(DefaultPFSKeyRotationSec) * time.Second
	DefaultWireguardKeyRotationTime = time.Duration(DefaultWireguardKeyRotationSec) * time.Second
)
