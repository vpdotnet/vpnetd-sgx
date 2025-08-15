package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

type wgPubKey [32]byte

// KeyManager manages Curve25519 keypairs for WireGuard authentication
type KeyManager struct {
	// Server keypair
	privateKey [32]byte
	publicKey  [32]byte

	// Peer keys (client public keys)
	peerKeys      map[wgPubKey]*PeerInfo
	peerKeysMutex sync.RWMutex
}

// PeerInfo contains information about a peer
type PeerInfo struct {
	PublicKey     [32]byte  `json:"public_key"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	PresharedKey  [32]byte  `json:"preshared_key,omitempty"` // Optional PSK
	HasPSK        bool      `json:"has_psk"`                 // Whether a PSK is set
}

// KeyResponse represents a key generation response
type KeyResponse struct {
	Success       bool      `json:"success"`
	Status        string    `json:"status"` // Set to "OK"
	PublicKey     string    `json:"public_key"`
	PrivateKey    string    `json:"private_key,omitempty"` // Only for newly generated keys
	PeerPublicKey string    `json:"server_key"`            // Server's public key
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	PresharedKey  string    `json:"preshared_key,omitempty"` // Optional PSK
}

// NewKeyManager creates a new key manager
func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{
		peerKeys: make(map[wgPubKey]*PeerInfo),
	}

	// Generate server keypair if not provided
	if err := km.generateServerKeys(); err != nil {
		return nil, err
	}

	return km, nil
}

// generateServerKeys generates server keypair if not already present
func (km *KeyManager) generateServerKeys() error {
	// Generate private key randomly
	if _, err := rand.Read(km.privateKey[:]); err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Clear bit patterns required by Curve25519
	km.privateKey[0] &= 248
	km.privateKey[31] &= 127
	km.privateKey[31] |= 64

	// Generate public key
	pubKeyBytes, err := curve25519.X25519(km.privateKey[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to generate public key: %v", err)
	}
	copy(km.publicKey[:], pubKeyBytes)

	slog.Info("Server keypair generated successfully")
	return nil
}

// Helper function to generate a random integer in a range
func randomInt(min, max int) (int, error) {
	if min >= max {
		return 0, fmt.Errorf("min must be less than max")
	}

	// Calculate range size
	delta := max - min

	// Generate random number
	n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		return 0, err
	}

	return min + int(n.Int64()), nil
}

// RegisterPeer registers a new peer's public key
func (km *KeyManager) RegisterPeer(peerPubKeyBytes []byte, description string, validDays int) (*KeyResponse, error) {
	slog.Info("Registering peer with description", "description", description)

	if len(peerPubKeyBytes) != 32 {
		slog.Error("Error: invalid public key length", "length", len(peerPubKeyBytes))
		return nil, fmt.Errorf("invalid public key length")
	}

	var peerPubKey [32]byte
	copy(peerPubKey[:], peerPubKeyBytes[:32])

	// Calculate expiration
	now := Now()
	expires := now.AddDate(0, 0, validDays)
	slog.Info("Setting expiration date", "expires", expires.Format(time.RFC3339))

	// Create peer info
	peerInfo := &PeerInfo{
		PublicKey:   peerPubKey,
		Description: description,
		CreatedAt:   now,
		ExpiresAt:   expires,
		HasPSK:      false,
	}

	// Check if this peer already exists - Quick read lock
	exists := false
	{
		km.peerKeysMutex.RLock()
		_, exists = km.peerKeys[peerPubKey]
		km.peerKeysMutex.RUnlock()
	}

	if exists {
		slog.Info("Peer already exists, updating information")
	}

	// Store peer - Short write lock
	{
		slog.Info("Storing peer information")
		km.peerKeysMutex.Lock()
		km.peerKeys[peerPubKey] = peerInfo
		km.peerKeysMutex.Unlock()
	}

	slog.Info("Peer registered successfully")

	// Return response with WireGuard formatted keys
	return &KeyResponse{
		Success:       true,
		Status:        "OK",
		PublicKey:     base64.StdEncoding.EncodeToString(peerPubKey[:]),
		PeerPublicKey: base64.StdEncoding.EncodeToString(km.publicKey[:]),
		Description:   description,
		CreatedAt:     now,
		ExpiresAt:     expires,
	}, nil
}

// GetServerPublicKey returns the server's public key
func (km *KeyManager) GetServerPublicKey() [32]byte {
	return km.publicKey
}

// GetServerPrivateKey returns the server's private key
func (km *KeyManager) GetServerPrivateKey() [32]byte {
	return km.privateKey
}

// IsAuthorizedPeer checks if a peer's public key is authorized
func (km *KeyManager) IsAuthorizedPeer(peerPubKey [32]byte) bool {
	// Get peer info with a short read lock
	km.peerKeysMutex.RLock()
	peerInfo, exists := km.peerKeys[peerPubKey]
	km.peerKeysMutex.RUnlock()

	if !exists {
		return false
	}

	// Check expiration if set (no lock needed)
	if !peerInfo.ExpiresAt.IsZero() && Now().After(peerInfo.ExpiresAt) {
		return false
	}

	return true
}

// AddAuthorizedPeer adds a peer's public key to the authorized list
// This is called when the host approves an unknown peer via WireguardAddPeer
func (km *KeyManager) AddAuthorizedPeer(peerPubKey [32]byte) {
	km.peerKeysMutex.Lock()
	defer km.peerKeysMutex.Unlock()

	// Check if peer already exists
	if _, exists := km.peerKeys[peerPubKey]; exists {
		slog.Debug("Peer already authorized")
		return
	}

	// Add new peer with basic info
	peerInfo := &PeerInfo{
		PublicKey:     peerPubKey,
		Description:   "Host-authorized peer",
		CreatedAt:     Now(),
		LastHandshake: Now(),
		HasPSK:        false,
	}

	km.peerKeys[peerPubKey] = peerInfo
	slog.Debug("Added authorized peer")
}

// UpdatePeerLastHandshake updates the last handshake time for a peer
func (km *KeyManager) UpdatePeerLastHandshake(peerPubKey [32]byte) {
	km.peerKeysMutex.RLock()
	defer km.peerKeysMutex.RUnlock()
	if peerInfo, exists := km.peerKeys[peerPubKey]; exists {
		peerInfo.LastHandshake = Now()
	}
}

// AddKey adds a new peer key with the given parameters
func (km *KeyManager) AddKey(pubkeyStr string, description string, validDays int) (*KeyResponse, error) {
	slog.Info("Adding new key with description", "description", description)

	if pubkeyStr == "" {
		slog.Info("Error: missing peer public key")
		return nil, fmt.Errorf("missing peer public key")
	}

	var peerPubKeyBytes []byte
	var err error

	slog.Info("Attempting to decode public key", "pubkey", pubkeyStr)

	// Try standard base64 with padding
	peerPubKeyBytes, err = base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil || len(peerPubKeyBytes) != 32 {
		slog.Info("Standard base64 decode failed, trying without padding", "error", err)
		// Try base64 without padding
		peerPubKeyBytes, err = base64.RawStdEncoding.DecodeString(pubkeyStr)
		if err != nil || len(peerPubKeyBytes) != 32 {
			slog.Info("Raw base64 decode failed, trying hex", "error", err)
			// Try hex as last resort
			peerPubKeyBytes, err = hex.DecodeString(pubkeyStr)
			if err != nil {
				slog.Error("All decode methods failed for pubkey", "error", err)
				return nil, fmt.Errorf("invalid public key format: %v", err)
			}
		}
	}

	if len(peerPubKeyBytes) != 32 {
		slog.Error("Invalid public key length", "got", len(peerPubKeyBytes), "expected", 32)
		return nil, fmt.Errorf("invalid public key length: got %d bytes, need 32", len(peerPubKeyBytes))
	}

	slog.Info("Successfully decoded public key")

	// Default value for description
	if description == "" {
		description = "imported-client"
	}

	// Default value for validDays
	if validDays <= 0 {
		validDays = 30
	}

	slog.Info("Registering peer", "description", description, "validDays", validDays)

	// Register the peer
	keyResp, err := km.RegisterPeer(peerPubKeyBytes, description, validDays)
	if err != nil {
		slog.Error("Error registering peer", "error", err)
		return nil, fmt.Errorf("failed to register peer: %v", err)
	}

	slog.Info("Peer registered successfully")

	// Generate and set PSK if enabled
	if DefaultWireguardPresharedKeysEnabled {
		slog.Info("Generating PSK for peer")
		psk, err := km.GeneratePresharedKey()
		if err != nil {
			slog.Error("Error generating PSK", "error", err)
			return nil, fmt.Errorf("failed to generate PSK: %v", err)
		}

		// Convert peerPubKeyBytes to array
		var pubKey [32]byte
		copy(pubKey[:], peerPubKeyBytes)

		// Set PSK for this peer
		slog.Info("Setting PSK for peer")
		if err := km.SetPresharedKeyForPeer(pubKey, psk); err != nil {
			slog.Error("Error setting PSK", "error", err)
			return nil, fmt.Errorf("failed to set PSK: %v", err)
		}

		// Add PSK to response
		keyResp.PresharedKey = base64.StdEncoding.EncodeToString(psk[:])
		slog.Info("PSK generated and set successfully")
	}

	slog.Info("Key added successfully")
	return keyResp, nil
}

// GetPresharedKeyForPeer returns the PSK for a given peer if available
func (km *KeyManager) GetPresharedKeyForPeer(peerPubKey [32]byte) ([32]byte, bool) {
	var zeroPSK [32]byte

	// Use a short read lock
	km.peerKeysMutex.RLock()
	peer, exists := km.peerKeys[peerPubKey]
	km.peerKeysMutex.RUnlock()

	if !exists {
		return zeroPSK, false
	}

	// Return the PSK if it exists (no lock needed as we've made a copy)
	if peer.HasPSK {
		return peer.PresharedKey, true
	}

	return zeroPSK, false
}

// SetPresharedKeyForPeer sets a PSK for a peer
func (km *KeyManager) SetPresharedKeyForPeer(peerPubKey [32]byte, psk [32]byte) error {
	// Only take write lock when we know the peer exists
	km.peerKeysMutex.RLock()
	defer km.peerKeysMutex.RUnlock()
	// Double-check since another thread might have removed it
	peer, exists := km.peerKeys[peerPubKey]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	// Set the PSK
	peer.PresharedKey = psk
	peer.HasPSK = true

	return nil
}

// GeneratePresharedKey generates a random PSK
func (km *KeyManager) GeneratePresharedKey() ([32]byte, error) {
	var psk [32]byte

	// Generate random PSK
	if _, err := rand.Read(psk[:]); err != nil {
		return psk, fmt.Errorf("failed to generate PSK: %v", err)
	}

	return psk, nil
}

// GetPresharedKey returns the preshared key for a given peer
func (km *KeyManager) GetPresharedKey(peerPubKey [32]byte) [32]byte {
	var zeroPSK [32]byte
	psk, exists := km.GetPresharedKeyForPeer(peerPubKey)
	if exists {
		return psk
	}
	return zeroPSK
}
