package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

type SessionKey struct {
	IP   [16]byte // use To16
	Port uint16
}

func (s SessionKey) String() string {
	return fmt.Sprintf("%s:%d", net.IP(s.IP[:]), s.Port)
}

// IdentityVault manages session IDs, virtual IPs, and encryption keys
// This component processes packets without access to correlation data
type IdentityVault struct {
	keyManager *KeyManager // Reference to KeyManager for peer IP lookup

	sessions      map[SessionKey]*SessionInfo
	sessionsMutex sync.RWMutex

	// Statistics (only counts, no identifying information)
	stats struct {
		sessionsCreated int
		sessionsActive  int
	}
}

// SessionInfo represents a client session
type SessionInfo struct {
	SessionID  SessionKey   // Unique session identifier
	RemoteAddr *net.UDPAddr // Client's remote address
	LastActive time.Time    // Last activity time

	// WireGuard specific
	IsEstablished bool     // Whether session has completed handshake
	PeerPublicKey [32]byte // WireGuard peer public key
	RemoteIndex   uint32   // WireGuard remote index for sending packets

	// Handshake completion tracking
	HasCompletedHandshake bool      // Whether a full handshake with data was completed
	HandshakeTime         time.Time // When handshake was completed
}

// NewIdentityVault creates a new identity vault
func NewIdentityVault(keyManager *KeyManager) *IdentityVault {
	return &IdentityVault{
		keyManager: keyManager,
		sessions:   make(map[SessionKey]*SessionInfo),
	}
}

// CreateSession creates a new session
func (iv *IdentityVault) CreateSession(sessionID SessionKey, remoteAddr *net.UDPAddr) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session already exists
	if _, exists := iv.sessions[sessionID]; exists {
		return fmt.Errorf("session already exists: %s", sessionID)
	}

	// Create session info without assigning IP yet
	// IP will be assigned when PeerPublicKey is set during handshake completion
	now := Now()
	sessionInfo := &SessionInfo{
		SessionID:             sessionID,
		RemoteAddr:            remoteAddr,
		LastActive:            now,
		IsEstablished:         false,
		HasCompletedHandshake: false,
	}

	// Store session
	iv.sessions[sessionID] = sessionInfo

	// Update statistics
	iv.stats.sessionsCreated++
	iv.stats.sessionsActive++

	return nil
}

// GetSessionInfo gets information about a session
func (iv *IdentityVault) GetSessionInfo(sessionID SessionKey) (*SessionInfo, error) {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	// Check if session exists
	sessionInfo, exists := iv.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Update last active time
	sessionInfo.LastActive = Now()

	return sessionInfo, nil
}

// UpdateSessionPeerKey updates the WireGuard peer key for a session
func (iv *IdentityVault) UpdateSessionPeerKey(sessionID SessionKey, peerKey [32]byte) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session exists
	sessionInfo, exists := iv.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Update peer key
	sessionInfo.PeerPublicKey = peerKey

	return nil
}

// UpdateSessionRemoteIndex updates the WireGuard remote index for a session
func (iv *IdentityVault) UpdateSessionRemoteIndex(sessionID SessionKey, remoteIndex uint32) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session exists
	sessionInfo, exists := iv.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Update remote index
	sessionInfo.RemoteIndex = remoteIndex

	return nil
}

// TerminateSession terminates a session
func (iv *IdentityVault) TerminateSession(sessionID SessionKey) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session exists
	_, exists := iv.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Remove session
	delete(iv.sessions, sessionID)

	// Update statistics
	iv.stats.sessionsActive--

	return nil
}

// LookupSessionByPeerKey looks up a session by WireGuard peer key
func (iv *IdentityVault) LookupSessionByPeerKey(peerKey [32]byte) (SessionKey, error) {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	// TODO FIXME use index

	// Search for session with matching peer key
	for sessionID, sessionInfo := range iv.sessions {
		if bytes.Equal(peerKey[:], sessionInfo.PeerPublicKey[:]) {
			return sessionID, nil
		}
	}

	return SessionKey{}, fmt.Errorf("no session found for peer key: %x", peerKey[:8])
}

// GetSessionCount returns the number of active sessions
func (iv *IdentityVault) GetSessionCount() int {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	return len(iv.sessions)
}

// CleanupIdleSessions removes idle sessions
func (iv *IdentityVault) CleanupIdleSessions() {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	now := Now()
	idle := DefaultIdleTimeout

	for sessionID, sessionInfo := range iv.sessions {
		if now.Sub(sessionInfo.LastActive) > idle {
			// Remove session
			delete(iv.sessions, sessionID)

			// Update statistics
			iv.stats.sessionsActive--

		}
	}
}

// UpdateSessionRemoteAddr updates the remote address for a session
func (iv *IdentityVault) UpdateSessionRemoteAddr(sessionID SessionKey, remoteAddr *net.UDPAddr) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session exists
	sessionInfo, exists := iv.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Update remote address
	oldAddr := sessionInfo.RemoteAddr
	sessionInfo.RemoteAddr = remoteAddr

	if oldAddr != remoteAddr {
	}

	return nil
}

// IsSessionValid checks if a session exists and is valid
func (iv *IdentityVault) IsSessionValid(sessionID SessionKey) bool {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	_, exists := iv.sessions[sessionID]
	return exists
}

// GetAllSessions returns a list of all session IDs
func (iv *IdentityVault) GetAllSessions() []SessionKey {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	sessions := make([]SessionKey, 0, len(iv.sessions))
	for sessionID := range iv.sessions {
		sessions = append(sessions, sessionID)
	}

	return sessions
}

// DumpSessions returns information about all sessions for stats reporting
// This returns only basic information, not the full session objects
func (iv *IdentityVault) DumpSessions() []map[string]interface{} {
	iv.sessionsMutex.RLock()
	defer iv.sessionsMutex.RUnlock()

	result := make([]map[string]interface{}, 0, len(iv.sessions))

	for sessionID, info := range iv.sessions {
		// Format session ID for display
		sessionIDStr := fmt.Sprintf("%s:%d",
			net.IP(sessionID.IP[:]).String(),
			sessionID.Port)

		// Create sanitized session info map
		sessionMap := map[string]interface{}{
			"id":                 sessionIDStr,
			"established":        info.IsEstablished,
			"handshake_complete": info.HasCompletedHandshake,
			"last_active":        info.LastActive.UnixNano() / int64(time.Millisecond),
		}

		result = append(result, sessionMap)
	}

	return result
}

// Close closes the identity vault
func (iv *IdentityVault) Close() error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Terminate all sessions
	for sessionID := range iv.sessions {
		// Remove session
		delete(iv.sessions, sessionID)

	}

	iv.stats.sessionsActive = 0

	return nil
}

// CreatePreliminarySession creates a session that's not fully established yet
func (iv *IdentityVault) CreatePreliminarySession(sessionID SessionKey, remoteAddr *net.UDPAddr) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session already exists
	if _, exists := iv.sessions[sessionID]; exists {
		return fmt.Errorf("session already exists: %s", sessionID)
	}

	// Create session info
	now := Now()
	sessionInfo := &SessionInfo{
		SessionID:             sessionID,
		RemoteAddr:            remoteAddr,
		LastActive:            now,
		IsEstablished:         false, // Mark as not fully established
		HasCompletedHandshake: false,
	}

	// Store session
	iv.sessions[sessionID] = sessionInfo

	// Update statistics
	iv.stats.sessionsCreated++
	iv.stats.sessionsActive++

	return nil
}

// MarkSessionEstablished marks a session as fully established
func (iv *IdentityVault) MarkSessionEstablished(sessionID SessionKey) error {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	// Check if session exists
	sessionInfo, exists := iv.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Mark as established
	sessionInfo.IsEstablished = true

	return nil
}

// MarkHandshakeComplete marks a session as having completed a handshake
func (iv *IdentityVault) MarkHandshakeComplete(sessionID SessionKey) {
	iv.sessionsMutex.Lock()
	defer iv.sessionsMutex.Unlock()

	if sessionInfo, exists := iv.sessions[sessionID]; exists {
		sessionInfo.HasCompletedHandshake = true
		sessionInfo.HandshakeTime = Now()
	}
}
