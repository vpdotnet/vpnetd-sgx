package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

// GET https://<wg_server_ip>:<wg_port>/addKey
// * pubkey (Client's public key (base64-encoded))
// * pt (token)
// Response: {"status": "OK", "peer_ip": "10.x.x.x/32", "server_key": "base64_encoded_server_public_key", "server_ip": "x.x.x.x", "server_port": 12345, "server_vip": "10.x.x.x"}

func (e *VPNEnclave) StartWgHttpServer() error {
	// create tls config
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "WG"},
		NotBefore:    Now(),
		NotAfter:     Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	cert, err := enclave.CreateAttestationCertificate(template, template, priv.Public(), priv)
	if err != nil {
		//return err
		// func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv any) ([]byte, error)
		cert, err = x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
		if err != nil {
			return fmt.Errorf("failed to create self-signed certificate: %w", err)
		}
	}

	// Write only the certificate to file in PEM format
	if err := writeCertificateToPEM(cert); err != nil {
		slog.Warn("Failed to write certificate to PEM file", "error", err)
		// Continue despite the error, as this is not critical for operation
	} else {
		slog.Info("Certificate written to PEM file", "path", "/var/run/vpnet/http.pem")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

	// listen on port WireguardPort
	s, err := tls.Listen("tcp", ":"+strconv.Itoa(WireguardPort), tlsConfig)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/addKey", e.wgAddKeyHandler)
	mux.HandleFunc("/stats", e.statsHandler)

	return http.Serve(s, mux)
}

// Helper function to send JSON responses
func sendJSONResponse(rw http.ResponseWriter, data interface{}) {
	buf, err := json.Marshal(data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	rw.Header().Set("Expires", time.Now().Add(-365*86400*time.Second).Format(time.RFC1123))
	rw.Write(buf)
}

// statsHandler provides statistics about the enclave via HTTP
func (e *VPNEnclave) statsHandler(rw http.ResponseWriter, req *http.Request) {
	// Get stats from various components
	stats := map[string]interface{}{
		"sessions_count":         e.identityVault.GetSessionCount(),
		"handshakes_processed":   atomic.LoadUint64(&e.stats.handshakesProcessed),
		"data_packets_processed": atomic.LoadUint64(&e.stats.dataPacketsProcessed),
		"errors":                 atomic.LoadUint64(&e.stats.errorCount),
		"packets_processed":      e.trafficProcessor.GetStatsPacketsProcessed(),
		"bytes_processed":        e.trafficProcessor.GetStatsBytesProcessed(),
		"timestamp":              time.Now().UnixNano() / int64(time.Millisecond),
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	json.NewEncoder(rw).Encode(stats)
}

type TokenInfo struct {
	Exp int64 `json:"exp"` // expiration time as unix timestamp
}

func (e *VPNEnclave) wgAddKeyHandler(rw http.ResponseWriter, req *http.Request) {
	slog.Debug("Received addKey request")

	pubkey := req.URL.Query().Get("pubkey")
	pt := req.URL.Query().Get("pt")

	if pubkey == "" {
		http.Error(rw, "pubkey is required", http.StatusBadRequest)
		return
	}
	if pt == "" {
		http.Error(rw, "pt is required", http.StatusBadRequest)
		return
	}

	// check validity of token
	// https://vp.net/_rest/Network/VPN/Token:check?token=19a2c63c397231fd9f8ee94b5444b63e357d7d7f17f98586
	// TODO need to move token verification so we instead make that a call to the local peer
	info, err := PostApi[TokenInfo]("Network/VPN/Token:check", map[string]any{"token": pt})
	if err != nil {
		slog.Error("Failed to check token", "error", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	// check expiration
	if info.Exp < Now().Unix() {
		http.Error(rw, "Subscription has expired", http.StatusPaymentRequired)
		return
	}

	//slog.Printf("[%s] Step 3: Calling AddKey method", remoteAddr)
	keyResp, err := e.keyManager.AddKey(pubkey, "http-api-client", 30)
	if err != nil {
		slog.Error("Error adding public key", "error", err)
		http.Error(rw, fmt.Sprintf("failed to add key: %v", err), http.StatusInternalServerError)
		return
	}

	// Process IP retrieval in a separate goroutine with timeout
	//slog.Printf("[%s] Step 6: Decoding public key", remoteAddr)

	// Decode the public key for IP lookup
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		slog.Error("Error decoding public key", "error", err)
		http.Error(rw, fmt.Sprintf("Invalid public key format: %v", err), http.StatusInternalServerError)
		return
	}

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

	// Get client IP with timeout
	//slog.Printf("[%s] Step 7: Retrieving client IP", remoteAddr)

	// Create response data map
	//slog.Printf("[%s] Step 9: Creating response data", remoteAddr)
	resData := make(map[string]any)

	// Copy relevant fields from keyResp, avoiding manual JSON marshaling/unmarshaling
	resData["status"] = "OK"
	resData["peer_pubkey"] = keyResp.PublicKey
	resData["server_key"] = keyResp.PeerPublicKey
	resData["description"] = keyResp.Description
	resData["dns_servers"] = []string{"10.0.0.243"}

	if keyResp.PresharedKey != "" {
		resData["preshared_key"] = keyResp.PresharedKey
	}

	// Add server info fields
	//slog.Printf("[%s] Step 10: Getting server IP", remoteAddr)
	// Extract server IP from the host or use a default if it can't be parsed
	serverIP := getPrimaryIP().String()
	if serverIP == "" {
		slog.Warn("getPrimaryIP returned empty string, using fallback IP")
		serverIP = "127.0.0.1" // Fallback IP
	}
	//slog.Printf("[%s] Using server IP: %s", remoteAddr, serverIP)

	resData["server_ip"] = serverIP
	resData["server_vip"] = "10.0.0.243"
	resData["server_port"] = WireguardPort
	resData["peer_ip"] = "10.7.0.2"

	// Encrypt the IP and send as encrypted_ip
	/*
		encryptedIP, err := e.keyManager.EncryptIPForPeer(clientIP, pubKey)
		if err != nil {
			slog.Error("Error encrypting IP for peer", "error", err)
			http.Error(rw, fmt.Sprintf("Failed to encrypt client IP: %v", err), http.StatusInternalServerError)
			return
		}
		resData["encrypted_ip"] = encryptedIP
	*/

	//slog.Printf("[%s] Step 11: Sending response for peer %s", remoteAddr, keyResp.PublicKey[:8])

	// Send the response
	sendJSONResponse(rw, resData)
	slog.Debug("addKey request completed successfully")
}

// writeCertificateToPEM writes the certificate to a PEM file at /var/run/vpnet/http.pem
func writeCertificateToPEM(cert []byte) error {
	// Ensure directory exists
	certDir := "/var/run/vpnet"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for certificate: %w", err)
	}

	// Prepare file path
	certPath := filepath.Join(certDir, "http.pem")

	// Create file
	file, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer file.Close()

	// Write certificate in PEM format
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return fmt.Errorf("failed to write PEM data: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(certPath, 0644); err != nil {
		return fmt.Errorf("failed to set certificate file permissions: %w", err)
	}

	return nil
}

func getPrimaryIP() net.IP {
	// Get public interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		// Skip loopback, non-up interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip nil IPs, loopback, and private addresses
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // skip ipv6
			}

			return ip
		}
	}
	return nil
}
