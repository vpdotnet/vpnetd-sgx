package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ============================================================
// Cross-language compatibility tests
//
// These tests use hardcoded inputs and assert hardcoded expected
// outputs. The Rust test suite at vpnetd-sgx-rust/tests/compat_test.rs
// uses identical inputs and expected values, proving both
// implementations produce byte-identical results.
// ============================================================

// ============================================================
// 1. Protocol constants
// ============================================================

func TestCompatInitialChainKey(t *testing.T) {
	expected := "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"
	got := hex.EncodeToString(InitialChainKey[:])
	if got != expected {
		t.Fatalf("InitialChainKey mismatch: got %s, want %s", got, expected)
	}
}

func TestCompatInitialHash(t *testing.T) {
	expected := "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"
	got := hex.EncodeToString(InitialHash[:])
	if got != expected {
		t.Fatalf("InitialHash mismatch: got %s, want %s", got, expected)
	}
}

// ============================================================
// 2. Crypto primitives
// ============================================================

func TestCompatMixHash(t *testing.T) {
	var h [32]byte // all zeros
	var dst [32]byte
	data := []byte("test data")

	mixHash(&dst, &h, data)

	got := hex.EncodeToString(dst[:])
	expected := "4082624f3b76e3c65cd6d569d2c6a08401646122827ce629091c0249a15cffab"
	if got != expected {
		t.Fatalf("mixHash mismatch: got %s, want %s", got, expected)
	}
}

func TestCompatHMAC1(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	input := []byte("hmac test input")
	var sum [32]byte

	HMAC1(&sum, key, input)

	got := hex.EncodeToString(sum[:])
	expected := "a72f9c8a76fda0b29f8e78f890fbf801f78ed4d2ac7e764fc9444b5d631b7d6a"
	if got != expected {
		t.Fatalf("HMAC1 mismatch: got %s, want %s", got, expected)
	}
}

func TestCompatKDF1(t *testing.T) {
	var key [32]byte // all zeros
	input := []byte("kdf1 test")
	var t0 [32]byte

	KDF1(&t0, key[:], input)

	got := hex.EncodeToString(t0[:])
	expected := "47fc9a3aa5fa1294fa976df8999b6099eb5523cf8007ec741594db4babe1a911"
	if got != expected {
		t.Fatalf("KDF1 mismatch: got %s, want %s", got, expected)
	}
}

func TestCompatKDF2(t *testing.T) {
	var key [32]byte // all zeros
	input := []byte("kdf2 test")
	var t0, t1 [32]byte

	KDF2(&t0, &t1, key[:], input)

	got0 := hex.EncodeToString(t0[:])
	got1 := hex.EncodeToString(t1[:])
	exp0 := "0a6b655650aba439b76aae9728b36f434731ff12725a72d25c2959b24e07393a"
	exp1 := "ca212db9e22b895cf908adcbb8f17cc72bf601373a87bb473933c2aaa236b611"
	if got0 != exp0 {
		t.Fatalf("KDF2 t0 mismatch: got %s, want %s", got0, exp0)
	}
	if got1 != exp1 {
		t.Fatalf("KDF2 t1 mismatch: got %s, want %s", got1, exp1)
	}
}

func TestCompatMAC1Key(t *testing.T) {
	var publicKey [32]byte
	for i := 0; i < 32; i++ {
		publicKey[i] = byte(i + 1)
	}

	result := calculateMAC1Key(publicKey)
	got := hex.EncodeToString(result[:])
	expected := "121b33018813efaa1d3128cdec1392897828e98831f01822c250ddfdf7090183"
	if got != expected {
		t.Fatalf("calculateMAC1Key mismatch: got %s, want %s", got, expected)
	}
}

// ============================================================
// 3. Curve25519 key derivation
// ============================================================

func TestCompatCurve25519KeyDerivation(t *testing.T) {
	var privkey [32]byte
	for i := range privkey {
		privkey[i] = 0x77
	}
	// Clamp
	privkey[0] &= 248
	privkey[31] &= 127
	privkey[31] |= 64

	pubkey, err := curve25519.X25519(privkey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}

	got := hex.EncodeToString(pubkey)
	expected := "1cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67"
	if got != expected {
		t.Fatalf("X25519 pubkey mismatch: got %s, want %s", got, expected)
	}

	// Also test shared secret (DH)
	var bobPriv [32]byte
	for i := range bobPriv {
		bobPriv[i] = 0x88
	}
	bobPriv[0] &= 248
	bobPriv[31] &= 127
	bobPriv[31] |= 64

	bobPub, _ := curve25519.X25519(bobPriv[:], curve25519.Basepoint)
	shared1, _ := curve25519.X25519(privkey[:], bobPub)
	shared2, _ := curve25519.X25519(bobPriv[:], pubkey)

	h1 := hex.EncodeToString(shared1)
	h2 := hex.EncodeToString(shared2)
	if h1 != h2 {
		t.Fatalf("shared secret mismatch: alice=%s, bob=%s", h1, h2)
	}

	expectedShared := "28f9816c74bb247a7bf39fce1c17df73be4f7ae513b04bcecf2cb29760bf445d"
	if h1 != expectedShared {
		t.Fatalf("shared secret mismatch: got %s, want %s", h1, expectedShared)
	}
}

// ============================================================
// 4. ChaCha20-Poly1305
// ============================================================

func TestCompatChaCha20Poly1305(t *testing.T) {
	var key [32]byte
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	// nonce: first 4 bytes zero, then counter=1 as little-endian u64
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], 1)

	plaintext := []byte("hello wireguard")

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce[:], plaintext, nil)
	got := hex.EncodeToString(ciphertext)
	expected := "f7329f33da0ad8715bd3c92933e7fd67f437183fc25046ed0fd4856eec4b4c"
	if got != expected {
		t.Fatalf("AEAD encrypt mismatch: got %s, want %s", got, expected)
	}

	// Verify decrypt
	decrypted, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		t.Fatalf("AEAD decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("AEAD decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Test with AAD
	aad := []byte("additional data")
	ciphertextAAD := aead.Seal(nil, nonce[:], plaintext, aad)
	gotAAD := hex.EncodeToString(ciphertextAAD)
	t.Logf("AEAD with AAD hex: %s", gotAAD)

	decryptedAAD, err := aead.Open(nil, nonce[:], ciphertextAAD, aad)
	if err != nil {
		t.Fatalf("AEAD decrypt with AAD failed: %v", err)
	}
	if string(decryptedAAD) != string(plaintext) {
		t.Fatalf("AEAD decrypt with AAD mismatch")
	}
}

// ============================================================
// 5. NAT checksums
// ============================================================

func TestCompatIPChecksum(t *testing.T) {
	header := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0xac, 0x10, 0x0a, 0x63,
		0xac, 0x10, 0x0a, 0x0c,
	}

	checksum := calculateIPChecksum(header)
	var expected uint16 = 0xb1e6
	if checksum != expected {
		t.Fatalf("IP checksum mismatch: got 0x%04x, want 0x%04x", checksum, expected)
	}
}

func TestCompatTCPChecksum(t *testing.T) {
	packet := make([]byte, 40)

	packet[0] = 0x45
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 0x40
	packet[9] = 0x06
	packet[12] = 192
	packet[13] = 168
	packet[14] = 1
	packet[15] = 1
	packet[16] = 192
	packet[17] = 168
	packet[18] = 1
	packet[19] = 2

	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 80)
	binary.BigEndian.PutUint32(packet[24:28], 1000)
	binary.BigEndian.PutUint32(packet[28:32], 0)
	packet[32] = 0x50
	packet[33] = 0x02
	binary.BigEndian.PutUint16(packet[34:36], 65535)

	tcpLength := uint16(20)
	checksum := calculateTCPUDPChecksum(packet, 20, tcpLength, 6)
	var expected uint16 = 0xf81d
	if checksum != expected {
		t.Fatalf("TCP checksum mismatch: got 0x%04x, want 0x%04x", checksum, expected)
	}
}

func TestCompatUDPChecksum(t *testing.T) {
	// 20-byte IP header + 8-byte UDP header + 5-byte payload = 33 bytes
	packet := make([]byte, 33)

	packet[0] = 0x45
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], 33)
	packet[8] = 0x40
	packet[9] = 17 // UDP
	packet[12] = 10
	packet[13] = 0
	packet[14] = 0
	packet[15] = 1
	packet[16] = 10
	packet[17] = 0
	packet[18] = 0
	packet[19] = 2

	binary.BigEndian.PutUint16(packet[20:22], 4000) // src port
	binary.BigEndian.PutUint16(packet[22:24], 53)   // dst port
	binary.BigEndian.PutUint16(packet[24:26], 13)   // UDP length
	// checksum at [26:28] = 0
	copy(packet[28:], []byte("hello"))

	udpLength := uint16(13)
	checksum := calculateTCPUDPChecksum(packet, 20, udpLength, 17)
	t.Logf("UDP checksum: 0x%04x", checksum)

	var expected uint16 = 0x982a
	if checksum != expected {
		t.Fatalf("UDP checksum mismatch: got 0x%04x, want 0x%04x", checksum, expected)
	}
}

func TestCompatICMPChecksum(t *testing.T) {
	icmpBytes := []byte{
		0x08, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x61, 0x62, 0x63, 0x64,
	}

	checksum := calculateICMPChecksum(icmpBytes)
	var expected uint16 = 0x3337
	if checksum != expected {
		t.Fatalf("ICMP checksum mismatch: got 0x%04x, want 0x%04x", checksum, expected)
	}
}

// ============================================================
// 6. IPC varint encoding
// ============================================================

func TestCompatVarintEncoding(t *testing.T) {
	expectedMap := map[uint64]string{
		0:     "00",
		1:     "01",
		127:   "7f",
		128:   "8001",
		255:   "ff01",
		300:   "ac02",
		16383: "ff7f",
		16384: "808001",
	}

	for v, expected := range expectedMap {
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(buf, v)
		got := hex.EncodeToString(buf[:n])
		if got != expected {
			t.Fatalf("varint(%d) mismatch: got %s, want %s", v, got, expected)
		}
	}
}

// ============================================================
// 7. IPC command framing
// ============================================================

func TestCompatCommandFraming(t *testing.T) {
	// Wire format: [2-byte cmd BE] [varint payload_len] [payload]
	// cmd=0x0100, payload="hello" (5 bytes)
	// Expected: 01 00 05 68 65 6c 6c 6f
	cmd := uint16(0x0100)
	payload := []byte("hello")

	var frame []byte
	frame = append(frame, byte(cmd>>8), byte(cmd))
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, uint64(len(payload)))
	frame = append(frame, buf[:n]...)
	frame = append(frame, payload...)

	got := hex.EncodeToString(frame)
	expected := "010005" + hex.EncodeToString(payload)
	if got != expected {
		t.Fatalf("command framing mismatch: got %s, want %s", got, expected)
	}
}

// ============================================================
// 8. Sliding window replay detection
// ============================================================

func TestCompatSlidingWindow(t *testing.T) {
	var sw SlidingWindow
	sw.Reset()

	type testCase struct {
		counter  uint64
		expected bool // true = replay (rejected)
	}

	cases := []testCase{
		{0, false},    // first packet, not replay
		{0, true},     // duplicate, replay
		{1, false},    // new packet
		{5, false},    // new packet
		{3, false},    // within window, not seen
		{3, true},     // duplicate
		{8191, false}, // far ahead, moves window
		{0, true},     // now too old
	}

	for i, tc := range cases {
		got := sw.CheckReplay(tc.counter)
		if got != tc.expected {
			t.Fatalf("case %d: CheckReplay(%d) = %v, want %v", i, tc.counter, got, tc.expected)
		}
	}
}

// ============================================================
// 9. Additional crypto: mixPSK, KDF3
// ============================================================

func TestCompatMixPSK(t *testing.T) {
	var chainingKey [32]byte
	var hash [32]byte
	var key [chacha20poly1305.KeySize]byte
	var psk [32]byte

	for i := range chainingKey {
		chainingKey[i] = 0x01
	}
	for i := range hash {
		hash[i] = 0x02
	}
	for i := range psk {
		psk[i] = 0x03
	}

	mixPSK(&chainingKey, &hash, &key, psk)

	gotCK := hex.EncodeToString(chainingKey[:])
	gotH := hex.EncodeToString(hash[:])
	gotK := hex.EncodeToString(key[:])

	expCK := "6d86490628b7a4577c60c6ee22c8ae9e43cb83089e2a64b745d563bc43574d9c"
	expH := "ebe2266793de1ba1d155b7992e2359a7eac60d413fa3f782b93973919fb44951"
	expK := "7f53191f1a2725863d5188134117f9132a40667cbcbb80a33e6ebba01235239d"

	if gotCK != expCK {
		t.Fatalf("mixPSK chainingKey mismatch: got %s, want %s", gotCK, expCK)
	}
	if gotH != expH {
		t.Fatalf("mixPSK hash mismatch: got %s, want %s", gotH, expH)
	}
	if gotK != expK {
		t.Fatalf("mixPSK key mismatch: got %s, want %s", gotK, expK)
	}
}

func TestCompatKDF3(t *testing.T) {
	var key [32]byte // all zeros
	data := []byte("kdf3 test")
	var t0, t1, t2 [32]byte

	KDF3(&t0, &t1, &t2, data, key[:])

	got0 := hex.EncodeToString(t0[:])
	got1 := hex.EncodeToString(t1[:])
	got2 := hex.EncodeToString(t2[:])

	exp0 := "a83658b1943aa5de3ee019cf9a6b1c41f4f4cee7a9f02c1c609453ef318d6150"
	exp1 := "5baf0f3d6f22afe89b2d49be5ee48860f406bb9b6bdc24c900e15df49ae43a51"
	exp2 := "6d67d6384654f8b9a960d51aeedcc8ab6b2c172e93f9563092f9017a9df2c619"

	if got0 != exp0 {
		t.Fatalf("KDF3 t0 mismatch: got %s, want %s", got0, exp0)
	}
	if got1 != exp1 {
		t.Fatalf("KDF3 t1 mismatch: got %s, want %s", got1, exp1)
	}
	if got2 != exp2 {
		t.Fatalf("KDF3 t2 mismatch: got %s, want %s", got2, exp2)
	}
}

// ============================================================
// 10. Cookie MAC1 verification
// ============================================================

func TestCompatCookieMAC1(t *testing.T) {
	var publicKey [32]byte
	for i := 0; i < 32; i++ {
		publicKey[i] = byte(i + 1)
	}

	var cc CookieChecker
	cc.mac1.key = calculateMAC1Key(publicKey)

	// Build a fake 148-byte initiation message with known bytes
	msg := make([]byte, 148)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	// Zero out MAC1 and MAC2 areas (offsets 116-148)
	for i := 116; i < 148; i++ {
		msg[i] = 0
	}

	// Compute MAC1 using blake2s-128 keyed hash over msg[0:116]
	mac, err := blake2s.New128(cc.mac1.key[:])
	if err != nil {
		t.Fatalf("failed to create MAC1 hash: %v", err)
	}
	mac.Write(msg[:116])
	var computed [16]byte
	mac.Sum(computed[:0])
	copy(msg[116:132], computed[:])

	// Verify CheckMAC1 returns true
	if !cc.CheckMAC1(msg) {
		t.Fatalf("CheckMAC1 should return true for correctly computed MAC1")
	}
}
