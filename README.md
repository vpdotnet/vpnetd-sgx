# VP.NET SGX Backend System

This repository contains the source code for the VP.NET SGX backend system. We release this code under an audit-only license to enable public verification of our privacy commitments and allow users to confirm they are connecting to servers running the exact code published here.

## Privacy Guarantee

VP.NET is built on a foundation of zero-knowledge privacy. By publishing our SGX enclave source code, we enable users to:

- Verify our no-logging policy through code inspection
- Confirm that servers cannot access user data or traffic patterns  
- Validate that the code running on our servers matches this public repository

## Deterministic Compilation and Verification

When you build this repository, it produces a unique mrenclave value - a cryptographic hash of the enclave code. This value is deterministic, meaning the same source code always produces the same mrenclave.

### How Verification Works

1. Build the code locally to generate the mrenclave value
2. Connect to a VP.NET server and retrieve its mrenclave
3. Compare the values - if they match, you have cryptographic proof that the server is running the exact code in this repository

This process ensures that:

- No backdoors or logging code can be secretly added
- The server behavior matches what you can audit in this repository
- Your privacy is protected by transparent, verifiable code

## Building the Project

### Prerequisites

- Linux
- Docker

### Build Instructions

# Clone the repository

    git clone https://github.com/vpdotnet/vpnetd-sgx.git
    cd vpnetd-sgx

# Create docker image for ego

    docker build -t ubuntu-ego .

# Build the SGX enclave

    make

# The build will output the mrenclave value
# Example: mrenclave=e16af534aeb32fd4eb0e0517ace05fd10d4890bf155163f2987537dd8f782286
### Verifying the mrenclave

After building, you can find the mrenclave value in the build output or by running:

/pkg/main/sys-devel.edgelessrt.dev/bin/oesign dump --enclave-image vpnetd-sgx | grep mrenclave
## Architecture

The VP.NET SGX backend implements a dual-layer security architecture combining the rasengan Core and MagicalTux Layer:

### rasengan Core

The core processes all traffic within Intel SGX secure enclaves using a concentrated, spiraling security model:

- Zero-Knowledge Architecture: The enclave processes traffic without storing or logging any user data
- Perfect Forward Secrecy: Keys are rotated regularly and never persisted
- Host Isolation: The enclave maintains strict isolation from the host system

### MagicalTux Layer

The sophisticated traffic mixing, obfuscation and cloaking system that wraps the core processing:

- Connection Pool Randomization: Packets are routed through different connections from the pool using round-robin load balancing
- Traffic Obfuscation: Padding and dummy traffic prevent traffic analysis
- Packet Buffering and Timing Protection: A 10ms flush interval batches packets together for temporal obfuscation
- Traffic Pattern Masking: Dummy traffic is generated at configurable intervals with random packet sizes
- NAT Processing: Network Address Translation happens within the enclave for complete privacy
- Memory-Safe Operations: All sensitive data is cleared from memory after use

## Security Features

### SGX Enclave Protection
All processing happens within Intel SGX secure enclaves with the following guarantees:

- Attestation Support: Clients can verify enclave integrity before connecting
- No Persistent Storage: The enclave has no access to disk storage
- Minimal Attack Surface: Limited system calls and isolated execution
- No Direct Memory Access: The host cannot read enclave memory

### Privacy Controls

#### No Logging of Sensitive Information
The enclave implements strict privacy controls to prevent information leakage:

- No PII Logging: IP addresses, public keys, session IDs, and other personally identifiable information are not logged
- Debug-Only Diagnostics: Sensitive operations use debug-level logging that is disabled in production
- Sanitized Error Messages: Error messages are generic and do not reveal user-specific details
- Memory Clearing: Cryptographic materials and sensitive data are explicitly zeroed after use

#### Traffic Flow Obfuscation
The enclave implements several mechanisms to prevent traffic correlation attacks:

Connection Pool Randomization
- Packets sent back to the host are routed through different connections from the pool
- Round-robin load balancing ensures no single connection can be used to track packet flow
- This prevents the host from correlating incoming and outgoing packets

Packet Buffering and Timing Protection
- Packets destined for the host are buffered before transmission
- A 10ms flush interval batches packets together
- This temporal obfuscation prevents timing correlation attacks
- The buffering system balances security with performance, ensuring minimal latency impact

Traffic Pattern Masking
- Dummy traffic is generated at configurable intervals (default 30 seconds) with random packet sizes (64-1024 bytes)
- Padding rounds packet sizes up to 32-byte blocks with random data to prevent size-based analysis
- Keep-alive packets maintain connection liveness (10 second timeout)
- Dummy packets use reserved counter values (0xFFFFFFFFFFFFFFFF) so clients can identify and discard them

### Host Isolation
The enclave maintains strict isolation from the host system:

- No Direct Memory Access: The host cannot read enclave memory
- Encrypted Communication: All data leaving the enclave is encrypted
- Minimal Host Interface: Only essential commands are accepted from the host
- Stateless Processing: No session state is shared with the host

## Client Connection Process

VP.NET implements a custom server that speaks the WireGuard® protocol. Clients use standard WireGuard® software to connect to VP.NET servers.

### Client Registration Flow (WireGuard® Protocol)

1. Key Generation: The client generates a public/private key pair locally using standard WireGuard® software

2. API Request: The client sends an HTTPS GET request to /addKey with query parameters:
   - pubkey: Base64-encoded public key
   - pt: Authentication token

3. Token Validation: The server validates the token by:
   - Checking with the backend API (Network/VPN/Token:check)
   - Verifying the token hasn't expired

4. Peer Registration: If valid, the KeyManager:
   - Registers the client as a peer with 30-day expiration
   - Assigns a VPN IP address (e.g., 10.7.0.2)
   - Optionally generates a preshared key for additional security

5. Response: Server returns JSON with:
   - server_key: Server's public key for the WireGuard® protocol
   - server_ip: Server's public IP address
   - server_vip: VPN server IP (10.0.0.243) - used by clients to send ping requests for connection liveness checks
   - server_port: Protocol port (51820)
   - peer_ip: Suggested client VPN IP - clients can use any IP they prefer as the server will properly route all client IPs
   - dns_servers: Internal DNS servers (["10.0.0.243"])
   - preshared_key: (optional) Additional security key

6. VPN Connection: Client configures their WireGuard® software with the provided details and establishes the VPN tunnel using the WireGuard® protocol

This token-based registration ensures only authenticated clients can join the VPN network, with automatic key expiration for enhanced security.

## License

This code is licensed under the Source Available for Examination (SAFE) License v1.0.

The SAFE License permits examination, auditing, security research, and verification of this code while prohibiting commercial use, distribution, and production deployment. This software and the techniques implemented herein may be protected by patents or pending patent applications.

Permitted: Code examination, security auditing, building for verification, academic research  
Prohibited: Commercial use, production deployment, distribution, offering as a service

For commercial licensing inquiries, please contact VP.NET.

## Contributing

While this is an audit-only repository, we welcome:

- Security vulnerability reports (please report privately first)
- Documentation improvements
- Bug reports related to privacy or security

## Contact

- For security issues: security@vp.net
- For general inquiries: support@vp.net

## Trademark Notice

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. VP.NET implements a custom server that is compatible with the WireGuard® protocol but is not affiliated with or endorsed by the WireGuard project.

By making our SGX backend code public, we demonstrate our commitment to transparency and user privacy. Trust through verification, not promises.

Don't trust, verify.
