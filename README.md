# crypto-lab-hybrid-wire

`crypto-lab-hybrid-wire` is a browser-based demo of **hybrid post-quantum key exchange** using **X25519 + ML-KEM-768** with **HKDF-SHA256** and **AES-256-GCM**.

## Hybrid Key Exchange catalog entry

| Field | Value |
|---|---|
| Scheme | X25519 + ML-KEM-768 hybrid |
| Classical component | X25519 (Curve25519 ECDH) |
| Post-quantum component | ML-KEM-768 (NIST FIPS 203) |
| Key derivation | HKDF-SHA256 |
| Security | Safe if either primitive is secure |
| Handshake overhead | +2,272 bytes vs pure X25519 |
| Deployed in | Chrome 124+, Cloudflare, AWS, Signal, iCloud |
| Standard | IETF `draft-ietf-tls-hybrid-design` |

## Portfolio connections

- `crypto-lab-ratchet-wire` → the classical X25519-only baseline; `hybrid-wire` is the post-quantum upgrade path used in deployments like Signal PQXDH.
- `crypto-lab-kyber-vault` → shows ML-KEM alone; `hybrid-wire` shows how it combines with X25519 in real production handshakes.
- `crypto-lab-dilithium-seal` → hybrid-wire handles confidentiality, while Dilithium-style signatures handle authentication.
- `crypto-lab-iron-serpent` → hybrid-wire negotiates the shared key; symmetric encryption carries the application data.

## Demo

**Live demo:** https://systemslibrarian.github.io/crypto-lab-hybrid-wire/

The implementation lives in `demos/hybrid-wire/` and includes:

- live six-step handshake visualization
- threat model and deployment notes
- encrypted chat with tamper detection
- browser benchmark for X25519 vs ML-KEM-768 vs hybrid
