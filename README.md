# crypto-lab-hybrid-wire

## 1. What It Is

This project is a browser demo of a hybrid key exchange that combines X25519 and ML-KEM-768, then derives a session key with HKDF-SHA-256 for AES-256-GCM message encryption. It addresses the transition problem where systems need confidentiality against both classical and future quantum-capable adversaries. The design is asymmetric and post-quantum-hybrid: two independent key-establishment wires are combined into one session key. The security goal is that the resulting session remains protected if either X25519 or ML-KEM-768 remains secure.

## 2. When to Use It

- Deploying internet-facing TLS during post-quantum migration. Hybrid exchange is appropriate when you need practical compatibility today while adding PQ resilience.
- Protecting long-lived or high-value encrypted traffic. It fits when harvest-now, decrypt-later risk matters and you want both classical and PQ assumptions in the same handshake.
- Testing protocol behavior before production rollout. It helps teams evaluate handshake overhead, key sizes, and implementation complexity with concrete measurements.
- Messaging or service bootstrapping that already uses X25519. It is a direct fit when existing systems can add ML-KEM-768 as a second wire without redesigning all crypto.
- Not for low-power or highly constrained links where bytes are critical. The extra key and ciphertext sizes (+2,272 bytes vs pure X25519) may be too costly.

## 3. Live Demo

Live GitHub Pages demo: https://systemslibrarian.github.io/crypto-lab-hybrid-wire/

The demo lets you step through a six-stage handshake, inspect both wires, and run encrypted chat with tamper detection after session derivation. You can navigate tabs for the live handshake, two-wire breakdown, threat model, deployed examples, and rationale. The benchmark control runs repeated iterations (50) to compare X25519, ML-KEM-768, and hybrid performance.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-wire.git
cd crypto-lab-hybrid-wire/demos/hybrid-wire
npm install
npm run dev
```

No environment variables are required.

## 5. Part of the Crypto-Lab Suite

This demo is part of the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
