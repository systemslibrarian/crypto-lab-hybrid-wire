# crypto-lab-hybrid-wire demo

## 1. What It Is

This demo implements a hybrid key exchange that combines X25519 and ML-KEM-768, then derives a shared session key with HKDF-SHA-256 for AES-256-GCM encryption. It solves the transition problem of protecting sessions against both present-day classical attacks and future quantum-capable attackers. The protocol is asymmetric and post-quantum-hybrid because it mixes two independent key-establishment primitives into one output key. Security is designed so the session key remains safe if either primitive remains secure.

## 2. When to Use It

- Migrating TLS or secure transport stacks toward post-quantum readiness. Hybrid mode allows incremental rollout without abandoning mature classical components.
- Protecting traffic with long confidentiality lifetimes. It is useful when harvest-now, decrypt-later risk is part of your threat model.
- Validating implementation and performance impact before production rollout. The demo exposes concrete handshake steps, sizes, and timing.
- Extending existing X25519-based systems with a PQ wire. It fits architectures that want compatibility while introducing ML-KEM-768.
- Not ideal for very constrained bandwidth paths. The additional hybrid overhead can be too expensive where payload size is tightly limited.

## 3. Live Demo

Live GitHub Pages demo: https://systemslibrarian.github.io/crypto-lab-hybrid-wire/

You can walk through each handshake phase, watch both shared secrets concatenate into the HKDF combiner, and run encrypted chat with tamper detection after key derivation. The threat-model tab is interactive: switch either wire to "broken" and confirm the session survives any single break and only fails when both wires fall together. The interface includes tab controls for handshake flow, wire details, the resilience explorer, current deployments, and rationale. A benchmark control runs 50 iterations to compare X25519, ML-KEM-768, and hybrid execution rates.

The hybrid security claim is encoded as a pure, unit-tested function (`src/crypto/security.ts`) so the interactive explorer and the test suite evaluate exactly the same logic.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-wire.git
cd crypto-lab-hybrid-wire/demos/hybrid-wire
npm install
npm run dev
```

No environment variables are required.

## 5. Part of the Crypto-Lab Suite

This project is one entry in the broader suite at https://systemslibrarian.github.io/crypto-lab/.

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
