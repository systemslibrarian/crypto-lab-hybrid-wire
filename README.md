# crypto-lab-hybrid-wire

## What It Is

This project is a browser demo of a hybrid key exchange that combines X25519 and ML-KEM-768, then derives a session key with HKDF-SHA-256 for AES-256-GCM message encryption. It addresses the transition problem where systems need confidentiality against both classical and future quantum-capable adversaries. The design is asymmetric and post-quantum-hybrid: two independent key-establishment wires are combined into one session key. The security goal is that the resulting session remains protected if either X25519 or ML-KEM-768 remains secure.

## When to Use It

- Deploying internet-facing TLS during post-quantum migration. Hybrid exchange is appropriate when you need practical compatibility today while adding PQ resilience.
- Protecting long-lived or high-value encrypted traffic. It fits when harvest-now, decrypt-later risk matters and you want both classical and PQ assumptions in the same handshake.
- Testing protocol behavior before production rollout. It helps teams evaluate handshake overhead, key sizes, and implementation complexity with concrete measurements.
- Messaging or service bootstrapping that already uses X25519. It is a direct fit when existing systems can add ML-KEM-768 as a second wire without redesigning all crypto.
- Not for low-power or highly constrained links where bytes are critical. The extra key and ciphertext sizes (+2,272 bytes vs pure X25519) may be too costly.
- Do NOT use this in production. It is a browser teaching demo of the hybrid handshake, not a vetted, hardened library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/)**

The demo lets you step through a six-stage handshake, watch both shared secrets feed the HKDF combiner, and run encrypted chat with tamper detection after session derivation. The threat-model tab is interactive: toggle either wire to "broken" and prove the core claim yourself — the session only fails when X25519 *and* ML-KEM-768 fall together. You can navigate tabs for the live handshake, two-wire breakdown, resilience explorer, deployed examples, and rationale. The benchmark control runs repeated iterations (50) to compare X25519, ML-KEM-768, and hybrid performance.

## What Can Go Wrong

- Combining the two shared secrets badly. XOR-ing or truncating raw secrets can void the security argument; the secrets must flow through a sound KDF (HKDF here) that binds both wires.
- Larger handshake messages. The added ML-KEM-768 key and ciphertext (+2,272 bytes vs X25519) can push a ClientHello past one packet and trip middlebox ossification on old network gear.
- Treating the hybrid as twice as strong. It is a hedge, not a multiplier: it survives a break of either wire, but a flaw in the combiner or in either implementation can still sink the session.
- Mismatched parameters or versions between peers. If the two ends disagree on the KEM parameter set or the HKDF/transcript binding, key agreement fails or, worse, silently weakens.
- Carrying the classical wire forever. Hybrid is a migration tool; the plan should include moving to PQ-native once ML-KEM has more cryptanalytic maturity.

## Real-World Usage

- TLS 1.3 hybrid key exchange. The IETF-named X25519MLKEM768 group pairs X25519 with ML-KEM-768 in the handshake and is now widely supported across browsers and servers.
- Cloudflare and Google. Both have deployed and measured hybrid post-quantum key exchange on production traffic during the migration period.
- Harvest-now-decrypt-later defense. Hybrids are enabled today so that traffic recorded now cannot be decrypted later once large-scale quantum computers exist.
- AES-256-GCM data protection. The derived session key feeds an AEAD cipher, the same record-protection pattern used by TLS and modern secure channels.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-wire
cd crypto-lab-hybrid-wire/demos/hybrid-wire
npm install
npm run dev
```

## Related Demos

- [crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/) — the decision guide and combiner theory behind this exact hybrid.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — the X25519MLKEM768 hybrid inside a real TLS 1.3 key schedule.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the post-quantum wire of this exchange.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — the same defense-in-depth idea applied to signatures.
- [crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) — a Double Ratchet over X25519 + HKDF + AES-256-GCM, the classical messaging counterpart.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
