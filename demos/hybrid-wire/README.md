# crypto-lab-hybrid-wire demo

## 1. What It Is

This demo implements a hybrid key exchange that combines X25519 and ML-KEM-768, then derives a shared session key with HKDF-SHA-256 for AES-256-GCM encryption. It solves the transition problem of protecting sessions against both present-day classical attacks and future quantum-capable attackers. The protocol is asymmetric and post-quantum-hybrid because it mixes two independent key-establishment primitives into one output key. Security is designed so the session key remains safe if either primitive remains secure.

The crypto is real, not simulated: X25519 comes from the browser's native WebCrypto (with a `@noble/curves` fallback), ML-KEM-768 from `@noble/post-quantum` (FIPS 203), and the combiner and record encryption from WebCrypto HKDF-SHA-256 and AES-256-GCM. The benchmark numbers shown in the UI are measured live in your browser, not baked-in figures.

> **Do NOT use this in production.** It is a browser teaching demo of the hybrid handshake, not a vetted, hardened, side-channel-resistant library. Use a reviewed TLS stack (e.g. the IETF `X25519MLKEM768` group) for real deployments.

## 2. When to Use It

- Migrating TLS or secure transport stacks toward post-quantum readiness. Hybrid mode allows incremental rollout without abandoning mature classical components.
- Protecting traffic with long confidentiality lifetimes. It is useful when harvest-now, decrypt-later risk is part of your threat model.
- Validating implementation and performance impact before production rollout. The demo exposes concrete handshake steps, sizes, and timing.
- Extending existing X25519-based systems with a PQ wire. It fits architectures that want compatibility while introducing ML-KEM-768.
- Not ideal for very constrained bandwidth paths. The additional hybrid overhead can be too expensive where payload size is tightly limited.

## 3. Live Demo

Live GitHub Pages demo: https://systemslibrarian.github.io/crypto-lab-hybrid-wire/

You can walk through each handshake phase, watch both shared secrets concatenate into the HKDF combiner, and run encrypted chat with tamper detection after key derivation. The threat-model tab is interactive: switch either wire to "broken" and confirm the session survives any single break and only fails when both wires fall together. The interface includes tab controls for handshake flow, wire details, the resilience explorer, current deployments, and rationale. A benchmark control runs 50 iterations to compare X25519, ML-KEM-768, and hybrid execution rates.

The exhibit is layered for both newcomers and cryptographers:

1. **Live handshake** — a six-step stepper with a wire diagram whose animation carries meaning: a labelled token rides the blue wire when the X25519 secret is derived, and the purple wire when the ML-KEM ciphertext travels back and the PQ secret is recovered; at step 6 both tokens slide into an HKDF box and the pulse stops. The per-wire byte details, outcome metrics, combiner, and secure chat are revealed progressively so the six-step narrative isn't drowned by a wall of cards.
2. **Two wires** — sizes and the HKDF combiner formula, fronted by a collapsible **"What is a KEM?"** aside that contrasts X25519 (a symmetric Diffie-Hellman exchange, both sides do the same operation) with ML-KEM (an asymmetric encapsulate → ciphertext → decapsulate flow), which is why the purple wire sends a packet back and the blue wire does not.
3. **Threat model** — the "prove it yourself" resilience explorer. Toggles define **"broken"** explicitly ("assume the attacker has recovered *this* wire's 32-byte secret") and, when a wire is broken, reveal its live secret bytes as *known to attacker* while the surviving wire's bytes stay masked — so a learner literally sees that HKDF's input is still half-unknown after a single break.
4. **Deployed today** — real-world hybrid rollouts (Chrome, Cloudflare, Signal PQXDH, AWS s2n-tls, iCloud PQ3, OpenSSH).
5. **Why hybrid** — the rationale, portfolio connections, and a **"Twice as strong? No"** callout that names and refutes the natural wrong guess (hybrid is a hedge in series — break both to win — not a doubling of security bits).

The hybrid security claim is encoded as a pure, unit-tested function (`src/crypto/security.ts`) so the interactive explorer and the test suite evaluate exactly the same logic.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-wire.git
cd crypto-lab-hybrid-wire/demos/hybrid-wire
npm install
npm run dev
```

No environment variables are required.

## 5. Running the Tests

The crypto is covered by Vitest unit tests (handshake round-trips, HKDF combiner
determinism and independence, forgery rejection, and the resilience claim) plus a
strict accessibility gate driven by Playwright + axe-core.

```bash
npm test          # Vitest: crypto correctness + resilience claim (src/__tests__/)
npm run build     # type-check (tsc --noEmit) + production build
npm run test:a11y # Playwright + axe-core WCAG A/AA gate, both themes
```

`npm test` runs only the unit suite under `src/__tests__/`; the Playwright a11y
specs under `e2e/` are a separate command and are not collected by Vitest.

## 6. A Note on the Combiner

The HKDF combiner (`combineSecrets` in `src/crypto/hybrid.ts`) concatenates the
two shared secrets — `HKDF(x25519_secret || mlkem_secret)` — exactly as in
[draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/).
It does **not** itself bind the ML-KEM ciphertext or the public keys into the KDF
context. That transcript binding is provided one layer up by TLS 1.3, where the
hybrid secret enters the key schedule alongside the handshake transcript hash.
This demo has no surrounding TLS transcript, so the combiner is unbound on its own.
If you reuse this combiner in a protocol without an outer transcript, add the KEM
ciphertext and both peers' public keys to the HKDF `info` (or a transcript hash)
so the derived key commits to the handshake it came from. See the comment on
`combineSecrets` for the full explanation.

## 7. Part of the Crypto-Lab Suite

This project is one entry in the broader suite at https://systemslibrarian.github.io/crypto-lab/.

### Related Demos

- [crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/) — the decision guide and combiner theory behind this exact hybrid.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — the X25519MLKEM768 hybrid inside a real TLS 1.3 key schedule.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the post-quantum wire of this exchange.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — the same defense-in-depth idea applied to signatures.
- [crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) — a Double Ratchet over X25519 + HKDF + AES-256-GCM, the classical messaging counterpart.

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
