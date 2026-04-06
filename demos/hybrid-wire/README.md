# crypto-lab-hybrid-wire demo

This demo shows a full **X25519 + ML-KEM-768 hybrid handshake** in the browser:

- a six-step live walkthrough of the hybrid key exchange
- a dual-wire view for the classical and post-quantum components
- a threat-model explanation for harvest-now, decrypt-later attacks
- deployed-today examples from browsers, CDNs, messaging, and SSH
- AES-256-GCM encrypted chat using the hybrid-derived session key
- a small benchmark comparing pure X25519, pure ML-KEM-768, and the hybrid handshake

## Live demo

https://systemslibrarian.github.io/crypto-lab-hybrid-wire/

## Run locally

```bash
npm install
npm run dev
```

Optional checks:

```bash
npm test
npm run build
```

## Package sources

The implementation uses verified package sources and Web Crypto primitives:

- `@noble/post-quantum` for `ml_kem768`
- `@noble/curves` for X25519 fallback support when native Web Crypto X25519 is unavailable
- browser `crypto.subtle` for HKDF-SHA-256 and AES-256-GCM

## Why hybrid instead of pure post-quantum?

A hybrid combiner keeps the session safe if **either** component remains secure:

- if X25519 stays secure, the session survives even if the PQ wire is weakened
- if ML-KEM-768 stays secure, the session survives even if a future quantum computer threatens X25519
- HKDF-SHA-256 mixes both secrets into a single 32-byte session key suitable for AES-256-GCM

## References

- IETF hybrid key exchange draft: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- ML-KEM FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST SP 800-56C Rev. 2: https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final
- Chromium deployment note: https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html

## Notes

- The app runs fully offline after `npm install`.
- No external CDNs are required at runtime.
- The X25519 module feature-detects native Web Crypto support and falls back to `@noble/curves` when needed.
