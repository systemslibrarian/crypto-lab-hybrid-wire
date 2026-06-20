// The core security claim of a hybrid handshake, expressed as a pure function so
// the demo and the test suite evaluate the *same* logic.
//
// session_key = HKDF-SHA-256(x25519_secret || mlkem_secret)
//
// Because both secrets feed the combiner, an attacker must recover BOTH to
// reconstruct the input keying material. Breaking a single wire leaves the
// other one carrying the session. This is the property every learner should be
// able to prove for themselves on the Threat model tab.

export type ResilienceLevel = 'protected' | 'degraded' | 'compromised';

export type SurvivingWire = 'both' | 'x25519' | 'mlkem' | 'none';

export interface ResilienceVerdict {
  level: ResilienceLevel;
  survivingWire: SurvivingWire;
  headline: string;
  detail: string;
}

export function evaluateResilience(x25519Broken: boolean, mlkemBroken: boolean): ResilienceVerdict {
  if (!x25519Broken && !mlkemBroken) {
    return {
      level: 'protected',
      survivingWire: 'both',
      headline: 'Session protected',
      detail:
        'Both wires are intact. An attacker would need to break the classical X25519 secret and the post-quantum ML-KEM-768 secret to rebuild the HKDF input.',
    };
  }

  if (x25519Broken && !mlkemBroken) {
    return {
      level: 'degraded',
      survivingWire: 'mlkem',
      headline: 'Session still safe',
      detail:
        'X25519 fell — imagine a future quantum computer breaking the classical curve. The post-quantum ML-KEM-768 secret is still unknown to the attacker, so the HKDF input cannot be reconstructed.',
    };
  }

  if (!x25519Broken && mlkemBroken) {
    return {
      level: 'degraded',
      survivingWire: 'x25519',
      headline: 'Session still safe',
      detail:
        'ML-KEM-768 fell — imagine a cryptanalytic break of the newer lattice scheme. The mature classical X25519 secret is still unknown to the attacker, so the HKDF input cannot be reconstructed.',
    };
  }

  return {
    level: 'compromised',
    survivingWire: 'none',
    headline: 'Session compromised',
    detail:
      'Both wires fell at the same time. Only when X25519 and ML-KEM-768 are broken together can an attacker rebuild the HKDF input and recover the session key. Hybrid buys safety against either break alone.',
  };
}
