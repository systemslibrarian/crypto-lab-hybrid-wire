// The core security claim of a hybrid handshake, established by running the
// attack rather than by consulting the two "broken" switches.
//
// session_key = HKDF-SHA-256(x25519_secret || mlkem_secret)
//
// Because both secrets feed the combiner, an attacker must recover BOTH to
// reconstruct the input keying material. Breaking a single wire leaves the
// other one carrying the session. Instead of asserting that, this module hands
// the attacker exactly the secrets the broken wires leaked, runs the real
// combiner over them plus a guess for whatever is still hidden, compares the
// bytes to the session key the handshake actually derived, and tries to decrypt
// an intercepted record with them. The verdict is whatever that produced.

import { combineSecrets, DEFAULT_HYBRID_CONTEXT } from './hybrid';
import { bytesEqual } from './utils';

export type ResilienceLevel = 'protected' | 'degraded' | 'compromised';

export type SurvivingWire = 'both' | 'x25519' | 'mlkem' | 'none';

export interface ResilienceVerdict {
  level: ResilienceLevel;
  survivingWire: SurvivingWire;
  headline: string;
  detail: string;
  /** One line of receipts: what the reconstruction attempt actually did. */
  measurement: string;
}

/** The plaintext of the record the attacker intercepts and tries to open. */
export const INTERCEPTED_PLAINTEXT = 'hybrid-wire session record';

export interface InterceptedRecord {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

function asBufferSource(value: Uint8Array): BufferSource {
  return new Uint8Array(value) as BufferSource;
}

async function getSubtle(): Promise<SubtleCrypto> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API is unavailable in this environment.');
  }
  return subtle;
}

async function aesKey(raw: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  const subtle = await getSubtle();
  return subtle.importKey('raw', asBufferSource(raw), { name: 'AES-GCM', length: 256 }, false, usage);
}

/** Encrypt one record under the live session key. This is what gets attacked. */
export async function createInterceptedRecord(sessionKey: Uint8Array): Promise<InterceptedRecord> {
  const subtle = await getSubtle();
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    await aesKey(sessionKey, ['encrypt']),
    new TextEncoder().encode(INTERCEPTED_PLAINTEXT),
  );
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

/**
 * Try to open the intercepted record with a candidate key. The GCM tag is the
 * only oracle — a wrong key throws and we report null.
 */
export async function tryOpenRecord(
  record: InterceptedRecord,
  candidateKey: Uint8Array,
): Promise<string | null> {
  const subtle = await getSubtle();
  try {
    const plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(record.iv) },
      await aesKey(candidateKey, ['decrypt']),
      asBufferSource(record.ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}

export interface HandshakeTarget {
  x25519Secret: Uint8Array;
  mlkemSecret: Uint8Array;
  sessionKey: Uint8Array;
  record: InterceptedRecord;
}

export interface BrokenWires {
  x25519: boolean;
  mlkem: boolean;
}

export interface ReconstructionResult {
  /** How many candidate keys the attacker derived and tested. */
  attempts: number;
  /** Wires whose 32-byte secret was leaked to the attacker. */
  leakedWires: Array<'x25519' | 'mlkem'>;
  /** Wires the attacker had to guess. */
  hiddenWires: Array<'x25519' | 'mlkem'>;
  /** Measured off the actual withheld secrets, not off the switches. */
  hiddenBits: number;
  /** The last key the attacker's HKDF produced — a real 32-byte key either way. */
  candidateKey: Uint8Array<ArrayBufferLike>;
  /** Measured: candidateKey === the session key the handshake derived. */
  keyMatches: boolean;
  /** Measured: the plaintext, when a candidate key opened the record. */
  openedPlaintext: string | null;
  /** Best byte-agreement between any candidate and the real key, out of 32. */
  bestBytesMatched: number;
}

function bytesMatched(a: Uint8Array, b: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] === b[i]) n += 1;
  }
  return n;
}

function randomSecret(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * Run the reconstruction. A broken wire hands over its genuine 32-byte secret;
 * an intact one forces the attacker to guess, so we draw a real guess and run
 * the real HKDF combiner over it. This is at full parameters — an intact wire
 * is 256 bits, so a wrong guess is wrong with probability 1 - 2^-256 and the
 * failure below is observed rather than stipulated.
 */
export async function attemptReconstruction(
  target: HandshakeTarget,
  broken: BrokenWires,
  attempts = 8,
): Promise<ReconstructionResult> {
  const leakedWires: Array<'x25519' | 'mlkem'> = [];
  const hiddenWires: Array<'x25519' | 'mlkem'> = [];
  if (broken.x25519) leakedWires.push('x25519');
  else hiddenWires.push('x25519');
  if (broken.mlkem) leakedWires.push('mlkem');
  else hiddenWires.push('mlkem');

  const hiddenBits = hiddenWires.reduce(function (bits, wire) {
    return bits + (wire === 'x25519' ? target.x25519Secret.length : target.mlkemSecret.length) * 8;
  }, 0);

  // With nothing hidden the attacker has one deterministic candidate.
  const budget = hiddenWires.length === 0 ? 1 : attempts;

  let candidateKey: Uint8Array = new Uint8Array(32);
  let keyMatches = false;
  let openedPlaintext: string | null = null;
  let bestBytesMatched = 0;
  let performed = 0;

  for (let i = 0; i < budget; i += 1) {
    const x = broken.x25519 ? target.x25519Secret : randomSecret(target.x25519Secret.length);
    const m = broken.mlkem ? target.mlkemSecret : randomSecret(target.mlkemSecret.length);
    candidateKey = await combineSecrets(x, m, DEFAULT_HYBRID_CONTEXT);
    performed += 1;
    bestBytesMatched = Math.max(bestBytesMatched, bytesMatched(candidateKey, target.sessionKey));
    if (bytesEqual(candidateKey, target.sessionKey)) keyMatches = true;
    const opened = await tryOpenRecord(target.record, candidateKey);
    if (opened !== null) {
      openedPlaintext = opened;
      break;
    }
  }

  return {
    attempts: performed,
    leakedWires,
    hiddenWires,
    hiddenBits,
    candidateKey,
    keyMatches,
    openedPlaintext,
    bestBytesMatched,
  };
}

/**
 * Turn a completed reconstruction into the on-screen verdict. `level` is
 * decided by whether the attacker's derived key actually opened the intercepted
 * record — never by reading the toggles.
 */
export function evaluateResilience(result: ReconstructionResult): ResilienceVerdict {
  const recovered = result.openedPlaintext !== null;
  const measurement = recovered
    ? result.attempts +
      ' derivation' +
      (result.attempts === 1 ? '' : 's') +
      ' · record decrypted · key matched 32/32 bytes'
    : result.attempts +
      ' derivations · 0 opened the record · best candidate matched ' +
      result.bestBytesMatched +
      '/32 bytes';

  if (recovered) {
    return {
      level: 'compromised',
      survivingWire: 'none',
      headline: 'Session compromised',
      detail:
        'Both wires fell at the same time, so the attacker rebuilt A ‖ B, re-derived the session key and opened the intercepted record (recovered plaintext: “' +
        result.openedPlaintext +
        '”). Hybrid buys safety against either break alone.',
      measurement,
    };
  }

  if (result.hiddenWires.length === 0) {
    // Every secret was handed over yet the record survived: that is a fault in
    // the demo's own plumbing, not a security property.
    return {
      level: 'compromised',
      survivingWire: 'none',
      headline: 'Inconclusive — derivation mismatch',
      detail:
        'The attacker was given both wire secrets but the key they derived did not open the intercepted record. That is not resilience; the session key and the record were built from different inputs.',
      measurement,
    };
  }

  if (result.hiddenWires.length === 2) {
    return {
      level: 'protected',
      survivingWire: 'both',
      headline: 'Session protected',
      detail:
        'Both wires are intact. The attacker still ran the combiner over guesses for both halves, and none of the keys they produced opened the intercepted record.',
      measurement,
    };
  }

  if (result.hiddenWires[0] === 'mlkem') {
    return {
      level: 'degraded',
      survivingWire: 'mlkem',
      headline: 'Session still safe',
      detail:
        'X25519 fell — imagine a future quantum computer breaking the classical curve. The attacker fed that real secret into HKDF alongside a guess for the post-quantum half, and the key that came out did not open the intercepted record.',
      measurement,
    };
  }

  return {
    level: 'degraded',
    survivingWire: 'x25519',
    headline: 'Session still safe',
    detail:
      'ML-KEM-768 fell — imagine a cryptanalytic break of the newer lattice scheme. The attacker fed that real secret into HKDF alongside a guess for the mature classical half, and the key that came out did not open the intercepted record.',
    measurement,
  };
}
