import { generateMLKEMKeyPair, mlkemDecapsulate, mlkemEncapsulate, type MLKEMKeyPair } from './mlkem768';
import { concatBytes, nowMs } from './utils';
import { generateX25519KeyPair, x25519SharedSecret, type X25519KeyPair } from './x25519';

// Related TLS standards: https://www.rfc-editor.org/rfc/rfc9954.html
// and https://www.rfc-editor.org/rfc/rfc10024.html (X25519MLKEM768).
export interface HybridKeyPair {
  x25519: X25519KeyPair;
  mlkem: MLKEMKeyPair;
}

export interface HybridHandshakeResult {
  x25519SharedSecret: Uint8Array;
  mlkemSharedSecret: Uint8Array;
  combinedSessionKey: Uint8Array;
  mlkemCiphertext: Uint8Array;
  handshakeTimeMs: number;
}

export const DEFAULT_HYBRID_CONTEXT = 'hybrid-wire-v1';

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

// Combiner note — transcript binding is intentionally OUT of scope here.
//
// This is a teaching construction: HKDF-SHA-256(x25519_secret || mlkem_secret),
// with a zero salt and the "hybrid-wire-v1" info string. The final TLS 1.3
// X25519MLKEM768 group in RFC 10024 §4.3 concatenates in the reverse order,
// mlkem_secret || x25519_secret, then enters the TLS 1.3 key schedule. It also
// puts ML-KEM before X25519 in both client and server key_share values (§§4.1–4.2).
// RFC 9954 describes the TLS hybrid framework; neither RFC specifies this
// demo's direct HKDF-to-AES session-key construction. These outputs are not TLS
// interoperable, and reversing these two arguments alone would not make them so.
//
// This demo has no surrounding TLS transcript, so the combiner below is UNBOUND
// on its own. Do NOT lift this function into another protocol as-is: if your
// construction lacks an outer transcript, add the KEM ciphertext and both peers'
// public keys to the HKDF `info` (or a preceding transcript hash) so the derived
// key commits to the exact handshake it came from. A production protocol also
// needs peer authentication and a full security analysis; concatenation alone
// does not provide channel binding or authenticated key exchange.
export async function combineSecrets(
  x25519Secret: Uint8Array,
  mlkemSecret: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  const subtle = await getSubtle();
  const ikm = concatBytes(x25519Secret, mlkemSecret);
  const hkdfKey = await subtle.importKey('raw', asBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const combinedBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(context),
    },
    hkdfKey,
    256,
  );

  return new Uint8Array(combinedBits);
}

export async function generateHybridKeyPair(): Promise<HybridKeyPair> {
  const [x25519, mlkem] = await Promise.all([generateX25519KeyPair(), generateMLKEMKeyPair()]);
  return { x25519, mlkem };
}

export async function hybridEncapsulate(
  recipientX25519PublicKey: Uint8Array,
  recipientMLKEMPublicKey: Uint8Array,
  myX25519KeyPair: X25519KeyPair,
): Promise<HybridHandshakeResult> {
  const startedAt = nowMs();
  const [x25519Secret, mlkemResult] = await Promise.all([
    x25519SharedSecret(myX25519KeyPair.privateKey, recipientX25519PublicKey),
    mlkemEncapsulate(recipientMLKEMPublicKey),
  ]);
  const combinedSessionKey = await combineSecrets(
    x25519Secret,
    mlkemResult.sharedSecret,
    DEFAULT_HYBRID_CONTEXT,
  );

  return {
    x25519SharedSecret: x25519Secret,
    mlkemSharedSecret: mlkemResult.sharedSecret,
    combinedSessionKey,
    mlkemCiphertext: mlkemResult.ciphertext,
    handshakeTimeMs: nowMs() - startedAt,
  };
}

export async function hybridDecapsulate(
  senderX25519PublicKey: Uint8Array,
  mlkemCiphertext: Uint8Array,
  myX25519KeyPair: X25519KeyPair,
  myMLKEMPrivateKey: Uint8Array,
): Promise<HybridHandshakeResult> {
  const startedAt = nowMs();
  const [x25519Secret, mlkemSecret] = await Promise.all([
    x25519SharedSecret(myX25519KeyPair.privateKey, senderX25519PublicKey),
    mlkemDecapsulate(mlkemCiphertext, myMLKEMPrivateKey),
  ]);
  const combinedSessionKey = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);

  return {
    x25519SharedSecret: x25519Secret,
    mlkemSharedSecret: mlkemSecret,
    combinedSessionKey,
    mlkemCiphertext,
    handshakeTimeMs: nowMs() - startedAt,
  };
}

