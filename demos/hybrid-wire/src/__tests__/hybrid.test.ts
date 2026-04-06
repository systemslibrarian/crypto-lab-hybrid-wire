import { describe, expect, it } from 'vitest';

import { combineSecrets, generateHybridKeyPair, hybridDecapsulate, hybridEncapsulate } from '../crypto/hybrid';
import { decryptMessage, encryptMessage, type HybridSession } from '../crypto/session';
import { bytesEqual } from '../crypto/utils';
import { generateX25519KeyPair, x25519SharedSecret } from '../crypto/x25519';

describe('hybrid X25519 + ML-KEM-768 handshake', () => {
  it('matches X25519 shared secrets from both perspectives', async () => {
    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const [aliceSecret, bobSecret] = await Promise.all([
      x25519SharedSecret(alice.privateKey, bob.publicKeyRaw),
      x25519SharedSecret(bob.privateKey, alice.publicKeyRaw),
    ]);

    expect(bytesEqual(aliceSecret, bobSecret)).toBe(true);
    expect(aliceSecret).toHaveLength(32);
  });

  it('completes a full handshake with matching ML-KEM and combined session keys', async () => {
    const bob = await generateHybridKeyPair();
    const aliceX25519 = await generateX25519KeyPair();

    const aliceResult = await hybridEncapsulate(
      bob.x25519.publicKeyRaw,
      bob.mlkem.publicKey,
      aliceX25519,
    );
    const bobResult = await hybridDecapsulate(
      aliceX25519.publicKeyRaw,
      aliceResult.mlkemCiphertext,
      bob.x25519,
      bob.mlkem.privateKey,
    );

    expect(bytesEqual(aliceResult.x25519SharedSecret, bobResult.x25519SharedSecret)).toBe(true);
    expect(bytesEqual(aliceResult.mlkemSharedSecret, bobResult.mlkemSharedSecret)).toBe(true);
    expect(bytesEqual(aliceResult.combinedSessionKey, bobResult.combinedSessionKey)).toBe(true);
    expect(aliceResult.handshakeTimeMs).toBeGreaterThanOrEqual(0);
    expect(bobResult.handshakeTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('keeps HKDF output deterministic for the same inputs', async () => {
    const x25519Secret = new Uint8Array(32).fill(0x11);
    const mlkemSecret = new Uint8Array(32).fill(0x22);

    const first = await combineSecrets(x25519Secret, mlkemSecret, 'hybrid-wire-v1');
    const second = await combineSecrets(x25519Secret, mlkemSecret, 'hybrid-wire-v1');

    expect(bytesEqual(first, second)).toBe(true);
    expect(first).toHaveLength(32);
  });

  it('diverges on tampered ML-KEM ciphertext and fails AES-GCM decryption', async () => {
    const bob = await generateHybridKeyPair();
    const aliceX25519 = await generateX25519KeyPair();

    const aliceResult = await hybridEncapsulate(
      bob.x25519.publicKeyRaw,
      bob.mlkem.publicKey,
      aliceX25519,
    );

    const tamperedCiphertext = aliceResult.mlkemCiphertext.slice();
    tamperedCiphertext[0] ^= 0x01;

    const tamperedBobResult = await hybridDecapsulate(
      aliceX25519.publicKeyRaw,
      tamperedCiphertext,
      bob.x25519,
      bob.mlkem.privateKey,
    );

    expect(bytesEqual(aliceResult.combinedSessionKey, tamperedBobResult.combinedSessionKey)).toBe(false);

    const aliceSession: HybridSession = {
      sessionKey: aliceResult.combinedSessionKey,
      myRole: 'alice',
      x25519PublicKey: aliceX25519.publicKeyRaw,
      mlkemCiphertext: aliceResult.mlkemCiphertext,
    };

    const tamperedBobSession: HybridSession = {
      sessionKey: tamperedBobResult.combinedSessionKey,
      myRole: 'bob',
      x25519PublicKey: bob.x25519.publicKeyRaw,
      mlkemPublicKey: bob.mlkem.publicKey,
    };

    const encrypted = await encryptMessage(aliceSession, 'Hybrid post-quantum session test', 1);
    await expect(decryptMessage(tamperedBobSession, encrypted)).rejects.toThrow(/failed|verification/i);
  });
});
