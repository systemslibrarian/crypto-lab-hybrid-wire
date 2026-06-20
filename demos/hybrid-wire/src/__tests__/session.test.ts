import { describe, expect, it } from 'vitest';

import { generateHybridKeyPair, hybridEncapsulate } from '../crypto/hybrid';
import { decryptMessage, encryptMessage, type HybridSession } from '../crypto/session';
import { generateX25519KeyPair } from '../crypto/x25519';

async function establishSession(): Promise<{ alice: HybridSession; bob: HybridSession }> {
  const bob = await generateHybridKeyPair();
  const aliceX25519 = await generateX25519KeyPair();
  const aliceResult = await hybridEncapsulate(bob.x25519.publicKeyRaw, bob.mlkem.publicKey, aliceX25519);

  return {
    alice: {
      sessionKey: aliceResult.combinedSessionKey,
      myRole: 'alice',
      x25519PublicKey: aliceX25519.publicKeyRaw,
      mlkemCiphertext: aliceResult.mlkemCiphertext,
    },
    bob: {
      sessionKey: aliceResult.combinedSessionKey,
      myRole: 'bob',
      x25519PublicKey: bob.x25519.publicKeyRaw,
      mlkemPublicKey: bob.mlkem.publicKey,
    },
  };
}

describe('hybrid secure channel', () => {
  it('round-trips a message Alice → Bob over the derived session key', async () => {
    const { alice, bob } = await establishSession();
    const message = 'Whatever you do, do it all for the glory of God.';

    const encrypted = await encryptMessage(alice, message, 1);
    const decrypted = await decryptMessage(bob, encrypted);

    expect(decrypted).toBe(message);
  });

  it('derives a distinct IV for each message number', async () => {
    const { alice } = await establishSession();

    const first = await encryptMessage(alice, 'one', 1);
    const second = await encryptMessage(alice, 'two', 2);

    expect(first.iv).not.toBe(second.iv);
  });

  it('rejects a ciphertext whose metadata was altered', async () => {
    const { alice, bob } = await establishSession();
    const encrypted = await encryptMessage(alice, 'tamper me', 1);

    // Replay the ciphertext under a different message number: the recipient
    // re-derives a different IV and the AES-GCM tag no longer authenticates.
    const forged = { ...encrypted, messageNumber: 99 };

    await expect(decryptMessage(bob, forged)).rejects.toThrow(/failed|verification/i);
  });
});
