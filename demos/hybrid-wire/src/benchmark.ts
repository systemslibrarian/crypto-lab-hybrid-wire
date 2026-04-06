import { bytesEqual, nextTick, nowMs } from './crypto/utils';
import { generateHybridKeyPair, hybridDecapsulate, hybridEncapsulate } from './crypto/hybrid';
import { generateMLKEMKeyPair, mlkemDecapsulate, mlkemEncapsulate } from './crypto/mlkem768';
import { generateX25519KeyPair, x25519SharedSecret } from './crypto/x25519';

export interface BenchmarkResult {
  iterations: number;
  x25519OpsPerSecond: number;
  mlkemOpsPerSecond: number;
  hybridOpsPerSecond: number;
  hybridOverheadPercent: number;
  durationsMs: {
    x25519: number;
    mlkem: number;
    hybrid: number;
  };
}

async function timedLoop(iterations: number, task: () => Promise<void>): Promise<number> {
  const startedAt = nowMs();

  for (let index = 0; index < iterations; index += 1) {
    await task();
    if ((index + 1) % 5 === 0) {
      await nextTick();
    }
  }

  return nowMs() - startedAt;
}

export async function runBenchmark(iterations = 50): Promise<BenchmarkResult> {
  const x25519Duration = await timedLoop(iterations, async () => {
    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();
    const [aliceSecret, bobSecret] = await Promise.all([
      x25519SharedSecret(alice.privateKey, bob.publicKeyRaw),
      x25519SharedSecret(bob.privateKey, alice.publicKeyRaw),
    ]);

    if (!bytesEqual(aliceSecret, bobSecret)) {
      throw new Error('X25519 benchmark mismatch detected.');
    }
  });

  const mlkemDuration = await timedLoop(iterations, async () => {
    const bob = await generateMLKEMKeyPair();
    const alice = await mlkemEncapsulate(bob.publicKey);
    const bobSecret = await mlkemDecapsulate(alice.ciphertext, bob.privateKey);

    if (!bytesEqual(alice.sharedSecret, bobSecret)) {
      throw new Error('ML-KEM benchmark mismatch detected.');
    }
  });

  const hybridDuration = await timedLoop(iterations, async () => {
    const bob = await generateHybridKeyPair();
    const aliceX25519 = await generateX25519KeyPair();
    const alice = await hybridEncapsulate(bob.x25519.publicKeyRaw, bob.mlkem.publicKey, aliceX25519);
    const bobResult = await hybridDecapsulate(
      aliceX25519.publicKeyRaw,
      alice.mlkemCiphertext,
      bob.x25519,
      bob.mlkem.privateKey,
    );

    if (!bytesEqual(alice.combinedSessionKey, bobResult.combinedSessionKey)) {
      throw new Error('Hybrid benchmark mismatch detected.');
    }
  });

  const x25519OpsPerSecond = iterations / (x25519Duration / 1000);
  const mlkemOpsPerSecond = iterations / (mlkemDuration / 1000);
  const hybridOpsPerSecond = iterations / (hybridDuration / 1000);
  const hybridOverheadPercent = ((hybridDuration - x25519Duration) / x25519Duration) * 100;

  return {
    iterations,
    x25519OpsPerSecond,
    mlkemOpsPerSecond,
    hybridOpsPerSecond,
    hybridOverheadPercent,
    durationsMs: {
      x25519: x25519Duration,
      mlkem: mlkemDuration,
      hybrid: hybridDuration,
    },
  };
}
