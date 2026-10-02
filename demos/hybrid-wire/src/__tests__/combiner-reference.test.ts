/**
 * combiner-reference.test.ts — check combineSecrets against an RFC 5869
 * implementation written out here, rather than against itself.
 *
 * WHY THIS FILE EXISTS
 *
 * The suite already pins HKDF-SHA-256 to RFC 5869 Test Case 1, which anchors the
 * PRIMITIVE. It does not reach the combiner. `combineSecrets` makes four choices
 * of its own on top of that primitive -- the order the two secrets are
 * concatenated in, the salt, the context string as `info`, and a 256-bit output
 * -- and the only test of those choices asserted that calling it
 * twice with the same inputs gives the same answer. A function compared with
 * itself agrees with itself. Swap the two arguments inside it, pass the context
 * as `salt` instead of `info`, take 64 bytes instead of 32, and every one of
 * those tests still passes.
 *
 * Recorded as crypto-lab#28: "The combiner test compares the function with
 * itself. Add a fixed combined-key case computed by a separate RFC 5869
 * extract/expand reference, checking input order, salt, info and output bytes."
 *
 * WHAT MAKES THIS AN INDEPENDENT CHECK
 *
 * The reference below is HMAC-SHA-256 extract-then-expand spelled out from RFC
 * 5869 §2.2 and §2.3, over `node:crypto`'s HMAC. It does not call any HKDF
 * implementation: not WebCrypto's, which is what `combineSecrets` uses, and not
 * Node's `hkdfSync` either. So the two sides share SHA-256 and nothing above it,
 * and a defect in how the lab drives WebCrypto's HKDF cannot be present in both.
 *
 * It is NOT a published vector. There is no official test vector for this lab's
 * own concatenation and context -- that combination is this demo's -- so what
 * this establishes is agreement with the RFC's algorithm on the lab's inputs,
 * which is the strongest thing available here and weaker than a published vector.
 * The suite says so rather than letting a reader assume otherwise.
 *
 * The reference is also checked against RFC 5869 Test Case 1 before it is used to
 * judge anything, because a reference nobody verified is just a second
 * implementation of the same opinion.
 */
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { combineSecrets, DEFAULT_HYBRID_CONTEXT } from '../crypto/hybrid';
import { toHex } from '../crypto/utils';

/** RFC 5869 §2.2. PRK = HMAC-Hash(salt, IKM). */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', salt).update(ikm).digest());
}

/** RFC 5869 §2.3. T(1) = HMAC(PRK, info | 0x01), T(n) = HMAC(PRK, T(n-1) | info | n). */
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  if (n > 255) throw new Error('RFC 5869 allows at most 255 blocks');
  const out = new Uint8Array(n * hashLen);
  let previous = new Uint8Array(0);
  for (let i = 1; i <= n; i += 1) {
    const h = createHmac('sha256', prk);
    h.update(previous);
    h.update(info);
    h.update(Uint8Array.from([i]));
    previous = new Uint8Array(h.digest());
    out.set(previous, (i - 1) * hashLen);
  }
  return out.subarray(0, length);
}

function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdfExpand(hkdfExtract(salt, ikm), info, length);
}

const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
};

describe('the RFC 5869 reference used below is itself correct', () => {
  it('reproduces RFC 5869 Test Case 1', () => {
    const okm = hkdf(
      new Uint8Array(22).fill(0x0b),
      Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]),
      Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]),
      42,
    );
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a'
        + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        + '34007208d5b887185865',
    );
  });

  it('reproduces RFC 5869 Test Case 3, the empty salt and info case', () => {
    const okm = hkdf(new Uint8Array(22).fill(0x0b), new Uint8Array(0), new Uint8Array(0), 42);
    expect(toHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31'
        + 'b8a11f5c5ee1879ec3454e5f3c738d2d'
        + '9d201395faa4b61a96c8',
    );
  });
});

describe('combineSecrets agrees with the RFC 5869 reference, byte for byte', () => {
  /* Two distinct secrets, so a swapped concatenation cannot pass. The pattern is
     deliberately asymmetric for the same reason: 0x11.. and 0x22.. would also
     catch a swap, but a reader can see at a glance that these cannot be confused
     for each other. */
  const x25519Secret = new Uint8Array(32).fill(0xa1);
  const mlkemSecret = new Uint8Array(32).fill(0xb2);

  const expected = (x: Uint8Array, m: Uint8Array, context: string) =>
    hkdf(concat(x, m), new Uint8Array(32), new TextEncoder().encode(context), 32);

  it('matches on the default context', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);
    expect(toHex(got)).toBe(toHex(expected(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT)));
  });

  it('matches on a different context, so `info` is what carries it', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, 'some-other-context');
    expect(toHex(got)).toBe(toHex(expected(x25519Secret, mlkemSecret, 'some-other-context')));
  });

  /* The assertions below are the point of the file. Each states a choice the
     combiner makes, and each FAILS if that choice changes -- which is exactly what
     a self-comparison cannot do. One of them records that a choice is NOT a
     choice, which this test established by failing twice. */

  it('concatenates x25519 BEFORE ml-kem, not the other way round', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);
    const swapped = expected(mlkemSecret, x25519Secret, DEFAULT_HYBRID_CONTEXT);
    expect(toHex(got)).not.toBe(toHex(swapped));
    expect(toHex(got)).toBe(toHex(expected(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT)));
  });

  /* THE SALT IS INERT, and this says so rather than implying it is a parameter.
     Two facts compose: RFC 5869 §2.2 sets an absent salt to HashLen zeros, and
     HMAC zero-pads its key to the hash's BLOCK size, 64 bytes for SHA-256. So
     every all-zero salt of 64 bytes or fewer is the same HMAC key, and the
     combiner's explicit `new Uint8Array(32)` derives exactly what no salt at all
     would.

     Both halves were found by this test failing. The first version asserted the
     32-byte salt differs from an empty one; the second asserted it differs from a
     16-byte one. Neither is true, and asserting them would have pinned a belief
     rather than the behaviour.

     The inequality below is the one that proves the salt is wired at all: a
     NON-ZERO salt does change the key. If that ever stopped being true, the
     combiner would have stopped passing its salt. */
  it('derives what an absent salt would, because every short zero salt is one HMAC key', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);
    const ikm = concat(x25519Secret, mlkemSecret);
    const info = new TextEncoder().encode(DEFAULT_HYBRID_CONTEXT);

    for (const zeroSalt of [new Uint8Array(0), new Uint8Array(16), new Uint8Array(32), new Uint8Array(64)]) {
      expect(toHex(got)).toBe(toHex(hkdfExpand(hkdfExtract(zeroSalt, ikm), info, 32)));
    }

    const nonZeroSalt = new Uint8Array(32).fill(0x5c);
    expect(toHex(got)).not.toBe(toHex(hkdfExpand(hkdfExtract(nonZeroSalt, ikm), info, 32)));
  });

  it('passes the context as `info`, not as the salt', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);
    const contextAsSalt = hkdfExpand(
      hkdfExtract(new TextEncoder().encode(DEFAULT_HYBRID_CONTEXT), concat(x25519Secret, mlkemSecret)),
      new Uint8Array(0),
      32,
    );
    expect(toHex(got)).not.toBe(toHex(contextAsSalt));
  });

  it('derives exactly 256 bits', async () => {
    const got = await combineSecrets(x25519Secret, mlkemSecret, DEFAULT_HYBRID_CONTEXT);
    expect(got).toHaveLength(32);
    /* And the first 32 bytes of a longer derivation are the same 32 bytes, so the
       length is a choice about how much to take rather than about what to compute.
       This is what makes the assertion above a claim about L and not a tautology. */
    const longer = hkdf(
      concat(x25519Secret, mlkemSecret),
      new Uint8Array(32),
      new TextEncoder().encode(DEFAULT_HYBRID_CONTEXT),
      64,
    );
    expect(toHex(got)).toBe(toHex(longer.subarray(0, 32)));
  });
});
