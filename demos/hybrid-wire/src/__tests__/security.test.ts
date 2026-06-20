import { describe, expect, it } from 'vitest';

import { evaluateResilience } from '../crypto/security';

describe('hybrid resilience claim', () => {
  it('keeps the session protected when both wires hold', () => {
    const verdict = evaluateResilience(false, false);
    expect(verdict.level).toBe('protected');
    expect(verdict.survivingWire).toBe('both');
  });

  it('survives a classical X25519 break because ML-KEM still carries the key', () => {
    const verdict = evaluateResilience(true, false);
    expect(verdict.level).toBe('degraded');
    expect(verdict.survivingWire).toBe('mlkem');
  });

  it('survives a post-quantum ML-KEM break because X25519 still carries the key', () => {
    const verdict = evaluateResilience(false, true);
    expect(verdict.level).toBe('degraded');
    expect(verdict.survivingWire).toBe('x25519');
  });

  it('is only compromised when both wires break together', () => {
    const verdict = evaluateResilience(true, true);
    expect(verdict.level).toBe('compromised');
    expect(verdict.survivingWire).toBe('none');
  });
});
