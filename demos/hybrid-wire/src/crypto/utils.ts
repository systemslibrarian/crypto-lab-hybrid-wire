export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, current) => sum + current.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;

  for (const array of arrays) {
    combined.set(array, offset);
    offset += array.length;
  }

  return combined;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }

  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function shortHex(bytes?: Uint8Array, take = 12): string {
  if (!bytes || bytes.length === 0) {
    return '—';
  }

  const hex = toHex(bytes);
  const visible = take * 2;
  return hex.length <= visible ? hex : hex.slice(0, visible) + '…';
}

function bytesToBinary(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = '';

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }

  return binary;
}

export function toBase64(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function formatMs(value: number): string {
  return value.toFixed(2) + ' ms';
}

export function nowMs(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }

  return Date.now();
}

export async function nextTick(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

export function fingerprint(bytes: Uint8Array, take = 8): string {
  return toHex(bytes.slice(0, take));
}

