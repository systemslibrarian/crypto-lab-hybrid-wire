import { x25519 as nobleX25519 } from '@noble/curves/ed25519.js';

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

const subtle = globalThis.crypto?.subtle;
const fallbackPrivateKeys = new WeakMap<object, Uint8Array>();
let nativeSupportPromise: Promise<boolean> | undefined;

function cloneBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

async function supportsNativeX25519(): Promise<boolean> {
  if (!subtle) {
    return false;
  }

  if (!nativeSupportPromise) {
    nativeSupportPromise = subtle
      .generateKey({ name: 'X25519' }, false, ['deriveBits'])
      .then(() => true)
      .catch(() => false);
  }

  return nativeSupportPromise;
}

async function createFallbackPrivateKey(secretKey: Uint8Array): Promise<CryptoKey> {
  if (subtle) {
    try {
      const keyMaterial = cloneBytes(secretKey) as BufferSource;
      const key = await subtle.importKey('raw', keyMaterial, { name: 'HKDF' }, false, ['deriveBits']);
      fallbackPrivateKeys.set(key as object, cloneBytes(secretKey));
      return key as unknown as CryptoKey;
    } catch {
      // Fall through to the light wrapper below.
    }
  }

  const fallbackKey = {
    type: 'private',
    extractable: false,
    algorithm: { name: 'X25519-fallback' },
    usages: ['deriveBits'],
  } as unknown as CryptoKey;

  fallbackPrivateKeys.set(fallbackKey as unknown as object, cloneBytes(secretKey));
  return fallbackKey;
}

async function importNativePublicKey(publicKeyBytes: Uint8Array): Promise<CryptoKey> {
  if (!subtle) {
    throw new Error('Web Crypto is unavailable.');
  }

  const publicKeyMaterial = cloneBytes(publicKeyBytes) as BufferSource;
  return subtle.importKey('raw', publicKeyMaterial, { name: 'X25519' }, true, []);
}

export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  if (await supportsNativeX25519()) {
    const keyPair = (await subtle!.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
    const publicKeyRaw = cloneBytes(new Uint8Array(await subtle!.exportKey('raw', keyPair.publicKey)));

    return {
      publicKey: publicKeyRaw,
      publicKeyRaw,
      privateKey: keyPair.privateKey,
    };
  }

  const privateKeyBytes = cloneBytes(nobleX25519.utils.randomSecretKey());
  const publicKey = cloneBytes(nobleX25519.getPublicKey(privateKeyBytes));

  return {
    publicKey,
    publicKeyRaw: publicKey,
    privateKey: await createFallbackPrivateKey(privateKeyBytes),
  };
}

export async function x25519SharedSecret(
  myPrivateKey: CryptoKey,
  theirPublicKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  const fallbackPrivateKey = fallbackPrivateKeys.get(myPrivateKey as unknown as object);
  if (fallbackPrivateKey) {
    return cloneBytes(nobleX25519.getSharedSecret(cloneBytes(fallbackPrivateKey), cloneBytes(theirPublicKeyBytes)));
  }

  if (!(await supportsNativeX25519())) {
    throw new Error('X25519 is unavailable in this runtime and no fallback key material was provided.');
  }

  const theirPublicKey = await importNativePublicKey(theirPublicKeyBytes);
  const sharedBits = await subtle!.deriveBits(
    { name: 'X25519', public: theirPublicKey },
    myPrivateKey,
    256,
  );

  return cloneBytes(new Uint8Array(sharedBits));
}

