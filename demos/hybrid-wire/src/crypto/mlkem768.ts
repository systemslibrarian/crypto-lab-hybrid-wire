import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export interface MLKEMKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

function cloneBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

export async function generateMLKEMKeyPair(): Promise<MLKEMKeyPair> {
  const { publicKey, secretKey } = ml_kem768.keygen();

  return {
    publicKey: cloneBytes(publicKey),
    privateKey: cloneBytes(secretKey),
  };
}

export async function mlkemEncapsulate(
  publicKey: Uint8Array,
): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
  const { sharedSecret, cipherText } = ml_kem768.encapsulate(cloneBytes(publicKey));

  return {
    sharedSecret: cloneBytes(sharedSecret),
    ciphertext: cloneBytes(cipherText),
  };
}

export async function mlkemDecapsulate(
  ciphertext: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  return cloneBytes(ml_kem768.decapsulate(cloneBytes(ciphertext), cloneBytes(privateKey)));
}

