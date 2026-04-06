import { bytesEqual, fromBase64, toBase64 } from './utils';

export interface HybridSession {
  sessionKey: Uint8Array;
  myRole: 'alice' | 'bob';
  x25519PublicKey: Uint8Array;
  mlkemPublicKey?: Uint8Array;
  mlkemCiphertext?: Uint8Array;
}

export interface EncryptedMessage {
  ciphertext: string;
  iv: string;
  sender: string;
  messageNumber: number;
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

async function importSessionKey(sessionKey: Uint8Array): Promise<CryptoKey> {
  const subtle = await getSubtle();
  return subtle.importKey('raw', asBufferSource(sessionKey), { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function deriveMessageIv(
  sessionKey: Uint8Array,
  sender: string,
  messageNumber: number,
): Promise<Uint8Array> {
  const subtle = await getSubtle();
  const hkdfKey = await subtle.importKey('raw', asBufferSource(sessionKey), 'HKDF', false, ['deriveBits']);
  const ivBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('hybrid-wire-iv:' + sender + ':' + messageNumber),
    },
    hkdfKey,
    96,
  );

  return new Uint8Array(ivBits);
}

export async function encryptMessage(
  session: HybridSession,
  plaintext: string,
  messageNumber: number,
): Promise<EncryptedMessage> {
  const subtle = await getSubtle();
  const iv = await deriveMessageIv(session.sessionKey, session.myRole, messageNumber);
  const key = await importSessionKey(session.sessionKey);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    key,
    new TextEncoder().encode(plaintext),
  );

  return {
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    iv: toBase64(iv),
    sender: session.myRole,
    messageNumber,
  };
}

export async function decryptMessage(session: HybridSession, message: EncryptedMessage): Promise<string> {
  const subtle = await getSubtle();
  const derivedIv = await deriveMessageIv(session.sessionKey, message.sender, message.messageNumber);
  const transmittedIv = fromBase64(message.iv);

  if (!bytesEqual(derivedIv, transmittedIv)) {
    throw new Error('IV verification failed: the message metadata was modified.');
  }

  const key = await importSessionKey(session.sessionKey);

  try {
    const plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(derivedIv) },
      key,
      asBufferSource(fromBase64(message.ciphertext)),
    );

    return new TextDecoder().decode(plaintext);
  } catch (error) {
    throw new Error('Authentication failed: ' + (error as Error).message);
  }
}

