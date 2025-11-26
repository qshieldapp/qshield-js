import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import ChaCha20 from 'js-chacha20';
import { Buffer } from 'buffer';



// === CRYPTO HELPERS ===
function randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}

async function computeMac(data, key) {
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const combined = Buffer.concat([Buffer.from(dataBytes), Buffer.from(keyBytes)]);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return Buffer.from(hash);
}

function postQuantumEncrypt(data, key) {
  const nonce = randomBytes(12);
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(dataBytes);
  return {
    encrypted: encode(encrypted),
    nonce: encode(nonce),
  };
}

async function postQuantumDecrypt(encryptedB64, nonceB64, key, authTagB64) {
  const encrypted = Buffer.from(decode(encryptedB64));
  const nonce = Buffer.from(decode(nonceB64));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

export async function quantumResistantEncrypt(inputData, pubKeyB64) {
  const publicKey = Buffer.from(decode(pubKeyB64));
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);
  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);
  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);
  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

export async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = encryptedData.split(':');
  if (!ciphertextB64 || !nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted data format');
  }
  const privateKey = Buffer.from(decode(privateKeyB64));
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(Buffer.from(decode(ciphertextB64)), privateKey);
  return await postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
}

export async function encryptPrivateKey(privateKey, masterPassword) {
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const nonce = randomBytes(12);
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(privateKey));
  const combinedData = new TextEncoder().encode(`${encode(nonce)}${encode(encrypted)}`);
  const authTag = await computeMac(combinedData, key);
  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

export async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const nonce = Buffer.from(decode(nonceB64));
  const encrypted = Buffer.from(decode(encryptedB64));
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}
