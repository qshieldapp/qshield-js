import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import Chacha20 from 'ts-chacha20';  // ← pure JS, works in browser + Node

// === Helpers ===
function randomBytes(length) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

function toBytes(input) {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function computeMac(data, key) {
  const dataBytes = toBytes(data);
  const combined = new Uint8Array(dataBytes.length + key.length);
  combined.set(dataBytes, 0);
  combined.set(key, dataBytes.length);

  const hash = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hash);
}

// === Post-Quantum Hybrid Encryption ===
export async function quantumResistantEncrypt(inputData, pubKeyB64) {
  const publicKey = decode(pubKeyB64);
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);

  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);
  const authTag = await computeMac(`${nonce}${encrypted}`, sharedSecret);

  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

export async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ctB64, nonceB64, encB64, macB64] = encryptedData.split(':');
  if (!ctB64 || !nonceB64 || !encB64 || !macB64) {
    throw new Error('Invalid encrypted data format');
  }

  const privateKey = decode(privateKeyB64);
  const ciphertext = decode(ctB64);

  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(ciphertext, privateKey);

  const encrypted = decode(encB64);
  const nonce = decode(nonceB64);
  const providedMac = decode(macB64);

  const computedMac = await computeMac(`${nonceB64}${encB64}`, sharedSecret);
  if (!bytesEqual(computedMac, providedMac)) {
    throw new Error('Invalid MAC');
  }

  const chacha = new Chacha20(sharedSecret, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

function postQuantumEncrypt(data, key) {
  const nonce = randomBytes(12);
  const plaintext = toBytes(data);

  const chacha = new Chacha20(key, nonce);
  const encrypted = chacha.encrypt(plaintext);

  return {
    encrypted: encode(encrypted),
    nonce: encode(nonce),
  };
}

// === Master Password Protected Private Key ===
export async function encryptPrivateKey(privateKey, masterPassword) {
  const key = toBytes(masterPassword.padEnd(32, '\0').slice(0, 32));
  const nonce = randomBytes(12);
  const plaintext = toBytes(privateKey);

  const chacha = new Chacha20(key, nonce);
  const encrypted = chacha.encrypt(plaintext);
  const authTag = await computeMac(`${encode(nonce)}${encode(encrypted)}`, key);

  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

export async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }

  const key = toBytes(masterPassword.padEnd(32, '\0').slice(0, 32));
  const computedMac = await computeMac(`${nonceB64}${encryptedB64}`, key);

  if (!bytesEqual(computedMac, decode(authTagB64))) {
    throw new Error('Wrong password or corrupted data');
  }

  const nonce = decode(nonceB64);
  const encrypted = decode(encryptedB64);

  const chacha = new Chacha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}
