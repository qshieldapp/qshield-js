// index.d.ts
export interface QuantumEncrypted {
  encrypted_data: string;
}

export function quantumResistantEncrypt(
  inputData: string | Uint8Array,
  pubKeyB64: string
): Promise<QuantumEncrypted>;

export function quantumResistantDecrypt(
  encryptedData: string,
  privateKeyB64: string
): Promise<string>;

export function encryptPrivateKey(
  privateKey: string | Uint8Array,
  masterPassword: string
): Promise<string>;

export function decryptPrivateKey(
  encryptedPrivateKey: string,
  masterPassword: string
): Promise<string>;
