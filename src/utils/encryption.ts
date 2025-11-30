import { config } from '../config';

/**
 * Current encryption version - increment when changing algorithms
 * Version 1: AES-256-GCM
 */
export const CURRENT_ENCRYPTION_VERSION = 1;

export interface EncryptedData {
  encryptedContent: string;
  iv: string;
  authTag: string;
}

/**
 * Encryption service interface - async to support remote implementations
 */
export interface IEncryptionService {
  encrypt(content: string): Promise<EncryptedData>;
  decrypt(data: EncryptedData): Promise<string>;
}

// Singleton instance - lazily initialized
let encryptionService: IEncryptionService | null = null;

/**
 * Get the encryption service instance
 * Uses RemoteEncryptionService (Go microservice)
 */
export async function getEncryptionService(): Promise<IEncryptionService> {
  if (!encryptionService) {
    const { RemoteEncryptionService } = await import('./remoteEncryption.js');
    encryptionService = new RemoteEncryptionService(config.crypto.serviceUrl);
    console.log(`Using remote encryption service at ${config.crypto.serviceUrl}`);
  }
  return encryptionService;
}

/**
 * Sanitizes content for logging - NEVER log actual secret values
 */
export function sanitizeForLogging(content: string): string {
  const lines = content.split('\n').length;
  const chars = content.length;
  return `[REDACTED: ${lines} lines, ${chars} characters]`;
}
