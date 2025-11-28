import { encrypt, decrypt } from './encryption';

/**
 * Encrypted token data for storage in database
 */
export interface EncryptedToken {
  encryptedAccessToken: string;
  accessTokenIv: string;
  accessTokenAuthTag: string;
}

/**
 * Encrypts a GitHub access token for secure storage
 * @param accessToken - The plaintext GitHub access token
 * @returns Encrypted token data ready for database storage
 */
export function encryptAccessToken(accessToken: string): EncryptedToken {
  const encrypted = encrypt(accessToken);
  return {
    encryptedAccessToken: encrypted.encryptedContent,
    accessTokenIv: encrypted.iv,
    accessTokenAuthTag: encrypted.authTag,
  };
}

/**
 * Decrypts a GitHub access token from database storage
 * @param encryptedToken - The encrypted token data from database
 * @returns Decrypted plaintext GitHub access token
 */
export function decryptAccessToken(encryptedToken: EncryptedToken): string {
  return decrypt({
    encryptedContent: encryptedToken.encryptedAccessToken,
    iv: encryptedToken.accessTokenIv,
    authTag: encryptedToken.accessTokenAuthTag,
  });
}
