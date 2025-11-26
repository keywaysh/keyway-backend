import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, sanitizeForLogging } from '../src/utils/encryption';

describe('Encryption Utils', () => {
  describe('encrypt', () => {
    it('should encrypt content and return encrypted data', () => {
      const content = 'my-secret-value';
      const result = encrypt(content);

      expect(result).toHaveProperty('encryptedContent');
      expect(result).toHaveProperty('iv');
      expect(result).toHaveProperty('authTag');
      expect(result.encryptedContent).not.toBe(content);
      expect(result.iv).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(result.authTag).toHaveLength(32); // 16 bytes = 32 hex chars
    });

    it('should produce different IVs for same content', () => {
      const content = 'same-content';
      const result1 = encrypt(content);
      const result2 = encrypt(content);

      expect(result1.iv).not.toBe(result2.iv);
      expect(result1.encryptedContent).not.toBe(result2.encryptedContent);
    });

    it('should handle empty strings', () => {
      const result = encrypt('');
      expect(result.encryptedContent).toBeDefined();
    });

    it('should handle unicode content', () => {
      const content = 'Hello 世界 🔐';
      const result = encrypt(content);
      expect(result.encryptedContent).toBeDefined();
    });

    it('should handle multiline content', () => {
      const content = 'DATABASE_URL=postgres://...\nAPI_KEY=secret123\nDEBUG=true';
      const result = encrypt(content);
      expect(result.encryptedContent).toBeDefined();
    });
  });

  describe('decrypt', () => {
    it('should decrypt encrypted content back to original', () => {
      const original = 'my-secret-value';
      const encrypted = encrypt(original);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(original);
    });

    it('should handle empty strings', () => {
      const original = '';
      const encrypted = encrypt(original);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(original);
    });

    it('should handle unicode content', () => {
      const original = 'Hello 世界 🔐';
      const encrypted = encrypt(original);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(original);
    });

    it('should handle multiline .env content', () => {
      const original = `DATABASE_URL=postgres://user:pass@host:5432/db
API_KEY=sk-1234567890
DEBUG=true
MULTILINE="line1
line2"`;
      const encrypted = encrypt(original);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(original);
    });

    it('should fail with tampered encrypted content', () => {
      const encrypted = encrypt('secret');
      encrypted.encryptedContent = 'tampered' + encrypted.encryptedContent;

      expect(() => decrypt(encrypted)).toThrow();
    });

    it('should fail with tampered auth tag', () => {
      const encrypted = encrypt('secret');
      encrypted.authTag = '00000000000000000000000000000000';

      expect(() => decrypt(encrypted)).toThrow();
    });

    it('should fail with wrong IV', () => {
      const encrypted = encrypt('secret');
      encrypted.iv = '00000000000000000000000000000000';

      expect(() => decrypt(encrypted)).toThrow();
    });
  });

  describe('sanitizeForLogging', () => {
    it('should return redacted string with line and char count', () => {
      const content = 'single line';
      const result = sanitizeForLogging(content);

      expect(result).toBe('[REDACTED: 1 lines, 11 characters]');
    });

    it('should count multiple lines correctly', () => {
      const content = 'line1\nline2\nline3';
      const result = sanitizeForLogging(content);

      expect(result).toContain('3 lines');
    });

    it('should not expose actual content', () => {
      const content = 'super-secret-api-key-123';
      const result = sanitizeForLogging(content);

      expect(result).not.toContain('super');
      expect(result).not.toContain('secret');
      expect(result).not.toContain('api');
      expect(result).not.toContain('key');
      expect(result).not.toContain('123');
    });

    it('should handle empty string', () => {
      const result = sanitizeForLogging('');
      expect(result).toBe('[REDACTED: 1 lines, 0 characters]');
    });
  });
});
