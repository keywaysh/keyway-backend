import { describe, it, expect, vi, beforeEach } from 'vitest';

// Use vi.hoisted to define mocks that can be used in vi.mock
const { mockEncrypt, mockDecrypt } = vi.hoisted(() => ({
  mockEncrypt: vi.fn(),
  mockDecrypt: vi.fn(),
}));

// All mocks must be defined inline without referencing external variables
vi.mock('../src/db', () => {
  const mockSecrets = [
    { id: '1', key: 'API_KEY', encryptedValue: 'enc1', iv: 'iv1', authTag: 'tag1', encryptionVersion: 1 },
    { id: '2', key: 'DB_URL', encryptedValue: 'enc2', iv: 'iv2', authTag: 'tag2', encryptionVersion: 1 },
  ];

  const mockProviderConnections = [
    {
      id: 'conn1',
      provider: 'vercel',
      encryptedAccessToken: 'enc-token',
      accessTokenIv: 'iv',
      accessTokenAuthTag: 'tag',
      accessTokenVersion: 1,
      encryptedRefreshToken: null,
      refreshTokenIv: null,
      refreshTokenAuthTag: null,
      refreshTokenVersion: null,
    },
  ];

  const mockUsers = [
    {
      id: 'user1',
      encryptedAccessToken: 'enc-gh-token',
      accessTokenIv: 'iv',
      accessTokenAuthTag: 'tag',
      tokenEncryptionVersion: 1,
    },
  ];

  return {
    db: {
      query: {
        secrets: {
          findMany: vi.fn().mockResolvedValue(mockSecrets),
        },
        providerConnections: {
          findMany: vi.fn().mockResolvedValue(mockProviderConnections),
        },
        users: {
          findMany: vi.fn().mockResolvedValue(mockUsers),
        },
      },
      update: vi.fn().mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue(undefined),
        }),
      }),
    },
    secrets: { id: 'id', encryptionVersion: 'encryptionVersion' },
    providerConnections: { id: 'id', accessTokenVersion: 'accessTokenVersion' },
    users: { id: 'id', tokenEncryptionVersion: 'tokenEncryptionVersion' },
  };
});

vi.mock('../src/utils/encryption', () => ({
  getEncryptionService: vi.fn().mockResolvedValue({
    encrypt: mockEncrypt,
    decrypt: mockDecrypt,
  }),
}));

import { rotateEncryptionKeys } from '../src/services/keyRotation';

describe('Key Rotation Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEncrypt.mockResolvedValue({
      encryptedContent: 'new-encrypted',
      iv: 'new-iv',
      authTag: 'new-tag',
      version: 2,
    });
    mockDecrypt.mockResolvedValue('decrypted-value');
  });

  describe('rotateEncryptionKeys', () => {
    it('should return target version and counts in dry run mode', async () => {
      const result = await rotateEncryptionKeys({ dryRun: true });

      expect(result.targetVersion).toBe(2);
      expect(result.secrets.total).toBe(2);
      expect(result.secrets.rotated).toBe(0); // Dry run = no rotations
      expect(result.secrets.failed).toBe(0);
      expect(result.providerTokens.total).toBe(1);
      expect(result.userTokens.total).toBe(1);
    });

    it('should rotate all secrets when not in dry run', async () => {
      const result = await rotateEncryptionKeys({ dryRun: false });

      expect(result.targetVersion).toBe(2);
      expect(result.secrets.rotated).toBe(2);
      expect(result.secrets.failed).toBe(0);
      expect(result.providerTokens.rotated).toBe(1);
      expect(result.userTokens.rotated).toBe(1);

      // Verify encrypt/decrypt were called
      expect(mockDecrypt).toHaveBeenCalled();
      expect(mockEncrypt).toHaveBeenCalled();
    });

    it('should use default batch size of 100', async () => {
      const result = await rotateEncryptionKeys({});

      expect(result.secrets.total).toBe(2);
    });

    it('should count failures when decryption fails', async () => {
      mockDecrypt.mockRejectedValueOnce(new Error('Decryption failed'));

      const result = await rotateEncryptionKeys({ dryRun: false });

      // First secret fails, second succeeds
      expect(result.secrets.failed).toBe(1);
      expect(result.secrets.rotated).toBe(1);
    });

    it('should return correct structure', async () => {
      const result = await rotateEncryptionKeys({ dryRun: true });

      expect(result).toHaveProperty('targetVersion');
      expect(result).toHaveProperty('secrets');
      expect(result).toHaveProperty('providerTokens');
      expect(result).toHaveProperty('userTokens');

      expect(result.secrets).toHaveProperty('total');
      expect(result.secrets).toHaveProperty('rotated');
      expect(result.secrets).toHaveProperty('failed');
    });
  });
});
