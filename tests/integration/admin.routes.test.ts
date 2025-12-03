import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FastifyInstance } from 'fastify';
import { createTestApp } from '../helpers/testApp';

// Use vi.hoisted for mocks that need to be available in vi.mock
const { mockEncrypt, mockDecrypt } = vi.hoisted(() => ({
  mockEncrypt: vi.fn(),
  mockDecrypt: vi.fn(),
}));

// Mock config with admin enabled
vi.mock('../../src/config', () => ({
  config: {
    admin: {
      secret: 'test-admin-secret-that-is-at-least-32-characters-long',
      enabled: true,
    },
    server: {
      isDevelopment: true,
    },
    github: {
      apiBaseUrl: 'https://api.github.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
    },
    cors: {
      allowedOrigins: [],
    },
  },
}));

// Mock the database module
vi.mock('../../src/db', () => {
  const mockSecrets = [
    { id: '1', key: 'API_KEY', encryptedValue: 'enc1', iv: 'iv1', authTag: 'tag1', encryptionVersion: 1 },
  ];

  return {
    db: {
      query: {
        secrets: {
          findMany: vi.fn().mockResolvedValue(mockSecrets),
        },
        providerConnections: {
          findMany: vi.fn().mockResolvedValue([]),
        },
        users: {
          findMany: vi.fn().mockResolvedValue([]),
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

// Mock encryption service
vi.mock('../../src/utils/encryption', () => ({
  getEncryptionService: vi.fn().mockResolvedValue({
    encrypt: mockEncrypt,
    decrypt: mockDecrypt,
  }),
}));

describe('Admin Routes', () => {
  let app: FastifyInstance;
  const VALID_ADMIN_SECRET = 'test-admin-secret-that-is-at-least-32-characters-long';

  beforeEach(async () => {
    vi.clearAllMocks();

    mockEncrypt.mockResolvedValue({
      encryptedContent: 'new-encrypted',
      iv: 'new-iv',
      authTag: 'new-tag',
      version: 2,
    });
    mockDecrypt.mockResolvedValue('decrypted-value');

    app = await createTestApp();

    const { adminRoutes } = await import('../../src/api/v1/routes/admin.routes');
    await app.register(adminRoutes, { prefix: '/v1/admin' });

    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /v1/admin/rotate-key', () => {
    it('should reject request without X-Admin-Secret header', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key',
      });

      expect(response.statusCode).toBe(401);
    });

    it('should reject request with invalid admin secret', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key',
        headers: {
          'x-admin-secret': 'wrong-secret',
        },
      });

      expect(response.statusCode).toBe(401);
    });

    it('should accept request with valid admin secret', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key',
        headers: {
          'x-admin-secret': VALID_ADMIN_SECRET,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      // Verify response wrapper format
      expect(body).toHaveProperty('data');
      expect(body).toHaveProperty('meta');
      expect(body.meta).toHaveProperty('requestId');

      // Verify data contents
      expect(body.data.success).toBe(true);
      expect(body.data).toHaveProperty('targetVersion');
      expect(body.data).toHaveProperty('secrets');
      expect(body.data).toHaveProperty('providerTokens');
      expect(body.data).toHaveProperty('userTokens');
    });

    it('should support dry_run query parameter', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key?dry_run=true',
        headers: {
          'x-admin-secret': VALID_ADMIN_SECRET,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.dryRun).toBe(true);
      expect(body.data.secrets.rotated).toBe(0); // Dry run doesn't rotate
    });

    it('should support batch_size query parameter', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key?batch_size=10',
        headers: {
          'x-admin-secret': VALID_ADMIN_SECRET,
        },
      });

      expect(response.statusCode).toBe(200);
    });

    it('should return correct response structure', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key',
        headers: {
          'x-admin-secret': VALID_ADMIN_SECRET,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      // Check wrapper structure
      expect(body).toHaveProperty('data');
      expect(body).toHaveProperty('meta');

      // Check data structure
      expect(body.data.secrets).toHaveProperty('total');
      expect(body.data.secrets).toHaveProperty('rotated');
      expect(body.data.secrets).toHaveProperty('failed');

      expect(body.data.providerTokens).toHaveProperty('total');
      expect(body.data.providerTokens).toHaveProperty('rotated');
      expect(body.data.providerTokens).toHaveProperty('failed');

      expect(body.data.userTokens).toHaveProperty('total');
      expect(body.data.userTokens).toHaveProperty('rotated');
      expect(body.data.userTokens).toHaveProperty('failed');
    });

    it('should report success=false when there are failures', async () => {
      // Make decryption fail
      mockDecrypt.mockRejectedValue(new Error('Decryption failed'));

      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/rotate-key',
        headers: {
          'x-admin-secret': VALID_ADMIN_SECRET,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.success).toBe(false);
      expect(body.data.secrets.failed).toBeGreaterThan(0);
    });
  });
});
