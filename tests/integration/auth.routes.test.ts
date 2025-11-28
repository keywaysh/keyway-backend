import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import formbody from '@fastify/formbody';
import { mockUser, mockDeviceCode, createMockDb, createMockGitHubUtils } from '../helpers/mocks';

// Mock the database module
vi.mock('../../src/db', () => {
  const mockDb = createMockDb();
  return {
    db: mockDb,
    users: { id: 'id', githubId: 'githubId' },
    vaults: { id: 'id' },
    secrets: { id: 'id' },
    deviceCodes: { id: 'id', deviceCode: 'deviceCode', userCode: 'userCode' },
  };
});

// Mock GitHub utils
vi.mock('../../src/utils/github', () => createMockGitHubUtils());

// Mock analytics (no-op)
vi.mock('../../src/utils/analytics', () => ({
  trackEvent: vi.fn(),
  identifyUser: vi.fn(),
  getSignupSource: vi.fn().mockReturnValue('direct'),
  AnalyticsEvents: {
    AUTH_SUCCESS: 'api_auth_success',
    AUTH_FAILURE: 'api_auth_failure',
    USER_CREATED: 'api_user_created',
  },
}));

describe('Auth Routes', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    // Reset all mocks
    vi.clearAllMocks();

    // Create fresh app for each test
    app = Fastify({ logger: false });
    await app.register(formbody);

    // Import and register auth routes after mocks are set up
    const { authRoutes } = await import('../../src/api/v1/routes/auth.routes');
    await app.register(authRoutes, { prefix: '/v1/auth' });

    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /v1/auth/device/start', () => {
    it('should start device flow and return codes', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/start',
        payload: {},
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body).toHaveProperty('deviceCode');
      expect(body).toHaveProperty('userCode');
      expect(body).toHaveProperty('verificationUri');
      expect(body).toHaveProperty('verificationUriComplete');
      expect(body).toHaveProperty('expiresIn');
      expect(body).toHaveProperty('interval');

      // User code should be in format XXXX-XXXX
      expect(body.userCode).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    });

    it('should accept optional repository parameter', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/start',
        payload: {
          repository: 'testuser/test-repo',
        },
      });

      expect(response.statusCode).toBe(200);
    });
  });

  describe('POST /v1/auth/device/poll', () => {
    it('should return pending status for pending device code', async () => {
      const { db } = await import('../../src/db');
      (db.query.deviceCodes.findFirst as any).mockResolvedValue({
        ...mockDeviceCode,
        status: 'pending',
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/poll',
        payload: {
          deviceCode: 'DEVICE123456',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('pending');
    });

    it('should return error for invalid device code', async () => {
      const { db } = await import('../../src/db');
      (db.query.deviceCodes.findFirst as any).mockResolvedValue(null);

      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/poll',
        payload: {
          deviceCode: 'INVALID123',
        },
      });

      expect(response.statusCode).toBe(404);
    });

    it('should return expired status for expired device code', async () => {
      const { db } = await import('../../src/db');
      (db.query.deviceCodes.findFirst as any).mockResolvedValue({
        ...mockDeviceCode,
        status: 'pending',
        expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/poll',
        payload: {
          deviceCode: 'DEVICE123456',
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('expired');
    });

    it('should return token when device code is approved', async () => {
      const { db } = await import('../../src/db');
      (db.query.deviceCodes.findFirst as any).mockResolvedValue({
        ...mockDeviceCode,
        status: 'approved',
        userId: mockUser.id,
        user: mockUser,
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/poll',
        payload: {
          deviceCode: 'DEVICE123456',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('approved');
      expect(body).toHaveProperty('keywayToken');
      expect(body).toHaveProperty('githubLogin');
      expect(body).toHaveProperty('expiresAt');
    });

    it('should return denied status for denied device code', async () => {
      const { db } = await import('../../src/db');
      (db.query.deviceCodes.findFirst as any).mockResolvedValue({
        ...mockDeviceCode,
        status: 'denied',
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/device/poll',
        payload: {
          deviceCode: 'DEVICE123456',
        },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('denied');
    });
  });

  describe('GET /v1/auth/device/verify', () => {
    it('should return verification page HTML', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/auth/device/verify',
      });

      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.body).toContain('Verify Your Device');
    });

    it('should pre-fill user code from query parameter', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/auth/device/verify?user_code=ABCD-1234',
      });

      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('ABCD-1234');
    });
  });

  describe('POST /v1/auth/logout', () => {
    it('should clear session cookies', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/auth/logout',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);

      // Check that Set-Cookie headers are present to clear cookies
      const cookies = response.headers['set-cookie'];
      expect(cookies).toBeDefined();
    });
  });
});
