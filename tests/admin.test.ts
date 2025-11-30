import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { FastifyRequest, FastifyReply } from 'fastify';

// Mock config
vi.mock('../src/config', () => ({
  config: {
    admin: {
      secret: 'test-admin-secret-that-is-at-least-32-chars',
      enabled: true,
    },
  },
}));

import { requireAdminSecret } from '../src/middleware/admin';
import { UnauthorizedError } from '../src/lib/errors';

describe('Admin Middleware', () => {
  const mockReply = {} as FastifyReply;

  const createMockRequest = (headers: Record<string, string | undefined> = {}): FastifyRequest => ({
    headers,
    log: {
      warn: vi.fn(),
      info: vi.fn(),
    },
  } as unknown as FastifyRequest);

  describe('requireAdminSecret', () => {
    it('should allow request with valid admin secret', async () => {
      const request = createMockRequest({
        'x-admin-secret': 'test-admin-secret-that-is-at-least-32-chars',
      });

      await expect(requireAdminSecret(request, mockReply)).resolves.toBeUndefined();
      expect(request.log.info).toHaveBeenCalledWith('Admin access granted');
    });

    it('should reject request without X-Admin-Secret header', async () => {
      const request = createMockRequest({});

      await expect(requireAdminSecret(request, mockReply)).rejects.toThrow(UnauthorizedError);
      expect(request.log.warn).toHaveBeenCalled();
    });

    it('should reject request with invalid admin secret', async () => {
      const request = createMockRequest({
        'x-admin-secret': 'wrong-secret',
      });

      await expect(requireAdminSecret(request, mockReply)).rejects.toThrow(UnauthorizedError);
      expect(request.log.warn).toHaveBeenCalled();
    });

    it('should reject request with empty admin secret', async () => {
      const request = createMockRequest({
        'x-admin-secret': '',
      });

      await expect(requireAdminSecret(request, mockReply)).rejects.toThrow(UnauthorizedError);
    });

    it('should include correct error message for missing header', async () => {
      const request = createMockRequest({});

      try {
        await requireAdminSecret(request, mockReply);
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedError);
        expect((error as UnauthorizedError).detail).toBe('Admin authentication required');
      }
    });

    it('should include correct error message for invalid secret', async () => {
      const request = createMockRequest({
        'x-admin-secret': 'wrong',
      });

      try {
        await requireAdminSecret(request, mockReply);
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedError);
        expect((error as UnauthorizedError).detail).toBe('Invalid admin credentials');
      }
    });
  });
});
