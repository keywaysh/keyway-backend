import { FastifyRequest, FastifyReply } from 'fastify';
import { UnauthorizedError } from '../lib/errors';
import { config } from '../config';

/**
 * Middleware to require admin secret for protected admin endpoints.
 * Uses X-Admin-Secret header for authentication.
 */
export async function requireAdminSecret(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  if (!config.admin.enabled) {
    throw new UnauthorizedError('Admin endpoints are not configured');
  }

  const secret = request.headers['x-admin-secret'];

  if (!secret) {
    request.log.warn('Admin endpoint accessed without X-Admin-Secret header');
    throw new UnauthorizedError('Admin authentication required');
  }

  if (secret !== config.admin.secret) {
    request.log.warn('Admin endpoint accessed with invalid secret');
    throw new UnauthorizedError('Invalid admin credentials');
  }

  request.log.info('Admin access granted');
}
