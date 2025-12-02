import { FastifyRequest, FastifyReply } from 'fastify';
import { UnauthorizedError } from '../lib/errors';
import { config } from '../config';

// Hardcoded admin usernames (GitHub usernames)
const ADMIN_USERNAMES = ['NicolasRitouet'];

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

/**
 * Middleware for admin dashboard access.
 * Allows access via:
 * 1. X-Admin-Secret header (for API/curl access)
 * 2. Logged-in user with admin username
 */
export async function requireAdmin(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  // Check X-Admin-Secret header first
  const secret = request.headers['x-admin-secret'];
  if (secret && config.admin.enabled && secret === config.admin.secret) {
    request.log.info('Admin access granted via secret');
    return;
  }

  // Check logged-in user
  const user = request.githubUser;
  if (user && ADMIN_USERNAMES.includes(user.username)) {
    request.log.info({ username: user.username }, 'Admin access granted via user');
    return;
  }

  throw new UnauthorizedError('Admin access required');
}
