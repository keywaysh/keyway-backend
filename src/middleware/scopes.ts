import { FastifyRequest, FastifyReply } from 'fastify';
import { ForbiddenError } from '../lib';
import { hasRequiredScopes, type ApiKeyScope } from '../utils/apiKeys';

/**
 * Middleware factory to require specific scopes for API key authentication.
 *
 * When the request is authenticated via:
 * - JWT (session): All scopes are allowed (full access)
 * - API Key: Only the scopes granted to the key are allowed
 *
 * @param requiredScopes - Array of scopes required for this endpoint
 * @returns Fastify preHandler middleware
 *
 * @example
 * fastify.get('/secrets', {
 *   preHandler: [authenticateGitHub, requireScopes(['read:secrets'])]
 * }, handler);
 */
export function requireScopes(requiredScopes: ApiKeyScope[]) {
  return async function scopeMiddleware(
    request: FastifyRequest,
    reply: FastifyReply
  ) {
    // If not authenticated via API key, allow all (JWT/session auth has full access)
    if (!request.apiKey) {
      return;
    }

    // Check if the API key has all required scopes
    const apiKeyScopes = request.apiKey.scopes;

    if (!hasRequiredScopes(apiKeyScopes, requiredScopes)) {
      const missing = requiredScopes.filter((s) => !apiKeyScopes.includes(s));
      request.log.warn(
        {
          apiKeyId: request.apiKey.id,
          required: requiredScopes,
          actual: apiKeyScopes,
          missing,
        },
        'API key missing required scopes'
      );

      throw new ForbiddenError(
        `This API key is missing required scopes: ${missing.join(', ')}. ` +
          `Required: ${requiredScopes.join(', ')}. ` +
          `Available: ${apiKeyScopes.join(', ') || 'none'}.`
      );
    }
  };
}

/**
 * Helper to check if request has a specific scope
 * Useful for conditional logic within handlers
 *
 * @param request - Fastify request
 * @param scope - Scope to check
 * @returns true if scope is available (JWT auth or API key with scope)
 */
export function hasScope(request: FastifyRequest, scope: ApiKeyScope): boolean {
  // JWT auth has all scopes
  if (!request.apiKey) {
    return true;
  }

  return request.apiKey.scopes.includes(scope);
}
