import { FastifyRequest, FastifyReply } from 'fastify';
import { UnauthorizedError, ForbiddenError } from '../lib';
import { getUserFromToken, getUserRoleWithApp } from '../utils/github';
import { verifyKeywayToken, generateKeywayToken, getTokenExpiresAt } from '../utils/jwt';
import { decryptAccessToken } from '../utils/tokenEncryption';
import { db, users, vaults } from '../db';
import { eq } from 'drizzle-orm';
import { hasEnvironmentPermission } from '../utils/permissions';
import type { PermissionType } from '../db/schema';

// Extend Fastify request type
declare module 'fastify' {
  interface FastifyRequest {
    accessToken?: string;
    githubUser?: {
      githubId: number;
      username: string;
      email: string | null;
      avatarUrl: string | null;
    };
  }
}

/**
 * Extract and validate authentication token
 * Supports: Authorization header (Bearer), session cookie, or GitHub access tokens
 */
export async function authenticateGitHub(
  request: FastifyRequest,
  reply: FastifyReply
) {
  let token: string | undefined;

  // Try Authorization header first
  const authHeader = request.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }

  // Fall back to session cookie (for web dashboard)
  if (!token) {
    const cookieHeader = request.headers.cookie;
    if (cookieHeader) {
      const cookies = cookieHeader.split(';');
      const sessionCookie = cookies.find(c => c.trim().startsWith('keyway_session='));
      if (sessionCookie) {
        token = sessionCookie.split('=')[1]?.trim();
      }
    }
  }

  if (!token) {
    throw new UnauthorizedError('Authentication required');
  }

  // Log token info for debugging
  const tokenPreview = token.substring(0, 20) + '...' + token.substring(token.length - 10);
  request.log.info({ tokenPreview, tokenLength: token.length }, 'Auth middleware: received token');

  // Step 1: Try to verify as Keyway JWT token
  let payload;
  try {
    payload = verifyKeywayToken(token);
    request.log.info({ userId: payload.userId, username: payload.username }, 'Auth middleware: JWT verified successfully');
  } catch (jwtError) {
    const errorMessage = jwtError instanceof Error ? jwtError.message : 'Unknown error';
    request.log.warn({ error: errorMessage, tokenPreview }, 'Auth middleware: JWT verification failed');

    // If not a valid JWT, try as GitHub access token
    if (jwtError instanceof Error && jwtError.message.includes('Token')) {
      request.log.info({ tokenPreview }, 'Auth middleware: trying as GitHub token');
      try {
        const githubUser = await getUserFromToken(token);
        request.log.info({ githubId: githubUser.githubId, username: githubUser.username }, 'Auth middleware: GitHub token valid');

        // Attach to request for use in route handlers
        request.accessToken = token;
        request.githubUser = githubUser;
        return;
      } catch (githubError) {
        const ghErrorMsg = githubError instanceof Error ? githubError.message : 'Unknown error';
        request.log.warn({ error: ghErrorMsg }, 'Auth middleware: GitHub token also invalid');
        reply.clearCookie('keyway_session', { path: '/' });
        throw new UnauthorizedError('Invalid access token');
      }
    }

    // JWT error (expired, malformed, wrong secret)
    request.log.warn({ error: errorMessage }, 'Auth middleware: JWT error, clearing cookie');
    reply.clearCookie('keyway_session', { path: '/' });
    throw new UnauthorizedError('Invalid or expired token');
  }

  // Step 2: Get user from database
  request.log.info({ searchUserId: payload.userId }, 'Auth middleware: Searching for user in DB by userId');

  const user = await db.query.users.findFirst({
    where: eq(users.id, payload.userId),
  });

  // If user not found by userId, try to find by githubId (more reliable than username)
  // This handles the case where user was recreated with a new userId
  let resolvedUser = user;

  if (!resolvedUser) {
    const userByGithubId = await db.query.users.findFirst({
      where: eq(users.githubId, payload.githubId),
    });

    if (userByGithubId) {
      request.log.warn({
        searchedUserId: payload.userId,
        actualUserId: userByGithubId.id,
        username: payload.username,
        githubId: payload.githubId,
      }, 'Auth middleware: User found by githubId but with DIFFERENT userId - auto-healing with new token');

      // Auto-heal: generate a new JWT with the correct userId and set it as a cookie
      const newToken = generateKeywayToken({
        userId: userByGithubId.id,
        githubId: userByGithubId.githubId,
        username: userByGithubId.username,
      });

      // Set the new token as a cookie (for web dashboard)
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        path: '/',
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
        ...(isProduction && { domain: '.keyway.sh' }),
      };

      reply.setCookie('keyway_session', newToken, cookieOptions);
      request.log.info({ userId: userByGithubId.id }, 'Auth middleware: Auto-healed session with new JWT');

      resolvedUser = userByGithubId;
    } else {
      request.log.warn({
        userId: payload.userId,
        username: payload.username,
        githubId: payload.githubId,
      }, 'Auth middleware: User not found in DB by userId or githubId');

      throw new UnauthorizedError('User not found');
    }
  }

  request.log.info({ userId: resolvedUser.id, username: resolvedUser.username }, 'Auth middleware: User found in DB');

  // Step 3: Decrypt the GitHub access token stored in DB
  try {
    request.accessToken = await decryptAccessToken({
      encryptedAccessToken: resolvedUser.encryptedAccessToken,
      accessTokenIv: resolvedUser.accessTokenIv,
      accessTokenAuthTag: resolvedUser.accessTokenAuthTag,
      tokenEncryptionVersion: resolvedUser.tokenEncryptionVersion ?? 1,
    });
    request.log.info({ username: resolvedUser.username }, 'Auth middleware: GitHub token decrypted successfully');
  } catch (decryptError) {
    const errorMessage = decryptError instanceof Error ? decryptError.message : 'Unknown error';
    request.log.error({ error: errorMessage, userId: resolvedUser.id }, 'Auth middleware: Failed to decrypt GitHub token');
    throw new UnauthorizedError('Failed to decrypt stored credentials. Please re-authenticate.');
  }

  request.githubUser = {
    githubId: resolvedUser.githubId,
    username: resolvedUser.username,
    email: resolvedUser.email,
    avatarUrl: resolvedUser.avatarUrl,
  };
}

/**
 * Verify user has admin access to a repository
 * Uses GitHub App installation token to check permissions
 * Requires authenticateGitHub to be called first
 */
export async function requireAdminAccess(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.accessToken || !request.githubUser) {
    throw new UnauthorizedError('Authentication required');
  }

  // Get repo name from params (owner/repo) or body
  const params = request.params as { owner?: string; repo?: string };
  const body = request.body as { repoFullName?: string };

  const repoFullName = params.owner && params.repo
    ? `${params.owner}/${params.repo}`
    : body?.repoFullName;

  if (!repoFullName) {
    throw new ForbiddenError('Repository name required');
  }

  // Use GitHub App to check user's role on the repo
  const role = await getUserRoleWithApp(repoFullName, request.githubUser.username);
  const isAdmin = role === 'admin';

  if (!isAdmin) {
    throw new ForbiddenError('Only repository admins can perform this action');
  }
}

/**
 * Create middleware factory for environment-based permissions
 * Requires authenticateGitHub to be called first
 */
export function requireEnvironmentAccess(permissionType: PermissionType) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    if (!request.accessToken || !request.githubUser) {
      throw new UnauthorizedError('Authentication required');
    }

    // Get repo and environment from params, query, or body
    const params = request.params as { repo?: string; env?: string };
    const query = request.query as { repo?: string; environment?: string };
    const body = request.body as { repoFullName?: string; environment?: string };

    const repoFullName = params.repo
      ? decodeURIComponent(params.repo)
      : query.repo || body?.repoFullName;

    const environment = params.env || query.environment || body?.environment;

    if (!repoFullName) {
      throw new ForbiddenError('Repository name required');
    }

    if (!environment) {
      throw new ForbiddenError('Environment name required');
    }

    // Get user's role for this repository using GitHub App
    const userRole = await getUserRoleWithApp(
      repoFullName,
      request.githubUser.username
    );

    if (!userRole) {
      throw new ForbiddenError('You do not have access to this repository');
    }

    // Get vault for this repository
    const vault = await db.query.vaults.findFirst({
      where: eq(vaults.repoFullName, repoFullName),
    });

    if (!vault) {
      throw new ForbiddenError('Vault not found for this repository');
    }

    // Check environment permission
    const hasPermission = await hasEnvironmentPermission(
      vault.id,
      environment,
      userRole,
      permissionType
    );

    if (!hasPermission) {
      const action = permissionType === 'read' ? 'read from' : 'write to';
      throw new ForbiddenError(
        `Your role (${userRole}) does not have permission to ${action} the "${environment}" environment`
      );
    }
  };
}
