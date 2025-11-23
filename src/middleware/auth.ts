import { FastifyRequest, FastifyReply } from 'fastify';
import { UnauthorizedError, ForbiddenError } from '../errors';
import { getUserFromToken, hasRepoAccess, hasAdminAccess } from '../utils/github';
import { verifyKeywayToken } from '../utils/jwt';
import { db, users } from '../db';
import { eq } from 'drizzle-orm';

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
 * Extract and validate Authorization header
 * Supports both GitHub access tokens and Keyway JWT tokens
 */
export async function authenticateGitHub(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new UnauthorizedError('Authorization header required');
  }

  if (!authHeader.startsWith('Bearer ')) {
    throw new UnauthorizedError('Authorization header must use Bearer scheme');
  }

  const token = authHeader.substring(7);

  if (!token) {
    throw new UnauthorizedError('Access token is required');
  }

  // Try to verify as Keyway JWT token first
  try {
    const payload = verifyKeywayToken(token);

    // Get user from database using userId from JWT
    const user = await db.query.users.findFirst({
      where: eq(users.id, payload.userId),
    });

    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    // Attach to request for use in route handlers
    // Use the GitHub access token stored in DB for API calls
    request.accessToken = user.accessToken;
    request.githubUser = {
      githubId: user.githubId,
      username: user.username,
      email: user.email,
      avatarUrl: user.avatarUrl,
    };

    return;
  } catch (error) {
    // If not a valid JWT, try as GitHub access token
    if (error instanceof Error && error.message.includes('Token')) {
      // Token is invalid JWT, try as GitHub token
      try {
        const githubUser = await getUserFromToken(token);

        // Attach to request for use in route handlers
        request.accessToken = token;
        request.githubUser = githubUser;
        return;
      } catch (githubError) {
        throw new UnauthorizedError('Invalid access token');
      }
    }

    throw error;
  }
}

/**
 * Verify user has access to a repository (collaborator or admin)
 * Requires authenticateGitHub to be called first
 */
export async function requireRepoAccess(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.accessToken) {
    throw new UnauthorizedError('Authentication required');
  }

  // Get repo name from params (encoded) or body
  const params = request.params as { repo?: string };
  const body = request.body as { repoFullName?: string };

  const repoFullName = params.repo
    ? decodeURIComponent(params.repo)
    : body?.repoFullName;

  if (!repoFullName) {
    throw new ForbiddenError('Repository name required');
  }

  const hasAccess = await hasRepoAccess(request.accessToken, repoFullName);

  if (!hasAccess) {
    throw new ForbiddenError('You do not have access to this repository');
  }
}

/**
 * Verify user has admin access to a repository
 * Requires authenticateGitHub to be called first
 */
export async function requireAdminAccess(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.accessToken) {
    throw new UnauthorizedError('Authentication required');
  }

  const body = request.body as { repoFullName?: string };
  const repoFullName = body?.repoFullName;

  if (!repoFullName) {
    throw new ForbiddenError('Repository name required');
  }

  const isAdmin = await hasAdminAccess(request.accessToken, repoFullName);

  if (!isAdmin) {
    throw new ForbiddenError('Only repository admins can perform this action');
  }
}
