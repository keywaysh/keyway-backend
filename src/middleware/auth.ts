import { FastifyRequest, FastifyReply } from 'fastify';
import { UnauthorizedError, ForbiddenError } from '../lib';
import { getUserFromToken, hasRepoAccess, hasAdminAccess, getUserRole } from '../utils/github';
import { verifyKeywayToken } from '../utils/jwt';
import { decryptAccessToken } from '../utils/tokenEncryption';
import { db, users, vaults } from '../db';
import { eq } from 'drizzle-orm';
import { hasEnvironmentPermission } from '../utils/permissions';
import type { PermissionType, CollaboratorRole } from '../db/schema';
import { checkUserRepoAccess, isAppInstalledOnRepo } from '../services/githubApp.service';
import { isGitHubAppEnabled } from '../utils/githubApp';

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
    // Decrypt the GitHub access token stored in DB for API calls
    request.accessToken = await decryptAccessToken({
      encryptedAccessToken: user.encryptedAccessToken,
      accessTokenIv: user.accessTokenIv,
      accessTokenAuthTag: user.accessTokenAuthTag,
      tokenEncryptionVersion: user.tokenEncryptionVersion ?? 1,
    });
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
 *
 * When GitHub App is enabled:
 * - Uses installation token to verify collaborator access (no user token needed for repo access)
 * - This proves we don't need access to user's repos via OAuth
 *
 * When GitHub App is not enabled (legacy/fallback):
 * - Uses user's OAuth token to check repo access
 */
export async function requireRepoAccess(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.githubUser) {
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

  // Use GitHub App if enabled (preferred - proves no code access needed)
  if (isGitHubAppEnabled()) {
    // First check if app is installed on the repo
    const installCheck = await isAppInstalledOnRepo(repoFullName);

    if (!installCheck.installed) {
      throw new ForbiddenError(
        `GitHub App is not installed on this repository. Install at: ${installCheck.installUrl}`
      );
    }

    // Check user access via installation token
    const accessCheck = await checkUserRepoAccess(repoFullName, request.githubUser.username);

    if (!accessCheck.hasAccess) {
      throw new ForbiddenError(
        `You do not have write access to this repository (permission: ${accessCheck.permission})`
      );
    }

    return;
  }

  // Fallback: use user's OAuth token (legacy mode)
  if (!request.accessToken) {
    throw new UnauthorizedError('Authentication required');
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
  if (!request.githubUser) {
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

  // Use GitHub App if enabled
  if (isGitHubAppEnabled()) {
    const installCheck = await isAppInstalledOnRepo(repoFullName);

    if (!installCheck.installed) {
      throw new ForbiddenError(
        `GitHub App is not installed on this repository. Install at: ${installCheck.installUrl}`
      );
    }

    const accessCheck = await checkUserRepoAccess(repoFullName, request.githubUser.username);

    if (accessCheck.permission !== 'admin') {
      throw new ForbiddenError(
        `Only repository admins can perform this action (your permission: ${accessCheck.permission})`
      );
    }

    return;
  }

  // Fallback: use user's OAuth token
  if (!request.accessToken) {
    throw new UnauthorizedError('Authentication required');
  }

  const isAdmin = await hasAdminAccess(request.accessToken, repoFullName);

  if (!isAdmin) {
    throw new ForbiddenError('Only repository admins can perform this action');
  }
}

/**
 * Map GitHub permission string to CollaboratorRole
 */
function mapGitHubPermissionToRole(permission: string): CollaboratorRole | null {
  const roleMap: Record<string, CollaboratorRole> = {
    admin: 'admin',
    maintain: 'maintain',
    write: 'write',
    push: 'write',  // GitHub sometimes returns 'push' for write access
    triage: 'triage',
    read: 'read',
    pull: 'read',   // GitHub sometimes returns 'pull' for read access
  };
  return roleMap[permission] || null;
}

/**
 * Create middleware factory for environment-based permissions
 * Requires authenticateGitHub to be called first
 */
export function requireEnvironmentAccess(permissionType: PermissionType) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    if (!request.githubUser) {
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

    let userRole: CollaboratorRole | null = null;

    // Use GitHub App if enabled
    if (isGitHubAppEnabled()) {
      const installCheck = await isAppInstalledOnRepo(repoFullName);

      if (!installCheck.installed) {
        throw new ForbiddenError(
          `GitHub App is not installed on this repository. Install at: ${installCheck.installUrl}`
        );
      }

      const accessCheck = await checkUserRepoAccess(repoFullName, request.githubUser.username);

      if (!accessCheck.hasAccess) {
        throw new ForbiddenError('You do not have access to this repository');
      }

      userRole = mapGitHubPermissionToRole(accessCheck.permission);
    } else {
      // Fallback: use user's OAuth token
      if (!request.accessToken) {
        throw new UnauthorizedError('Authentication required');
      }

      userRole = await getUserRole(
        request.accessToken,
        repoFullName,
        request.githubUser.username
      );
    }

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
