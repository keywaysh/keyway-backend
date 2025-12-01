/**
 * Installation Routes
 * Handles GitHub App installation checks and management
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { authenticateGitHub } from '../../../middleware/auth';
import { isAppInstalledOnRepo, checkUserRepoAccess } from '../../../services/githubApp.service';
import { isGitHubAppEnabled, getInstallationUrl } from '../../../utils/githubApp';
import { BadRequestError } from '../../../lib/errors';

// Request schemas
const checkInstallationQuerySchema = z.object({
  repo: z.string().min(1).regex(/^[^/]+\/[^/]+$/, 'Invalid repo format (expected owner/repo)'),
});

export async function installationsRoutes(fastify: FastifyInstance) {
  /**
   * Check if GitHub App is installed on a repository
   * GET /v1/installations/check?repo=owner/repo
   *
   * Returns:
   * - installed: boolean - whether the app is installed
   * - installUrl: string - URL to install the app (if not installed)
   * - hasAccess: boolean - whether the authenticated user has access (if installed)
   */
  fastify.get(
    '/check',
    {
      preHandler: [authenticateGitHub],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const query = checkInstallationQuerySchema.safeParse(request.query);
      if (!query.success) {
        throw new BadRequestError('Invalid query parameters: ' + query.error.errors.map(e => e.message).join(', '));
      }

      const { repo } = query.data;
      const username = request.githubUser?.username;

      if (!username) {
        throw new BadRequestError('User not authenticated');
      }

      // Check if GitHub App is enabled
      if (!isGitHubAppEnabled()) {
        // If GitHub App is not configured, return a simplified response
        // This allows backward compatibility during transition
        return reply.send({
          installed: true,
          hasAccess: true,
          message: 'GitHub App not required (legacy mode)',
        });
      }

      // Check installation status
      const installStatus = await isAppInstalledOnRepo(repo);

      if (!installStatus.installed) {
        return reply.send({
          installed: false,
          installUrl: installStatus.installUrl,
          message: 'GitHub App is not installed on this repository',
        });
      }

      // Check user access
      const accessStatus = await checkUserRepoAccess(repo, username);

      return reply.send({
        installed: true,
        installUrl: installStatus.installUrl,
        hasAccess: accessStatus.hasAccess,
        permission: accessStatus.permission,
        message: accessStatus.hasAccess
          ? 'You have access to this repository'
          : 'You do not have write access to this repository',
      });
    }
  );

  /**
   * Get installation URL for a repository
   * GET /v1/installations/url?repo=owner/repo
   *
   * This endpoint doesn't require authentication
   * It's used by the CLI to get the installation URL before login
   */
  fastify.get('/url', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { repo?: string };
    const installUrl = getInstallationUrl(query.repo);

    return reply.send({
      installUrl,
      appName: 'keyway-secrets',
    });
  });

  /**
   * Health check for GitHub App configuration
   * GET /v1/installations/status
   */
  fastify.get('/status', async (request: FastifyRequest, reply: FastifyReply) => {
    const enabled = isGitHubAppEnabled();

    return reply.send({
      enabled,
      message: enabled
        ? 'GitHub App is configured and ready'
        : 'GitHub App is not configured (using legacy OAuth)',
    });
  });
}
