import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticateGitHub } from '../../../middleware/auth';
import { db, users } from '../../../db';
import { eq } from 'drizzle-orm';
import { sendData, sendPaginatedData, sendCreated, sendNoContent, NotFoundError, ForbiddenError, buildPaginationMeta, parsePagination } from '../../../lib';
import {
  getVaultsForUser,
  getVaultByRepo,
  getVaultByRepoInternal,
  touchVault,
  getSecretsForVault,
  upsertSecret,
  updateSecret,
  deleteSecret,
  logActivity,
  extractRequestInfo,
} from '../../../services';
import { hasRepoAccess } from '../../../utils/github';
import { trackEvent, AnalyticsEvents } from '../../../utils/analytics';

// Schemas
const UpsertSecretSchema = z.object({
  key: z.string().min(1).max(255).regex(/^[A-Z][A-Z0-9_]*$/, {
    message: 'Key must be uppercase with underscores (e.g., DATABASE_URL)',
  }),
  value: z.string(),
  environment: z.string().min(1).max(50).default('default'),
});

const PatchSecretSchema = z.object({
  name: z.string().min(1).max(255).regex(/^[A-Z][A-Z0-9_]*$/, {
    message: 'Key must be uppercase with underscores (e.g., DATABASE_URL)',
  }).optional(),
  value: z.string().optional(),
}).refine(data => data.name !== undefined || data.value !== undefined, {
  message: 'At least one of name or value must be provided',
});

/**
 * Vault routes
 * GET    /api/v1/vaults              - List vaults
 * GET    /api/v1/vaults/:owner/:repo - Get vault details
 *
 * Nested secrets:
 * GET    /api/v1/vaults/:owner/:repo/secrets           - List secrets
 * POST   /api/v1/vaults/:owner/:repo/secrets           - Create/update secret
 * PATCH  /api/v1/vaults/:owner/:repo/secrets/:secretId - Update secret
 * DELETE /api/v1/vaults/:owner/:repo/secrets/:secretId - Delete secret
 */
export async function vaultsRoutes(fastify: FastifyInstance) {
  /**
   * GET /
   * List all vaults for the authenticated user
   */
  fastify.get('/', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const githubUser = request.githubUser!;
    const accessToken = request.accessToken!;
    const pagination = parsePagination(request.query);

    // Get user from database
    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });

    if (!user) {
      return sendPaginatedData(reply, [], buildPaginationMeta(pagination, 0, 0), {
        requestId: request.id,
      });
    }

    const vaultList = await getVaultsForUser(user.id, accessToken);

    // Apply pagination (in-memory for now, could be optimized)
    const paginatedVaults = vaultList.slice(pagination.offset, pagination.offset + pagination.limit);

    return sendPaginatedData(
      reply,
      paginatedVaults,
      buildPaginationMeta(pagination, vaultList.length, paginatedVaults.length),
      { requestId: request.id }
    );
  });

  /**
   * GET /:owner/:repo
   * Get vault details by owner/repo
   */
  fastify.get('/:owner/:repo', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const params = request.params as { owner: string; repo: string };
    const repoFullName = `${params.owner}/${params.repo}`;
    const accessToken = request.accessToken!;

    const { vault, hasAccess } = await getVaultByRepo(repoFullName, accessToken);

    if (!vault || !hasAccess) {
      throw new NotFoundError(`Vault '${repoFullName}' not found or you don't have access`);
    }

    return sendData(reply, vault, { requestId: request.id });
  });

  /**
   * GET /:owner/:repo/secrets
   * List secrets for a vault
   */
  fastify.get('/:owner/:repo/secrets', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const params = request.params as { owner: string; repo: string };
    const repoFullName = `${params.owner}/${params.repo}`;
    const accessToken = request.accessToken!;
    const pagination = parsePagination(request.query);

    const vault = await getVaultByRepoInternal(repoFullName);
    if (!vault) {
      throw new NotFoundError('Vault not found');
    }

    const hasAccess = await hasRepoAccess(accessToken, vault.repoFullName);
    if (!hasAccess) {
      throw new ForbiddenError('You do not have access to this vault');
    }

    const secrets = await getSecretsForVault(vault.id);

    // Apply pagination
    const paginatedSecrets = secrets.slice(pagination.offset, pagination.offset + pagination.limit);

    return sendPaginatedData(
      reply,
      paginatedSecrets,
      buildPaginationMeta(pagination, secrets.length, paginatedSecrets.length),
      { requestId: request.id }
    );
  });

  /**
   * POST /:owner/:repo/secrets
   * Create or update a secret
   */
  fastify.post('/:owner/:repo/secrets', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const params = request.params as { owner: string; repo: string };
    const repoFullName = `${params.owner}/${params.repo}`;
    const body = UpsertSecretSchema.parse(request.body);
    const githubUser = request.githubUser!;
    const accessToken = request.accessToken!;

    const vault = await getVaultByRepoInternal(repoFullName);
    if (!vault) {
      throw new NotFoundError('Vault not found');
    }

    const hasAccess = await hasRepoAccess(accessToken, vault.repoFullName);
    if (!hasAccess) {
      throw new ForbiddenError('You do not have access to this vault');
    }

    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });
    if (!user) {
      throw new ForbiddenError('User not found in database');
    }

    const result = await upsertSecret({
      vaultId: vault.id,
      key: body.key,
      value: body.value,
      environment: body.environment,
    });

    await touchVault(vault.id);

    const action = result.status === 'created' ? 'secret_created' : 'secret_updated';
    await logActivity({
      userId: user.id,
      action,
      platform: 'web',
      vaultId: vault.id,
      metadata: { key: body.key, environment: body.environment },
      ...extractRequestInfo(request),
    });

    trackEvent(user.id, AnalyticsEvents.SECRETS_PUSHED, {
      repoFullName: vault.repoFullName,
      environment: body.environment,
      action: result.status,
    });

    if (result.status === 'created') {
      return sendCreated(reply, result, { requestId: request.id });
    }
    return sendData(reply, result, { requestId: request.id });
  });

  /**
   * PATCH /:owner/:repo/secrets/:secretId
   * Update a secret
   */
  fastify.patch('/:owner/:repo/secrets/:secretId', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const params = request.params as { owner: string; repo: string; secretId: string };
    const repoFullName = `${params.owner}/${params.repo}`;
    const body = PatchSecretSchema.parse(request.body);
    const githubUser = request.githubUser!;
    const accessToken = request.accessToken!;

    const vault = await getVaultByRepoInternal(repoFullName);
    if (!vault) {
      throw new NotFoundError('Vault not found');
    }

    const hasAccess = await hasRepoAccess(accessToken, vault.repoFullName);
    if (!hasAccess) {
      throw new ForbiddenError('You do not have access to this vault');
    }

    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });
    if (!user) {
      throw new ForbiddenError('User not found in database');
    }

    const updatedSecret = await updateSecret(params.secretId, vault.id, {
      key: body.name,
      value: body.value,
    });

    if (!updatedSecret) {
      throw new NotFoundError('Secret not found');
    }

    await logActivity({
      userId: user.id,
      action: 'secret_updated',
      platform: 'web',
      vaultId: vault.id,
      metadata: { key: updatedSecret.key, environment: updatedSecret.environment },
      ...extractRequestInfo(request),
    });

    return sendData(reply, updatedSecret, { requestId: request.id });
  });

  /**
   * DELETE /:owner/:repo/secrets/:secretId
   * Delete a secret
   */
  fastify.delete('/:owner/:repo/secrets/:secretId', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const params = request.params as { owner: string; repo: string; secretId: string };
    const repoFullName = `${params.owner}/${params.repo}`;
    const githubUser = request.githubUser!;
    const accessToken = request.accessToken!;

    const vault = await getVaultByRepoInternal(repoFullName);
    if (!vault) {
      throw new NotFoundError('Vault not found');
    }

    const hasAccess = await hasRepoAccess(accessToken, vault.repoFullName);
    if (!hasAccess) {
      throw new ForbiddenError('You do not have access to this vault');
    }

    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });
    if (!user) {
      throw new ForbiddenError('User not found in database');
    }

    const deletedSecret = await deleteSecret(params.secretId, vault.id);
    if (!deletedSecret) {
      throw new NotFoundError('Secret not found');
    }

    await touchVault(vault.id);

    await logActivity({
      userId: user.id,
      action: 'secret_deleted',
      platform: 'web',
      vaultId: vault.id,
      metadata: { key: deletedSecret.key, environment: deletedSecret.environment },
      ...extractRequestInfo(request),
    });

    return sendNoContent(reply);
  });
}
