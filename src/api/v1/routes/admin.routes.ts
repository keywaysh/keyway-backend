import { FastifyInstance } from 'fastify';
import { requireAdminSecret } from '../../../middleware/admin';
import { rotateEncryptionKeys } from '../../../services/keyRotation';

/**
 * Admin Routes
 * Protected by X-Admin-Secret header
 */
export async function adminRoutes(fastify: FastifyInstance) {
  /**
   * POST /admin/rotate-key
   * Rotate encryption keys to the current version
   *
   * Query params:
   * - dryRun=true: Preview what would be rotated without making changes
   * - batchSize=100: Number of records to process at a time
   */
  fastify.post<{
    Querystring: {
      dryRun?: string;
      batchSize?: string;
    };
  }>('/rotate-key', {
    preHandler: [requireAdminSecret],
  }, async (request, reply) => {
    const dryRun = request.query.dryRun === 'true';
    const batchSize = request.query.batchSize
      ? parseInt(request.query.batchSize, 10)
      : 100;

    request.log.info({ dryRun, batchSize }, 'Starting key rotation');

    const result = await rotateEncryptionKeys({ dryRun, batchSize });

    const totalFailed =
      result.secrets.failed +
      result.providerTokens.failed +
      result.userTokens.failed;

    if (totalFailed > 0) {
      request.log.warn({ result }, 'Key rotation completed with failures');
    } else {
      request.log.info({ result }, 'Key rotation completed successfully');
    }

    return reply.send({
      success: totalFailed === 0,
      dryRun,
      ...result,
    });
  });
}
