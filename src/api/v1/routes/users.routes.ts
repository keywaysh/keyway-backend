import { FastifyInstance } from 'fastify';
import { authenticateGitHub } from '../../../middleware/auth';
import { db, users } from '../../../db';
import { eq } from 'drizzle-orm';
import { sendData } from '../../../lib';

/**
 * User routes
 * GET /api/v1/users/me - Get current user profile
 */
export async function usersRoutes(fastify: FastifyInstance) {
  /**
   * GET /me
   * Return the authenticated user profile
   */
  fastify.get('/me', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    const githubUser = request.githubUser!;

    // Get user from database
    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });

    const userData = user
      ? {
          id: user.id,
          githubId: user.githubId,
          username: user.username,
          email: user.email,
          avatarUrl: user.avatarUrl,
          createdAt: user.createdAt.toISOString(),
        }
      : {
          id: null,
          githubId: githubUser.githubId,
          username: githubUser.username,
          email: githubUser.email,
          avatarUrl: githubUser.avatarUrl,
          createdAt: null,
        };

    return sendData(reply, userData, { requestId: request.id });
  });
}
