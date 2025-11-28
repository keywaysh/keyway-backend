import { FastifyInstance } from 'fastify';
import { authenticateGitHub } from '../../../middleware/auth';

/**
 * Billing routes (placeholder endpoints for future Stripe/Paddle integration)
 * POST /api/v1/billing/create-checkout-session - Create checkout session for upgrade
 * POST /api/v1/billing/manage - Get billing portal link
 *
 * NOTE: These routes return 501 Not Implemented until billing is integrated.
 */
export async function billingRoutes(fastify: FastifyInstance) {
  /**
   * POST /create-checkout-session
   * Placeholder for creating a Stripe/Paddle checkout session
   */
  fastify.post('/create-checkout-session', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    return reply.status(501).send({
      error: 'NOT_IMPLEMENTED',
      message: 'Billing integration coming soon. Pro and Team plans are not yet available.',
      requestId: request.id,
    });
  });

  /**
   * POST /manage
   * Placeholder for Stripe/Paddle billing portal
   */
  fastify.post('/manage', {
    preHandler: [authenticateGitHub],
  }, async (request, reply) => {
    return reply.status(501).send({
      error: 'NOT_IMPLEMENTED',
      message: 'Billing portal coming soon. Pro and Team plans are not yet available.',
      requestId: request.id,
    });
  });
}
