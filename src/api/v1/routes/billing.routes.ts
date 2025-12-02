import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { authenticateGitHub } from '../../../middleware/auth';
import { db, users } from '../../../db';
import {
  isStripeEnabled,
  createCheckoutSession,
  createPortalSession,
  getUserSubscription,
  constructWebhookEvent,
  handleWebhookEvent,
  getAvailablePrices,
} from '../../../services';
import { config } from '../../../config';

// Extend FastifyContextConfig for rawBody support
declare module 'fastify' {
  interface FastifyContextConfig {
    rawBody?: boolean;
  }
}

// Request schemas
const createCheckoutSessionSchema = z.object({
  priceId: z.string().min(1, 'Price ID is required'),
  successUrl: z.string().url('Valid success URL required'),
  cancelUrl: z.string().url('Valid cancel URL required'),
});

const manageSchema = z.object({
  returnUrl: z.string().url('Valid return URL required'),
});

/**
 * Billing routes for Stripe subscription management
 */
export async function billingRoutes(fastify: FastifyInstance) {
  /**
   * GET /prices
   * Get available subscription prices
   */
  fastify.get('/prices', async (request, reply) => {
    if (!isStripeEnabled()) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Billing is not currently available',
        requestId: request.id,
      });
    }

    const prices = getAvailablePrices();

    return reply.send({
      prices: {
        pro: {
          monthly: {
            id: prices?.pro.monthly,
            price: 900, // $9.00 in cents
            interval: 'month',
          },
          yearly: {
            id: prices?.pro.yearly,
            price: 9000, // $90.00 in cents
            interval: 'year',
          },
        },
        // Team prices not exposed yet (Coming soon)
      },
    });
  });

  /**
   * GET /subscription
   * Get the authenticated user's current subscription
   */
  fastify.get('/subscription', {
    preHandler: [authenticateGitHub],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const githubUser = request.githubUser!;

    // Get user from database
    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });

    if (!user) {
      return reply.send({
        subscription: null,
        plan: 'free',
        billingStatus: 'active',
      });
    }

    if (!isStripeEnabled()) {
      return reply.send({
        subscription: null,
        plan: user.plan,
        billingStatus: user.billingStatus,
      });
    }

    const subscription = await getUserSubscription(user.id);

    return reply.send({
      subscription: subscription ? {
        id: subscription.id,
        status: subscription.status,
        currentPeriodEnd: subscription.currentPeriodEnd,
        cancelAtPeriodEnd: subscription.cancelAtPeriodEnd,
      } : null,
      plan: user.plan,
      billingStatus: user.billingStatus,
      stripeCustomerId: user.stripeCustomerId,
    });
  });

  /**
   * POST /create-checkout-session
   * Create a Stripe Checkout session for subscription
   */
  fastify.post('/create-checkout-session', {
    preHandler: [authenticateGitHub],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const githubUser = request.githubUser!;

    // Get user from database
    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });

    if (!isStripeEnabled()) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Billing is not currently available',
        requestId: request.id,
      });
    }

    // Validate request body
    const parseResult = createCheckoutSessionSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid request body',
        details: parseResult.error.flatten().fieldErrors,
        requestId: request.id,
      });
    }

    const { priceId, successUrl, cancelUrl } = parseResult.data;

    // Check if user already has an active subscription
    if (user && user.plan !== 'free' && user.billingStatus === 'active') {
      return reply.status(400).send({
        error: 'ALREADY_SUBSCRIBED',
        message: 'You already have an active subscription. Use the billing portal to manage it.',
        requestId: request.id,
      });
    }

    // Validate price ID is one we recognize
    const prices = getAvailablePrices();
    const validPriceIds = [
      prices?.pro.monthly,
      prices?.pro.yearly,
      // Team prices not enabled yet
    ].filter(Boolean);

    if (!validPriceIds.includes(priceId)) {
      return reply.status(400).send({
        error: 'INVALID_PRICE',
        message: 'Invalid price ID',
        requestId: request.id,
      });
    }

    // Validate URLs are from allowed origins
    const allowedOrigins = config.cors.allowedOrigins;
    if (allowedOrigins.length > 0) {
      const successOrigin = new URL(successUrl).origin;
      const cancelOrigin = new URL(cancelUrl).origin;
      if (!allowedOrigins.includes(successOrigin) || !allowedOrigins.includes(cancelOrigin)) {
        return reply.status(400).send({
          error: 'INVALID_URL',
          message: 'Redirect URLs must be from allowed origins',
          requestId: request.id,
        });
      }
    }

    try {
      // Use existing user ID or we'll need to create user first via the service
      const userId = user?.id;
      if (!userId) {
        return reply.status(400).send({
          error: 'USER_NOT_FOUND',
          message: 'Please log in to Keyway first to create your account',
          requestId: request.id,
        });
      }

      const checkoutUrl = await createCheckoutSession(
        userId,
        user.email || `${user.username}@users.noreply.github.com`,
        user.username,
        priceId,
        successUrl,
        cancelUrl
      );

      return reply.send({ url: checkoutUrl });
    } catch (error) {
      console.error('[Billing] Failed to create checkout session:', error);
      return reply.status(500).send({
        error: 'CHECKOUT_FAILED',
        message: 'Failed to create checkout session',
        requestId: request.id,
      });
    }
  });

  /**
   * POST /manage
   * Create a Stripe Customer Portal session
   */
  fastify.post('/manage', {
    preHandler: [authenticateGitHub],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const githubUser = request.githubUser!;

    // Get user from database
    const user = await db.query.users.findFirst({
      where: eq(users.githubId, githubUser.githubId),
    });

    if (!isStripeEnabled()) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Billing is not currently available',
        requestId: request.id,
      });
    }

    // Validate request body
    const parseResult = manageSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid request body',
        details: parseResult.error.flatten().fieldErrors,
        requestId: request.id,
      });
    }

    const { returnUrl } = parseResult.data;

    // Check if user has a Stripe customer ID
    if (!user?.stripeCustomerId) {
      return reply.status(400).send({
        error: 'NO_BILLING_ACCOUNT',
        message: 'No billing account found. Subscribe to a plan first.',
        requestId: request.id,
      });
    }

    // Validate return URL is from allowed origins
    const allowedOrigins = config.cors.allowedOrigins;
    if (allowedOrigins.length > 0) {
      const returnOrigin = new URL(returnUrl).origin;
      if (!allowedOrigins.includes(returnOrigin)) {
        return reply.status(400).send({
          error: 'INVALID_URL',
          message: 'Return URL must be from an allowed origin',
          requestId: request.id,
        });
      }
    }

    try {
      const portalUrl = await createPortalSession(user.id, returnUrl);
      return reply.send({ url: portalUrl });
    } catch (error) {
      console.error('[Billing] Failed to create portal session:', error);
      return reply.status(500).send({
        error: 'PORTAL_FAILED',
        message: 'Failed to create billing portal session',
        requestId: request.id,
      });
    }
  });

  /**
   * POST /webhook
   * Handle Stripe webhook events
   * Note: This endpoint uses raw body for signature verification
   */
  fastify.post('/webhook', {
    config: {
      rawBody: true,
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    if (!isStripeEnabled()) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Billing is not configured',
      });
    }

    const signature = request.headers['stripe-signature'];
    if (!signature || typeof signature !== 'string') {
      return reply.status(400).send({
        error: 'MISSING_SIGNATURE',
        message: 'Missing Stripe signature header',
      });
    }

    // Get raw body for signature verification
    const rawBody = (request as any).rawBody as Buffer;
    if (!rawBody) {
      return reply.status(400).send({
        error: 'MISSING_BODY',
        message: 'Missing raw request body',
      });
    }

    try {
      const event = constructWebhookEvent(rawBody, signature);
      await handleWebhookEvent(event);

      return reply.send({ received: true });
    } catch (error: any) {
      console.error('[Billing] Webhook error:', error.message);

      // Return 400 for signature verification errors
      if (error.message.includes('signature')) {
        return reply.status(400).send({
          error: 'INVALID_SIGNATURE',
          message: 'Invalid webhook signature',
        });
      }

      // For other errors, still return 200 to prevent Stripe retries
      // The event was already recorded for idempotency
      return reply.send({ received: true, error: error.message });
    }
  });
}
