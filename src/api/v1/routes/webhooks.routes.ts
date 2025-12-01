/**
 * Webhook Routes
 * Handles incoming webhooks from GitHub App
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { verifyWebhookSignature, isGitHubAppEnabled } from '../../../utils/githubApp';
import {
  handleInstallationCreated,
  handleInstallationDeleted,
  handleInstallationSuspend,
  handleInstallationRepositoriesChanged,
  type InstallationCreatedPayload,
  type InstallationDeletedPayload,
  type InstallationSuspendPayload,
  type InstallationRepositoriesPayload,
} from '../../../services/githubApp.service';

export async function webhooksRoutes(fastify: FastifyInstance) {
  /**
   * GitHub App Webhook Handler
   * POST /v1/webhooks/github-app
   *
   * Receives webhooks from GitHub when:
   * - App is installed/uninstalled
   * - App is suspended/unsuspended
   * - Repositories are added/removed from installation
   */
  fastify.post(
    '/github-app',
    async (request: FastifyRequest, reply: FastifyReply) => {
      // Check if GitHub App is enabled
      if (!isGitHubAppEnabled()) {
        fastify.log.warn('[Webhook] GitHub App is not configured');
        return reply.status(503).send({ error: 'GitHub App not configured' });
      }

      // Get the signature from headers
      const signature = request.headers['x-hub-signature-256'] as string | undefined;
      const event = request.headers['x-github-event'] as string | undefined;
      const deliveryId = request.headers['x-github-delivery'] as string | undefined;

      fastify.log.info({ event, deliveryId }, '[Webhook] Received GitHub webhook');

      // Verify webhook signature
      // Note: For webhook signature verification, we use the body as-is
      // In production, ensure Fastify is configured to preserve the raw body
      const bodyString = JSON.stringify(request.body);
      if (!verifyWebhookSignature(bodyString, signature)) {
        fastify.log.warn('[Webhook] Invalid webhook signature');
        return reply.status(401).send({ error: 'Invalid signature' });
      }

      const payload = request.body as any;

      try {
        // Handle different event types
        switch (event) {
          case 'installation': {
            const action = payload.action;

            if (action === 'created') {
              await handleInstallationCreated(payload as InstallationCreatedPayload);
              fastify.log.info(
                { installationId: payload.installation.id, account: payload.installation.account.login },
                '[Webhook] Installation created'
              );
            } else if (action === 'deleted') {
              await handleInstallationDeleted(payload as InstallationDeletedPayload);
              fastify.log.info(
                { installationId: payload.installation.id },
                '[Webhook] Installation deleted'
              );
            } else if (action === 'suspend' || action === 'unsuspend') {
              await handleInstallationSuspend(payload as InstallationSuspendPayload);
              fastify.log.info(
                { installationId: payload.installation.id, action },
                '[Webhook] Installation suspend status changed'
              );
            }
            break;
          }

          case 'installation_repositories': {
            await handleInstallationRepositoriesChanged(payload as InstallationRepositoriesPayload);
            fastify.log.info(
              {
                installationId: payload.installation.id,
                action: payload.action,
                added: payload.repositories_added?.length || 0,
                removed: payload.repositories_removed?.length || 0,
              },
              '[Webhook] Installation repositories changed'
            );
            break;
          }

          default:
            fastify.log.debug({ event }, '[Webhook] Unhandled event type');
        }

        return reply.status(200).send({ received: true });
      } catch (error) {
        fastify.log.error({ error, event, deliveryId }, '[Webhook] Error processing webhook');
        // Return 200 anyway to prevent GitHub from retrying
        // We log the error for debugging
        return reply.status(200).send({ received: true, error: 'Processing error logged' });
      }
    }
  );
}
