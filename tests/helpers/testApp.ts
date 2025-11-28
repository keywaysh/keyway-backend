import Fastify, { FastifyInstance } from 'fastify';
import formbody from '@fastify/formbody';

/**
 * Create a test Fastify instance
 * This creates a minimal app for testing routes
 */
export async function createTestApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
  });

  // Register form body parser (needed for POST routes)
  await app.register(formbody);

  return app;
}

/**
 * Close the test app
 */
export async function closeTestApp(app: FastifyInstance): Promise<void> {
  await app.close();
}
