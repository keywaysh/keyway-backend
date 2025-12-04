import jwt from 'jsonwebtoken';
import { config } from '../config';
import crypto from 'crypto';

/**
 * Payload for Keyway JWT tokens
 */
export interface KeywayTokenPayload {
  userId: string;
  githubId: number;
  username: string;
}

/**
 * Generate a Keyway JWT access token
 */
export function generateKeywayToken(payload: KeywayTokenPayload): string {
  const secretPreview = config.jwt.secret.substring(0, 8) + '...';
  console.log(`[JWT] Generating token for user ${payload.username} (userId: ${payload.userId}) with secret prefix: ${secretPreview}`);

  const token = jwt.sign(payload, config.jwt.secret, {
    algorithm: 'HS256',
    expiresIn: config.jwt.accessTokenExpiresIn,
    issuer: 'keyway-api',
    subject: payload.userId,
  });

  const tokenPreview = token.substring(0, 20) + '...' + token.substring(token.length - 10);
  console.log(`[JWT] Generated token: ${tokenPreview}`);

  return token;
}

/**
 * Generate a secure refresh token (opaque token, not JWT)
 * Returns a cryptographically random string
 */
export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString('base64url');
}

/**
 * Calculate refresh token expiration date
 */
export function getRefreshTokenExpiresAt(): Date {
  const expiresInDays = parseInt(config.jwt.refreshTokenExpiresIn);
  return new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
}

/**
 * Verify and decode a Keyway JWT token
 * @throws Error if token is invalid or expired
 */
export function verifyKeywayToken(token: string): KeywayTokenPayload {
  const tokenPreview = token.substring(0, 20) + '...' + token.substring(token.length - 10);
  const secretPreview = config.jwt.secret.substring(0, 8) + '...';
  console.log(`[JWT] Verifying token: ${tokenPreview} with secret prefix: ${secretPreview}`);

  try {
    const decoded = jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'],
      issuer: 'keyway-api',
    }) as jwt.JwtPayload;

    console.log(`[JWT] Token verified successfully for user: ${decoded.username}`);

    return {
      userId: decoded.sub as string,
      githubId: decoded.githubId as number,
      username: decoded.username as string,
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    console.log(`[JWT] Token verification FAILED: ${errorMsg}`);

    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    }
    throw error;
  }
}

/**
 * Get token expiration date
 */
export function getTokenExpiresAt(token: string): Date {
  const decoded = jwt.decode(token) as jwt.JwtPayload;
  if (!decoded || !decoded.exp) {
    throw new Error('Invalid token: no expiration');
  }
  return new Date(decoded.exp * 1000);
}
