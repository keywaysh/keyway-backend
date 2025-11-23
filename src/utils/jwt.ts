import jwt from 'jsonwebtoken';
import { config } from '../config';

/**
 * Payload for Keyway JWT tokens
 */
export interface KeywayTokenPayload {
  userId: string;
  githubId: number;
  username: string;
}

/**
 * Generate a Keyway JWT token for device flow authentication
 */
export function generateKeywayToken(payload: KeywayTokenPayload): string {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
    issuer: 'keyway-api',
    subject: payload.userId,
  });
}

/**
 * Verify and decode a Keyway JWT token
 * @throws Error if token is invalid or expired
 */
export function verifyKeywayToken(token: string): KeywayTokenPayload {
  try {
    const decoded = jwt.verify(token, config.jwt.secret, {
      issuer: 'keyway-api',
    }) as jwt.JwtPayload;

    return {
      userId: decoded.sub as string,
      githubId: decoded.githubId as number,
      username: decoded.username as string,
    };
  } catch (error) {
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
