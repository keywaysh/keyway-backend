import crypto from 'crypto';
import { config } from '../config';

/**
 * Sign a state object using HMAC-SHA256
 * Returns format: base64url(payload).base64url(signature)
 */
export function signState(data: Record<string, unknown>): string {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', config.jwt.secret)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

/**
 * Verify and decode a signed state
 * Returns null if signature is invalid
 */
export function verifyState(signed: string): Record<string, unknown> | null {
  try {
    const parts = signed.split('.');
    if (parts.length !== 2) return null;

    const [payload, signature] = parts;
    if (!payload || !signature) return null;

    const expectedSig = crypto
      .createHmac('sha256', config.jwt.secret)
      .update(payload)
      .digest('base64url');

    // Use timing-safe comparison to prevent timing attacks
    if (
      signature.length !== expectedSig.length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))
    ) {
      return null;
    }

    return JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return null;
  }
}
