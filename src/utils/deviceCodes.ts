import crypto from 'crypto';

/**
 * Generate a secure random device code (opaque, for polling)
 * Format: 64 character hex string
 */
export function generateDeviceCode(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a user-friendly code for display
 * Format: 8 character alphanumeric (uppercase, no confusing characters)
 */
export function generateUserCode(): string {
  // Use only uppercase letters and numbers, excluding confusing characters (0, O, 1, I, L)
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const length = 8;

  let code = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, chars.length);
    code += chars[randomIndex];
  }

  // Format as XXXX-XXXX for readability
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/**
 * Device flow configuration constants
 */
export const DEVICE_FLOW_CONFIG = {
  EXPIRES_IN: 900, // 15 minutes in seconds
  POLL_INTERVAL: 5, // 5 seconds between polls
} as const;
