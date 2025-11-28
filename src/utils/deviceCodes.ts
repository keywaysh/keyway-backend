import crypto from 'crypto';

/**
 * Generate a secure random device code (opaque, for polling)
 * Format: 64 character hex string (32 bytes = 256 bits of entropy)
 *
 * Security: Uses crypto.randomBytes(32) for cryptographically secure randomness.
 * This provides 256 bits of entropy, making brute-force attacks infeasible.
 * (HIGH-12: Device code entropy requirement met)
 */
export function generateDeviceCode(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a user-friendly code for display
 * Format: 8 character alphanumeric (uppercase, no confusing characters)
 *
 * Security: Generates 8 characters from a 29-character alphabet (excluding 0, O, 1, I, L).
 * This provides ~500 billion combinations (29^8), sufficient to prevent brute-force
 * attacks during the 15-minute expiration window with rate limiting.
 * (HIGH-12: User code entropy requirement met - 8 characters minimum)
 */
export function generateUserCode(): string {
  // Use only uppercase letters and numbers, excluding confusing characters (0, O, 1, I, L)
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const length = 8; // Minimum 8 characters for security

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
