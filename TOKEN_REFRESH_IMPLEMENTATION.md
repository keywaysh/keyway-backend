# Token Refresh Implementation - HIGH-3

## Overview
This document outlines the complete implementation of token refresh functionality for the Keyway backend API. The implementation adds a secure refresh token mechanism to prevent users from having to re-authenticate when their access tokens expire.

## Architecture Decision

**Approach**: Stateful refresh tokens stored in database
- Refresh tokens are cryptographically random opaque strings (not JWTs)
- Stored in database with expiration tracking
- Access tokens remain as JWTs (short-lived: 7 days)
- Refresh tokens are long-lived (90 days)
- Allows for token revocation and tracking

## Implementation Status

✅ **COMPLETED:**
1. Database schema updated with `refresh_tokens` table
2. JWT configuration updated to support separate expiration times
3. JWT utility functions for refresh token generation
4. Migration file created (`drizzle/0012_add_refresh_tokens.sql`)

⚠️ **NEEDS COMPLETION:**
The auth routes file (`src/api/v1/routes/auth.routes.ts`) needs to be updated but keeps getting reverted by linter. Manual implementation required.

## Files Modified

### 1. Database Schema (`src/db/schema.ts`)
**Status**: ✅ Complete

Added new `refresh_tokens` table with the following structure:
```typescript
export const refreshTokens = pgTable('refresh_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token: text('token').notNull().unique(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  lastUsedAt: timestamp('last_used_at'),
  // Device/client information for tracking
  deviceId: text('device_id'),
  userAgent: text('user_agent'),
  ipAddress: text('ip_address'),
});
```

Added relations and type exports:
- `refreshTokensRelations` for Drizzle ORM
- `RefreshToken` and `NewRefreshToken` type exports
- Added `refreshTokens: many(refreshTokens)` to `usersRelations`

### 2. Configuration (`src/config/index.ts`)
**Status**: ✅ Complete

Updated JWT configuration:
```typescript
jwt: {
  secret: env.JWT_SECRET,
  accessTokenExpiresIn: '7d',  // 7 days for access tokens
  refreshTokenExpiresIn: '90d', // 90 days for refresh tokens
},
```

### 3. JWT Utilities (`src/utils/jwt.ts`)
**Status**: ✅ Complete

Added three new functions:
```typescript
// Generate secure refresh token (64-byte random string)
export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString('base64url');
}

// Calculate refresh token expiration date
export function getRefreshTokenExpiresAt(): Date {
  const expiresInDays = parseInt(config.jwt.refreshTokenExpiresIn);
  return new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
}
```

Updated `generateKeywayToken()` to use `config.jwt.accessTokenExpiresIn` instead of the old generic `expiresIn`.

### 4. Database Migration (`drizzle/0012_add_refresh_tokens.sql`)
**Status**: ✅ Complete

Migration file created with:
- `refresh_tokens` table creation
- Foreign key constraint to `users` table
- Indexes on `token`, `user_id`, and `expires_at` for performance
- CASCADE delete when user is deleted

To apply migration:
```bash
pnpm run db:migrate
```

### 5. Auth Routes (`src/api/v1/routes/auth.routes.ts`)
**Status**: ⚠️ **REQUIRES MANUAL IMPLEMENTATION**

The following changes need to be made to this file:

#### a. Update Imports
Add to imports at top of file:
```typescript
import { db, users, deviceCodes, refreshTokens } from '../../../db';
import { eq, and, gt } from 'drizzle-orm';
import { generateKeywayToken, generateRefreshToken, getRefreshTokenExpiresAt, getTokenExpiresAt } from '../../../utils/jwt';
import { encryptAccessToken } from '../../../utils/tokenEncryption';
```

#### b. Add Refresh Token Schema
After `DeviceFlowPollSchema`:
```typescript
const RefreshTokenSchema = z.object({
  refreshToken: z.string().min(1),
});
```

#### c. Fix upsertUser Function
The function currently references old `accessToken` field. It should use encrypted fields:
```typescript
async function upsertUser(githubUser: { githubId: number; username: string; email: string | null; avatarUrl: string | null }, accessToken: string) {
  // Encrypt the GitHub access token before storing
  const encryptedToken = encryptAccessToken(accessToken);

  const existingUser = await db.query.users.findFirst({
    where: eq(users.githubId, githubUser.githubId),
  });

  if (existingUser) {
    const [updatedUser] = await db
      .update(users)
      .set({
        username: githubUser.username,
        email: githubUser.email,
        avatarUrl: githubUser.avatarUrl,
        encryptedAccessToken: encryptedToken.encryptedAccessToken,
        accessTokenIv: encryptedToken.accessTokenIv,
        accessTokenAuthTag: encryptedToken.accessTokenAuthTag,
        updatedAt: new Date(),
      })
      .where(eq(users.githubId, githubUser.githubId))
      .returning();
    return { user: updatedUser, isNewUser: false };
  }

  const [newUser] = await db
    .insert(users)
    .values({
      githubId: githubUser.githubId,
      username: githubUser.username,
      email: githubUser.email,
      avatarUrl: githubUser.avatarUrl,
      encryptedAccessToken: encryptedToken.encryptedAccessToken,
      accessTokenIv: encryptedToken.accessTokenIv,
      accessTokenAuthTag: encryptedToken.accessTokenAuthTag,
    })
    .returning();
  return { user: newUser, isNewUser: true };
}
```

#### d. Add Helper Function for Storing Refresh Tokens
After `upsertUser` function:
```typescript
// Helper to store a new refresh token
async function storeRefreshToken(userId: string, request: any) {
  const token = generateRefreshToken();
  const expiresAt = getRefreshTokenExpiresAt();

  await db.insert(refreshTokens).values({
    userId,
    token,
    expiresAt,
    userAgent: request.headers?.['user-agent'],
    ipAddress: request.ip,
  });

  return { token, expiresAt };
}
```

#### e. Update Device Flow Poll Endpoint
In the `POST /device/poll` handler, when status is 'approved', add refresh token generation:
```typescript
if (deviceCodeRecord.status === 'approved' && deviceCodeRecord.user) {
  const keywayToken = generateKeywayToken({
    userId: deviceCodeRecord.user.id,
    githubId: deviceCodeRecord.user.githubId,
    username: deviceCodeRecord.user.username,
  });

  const expiresAt = getTokenExpiresAt(keywayToken);

  // Generate and store refresh token
  const refreshTokenData = await storeRefreshToken(deviceCodeRecord.user.id, request);

  return {
    status: 'approved',
    keywayToken,
    refreshToken: refreshTokenData.token,
    githubLogin: deviceCodeRecord.user.username,
    expiresAt: expiresAt.toISOString(),
    refreshTokenExpiresAt: refreshTokenData.expiresAt.toISOString(),
  };
}
```

#### f. Add POST /refresh Endpoint
Add this new route before the closing brace of `authRoutes()` function:
```typescript
/**
 * POST /refresh
 * Refresh access token using refresh token
 */
fastify.post('/refresh', async (request, reply) => {
  const body = RefreshTokenSchema.parse(request.body);

  // Find the refresh token in database
  const refreshTokenRecord = await db.query.refreshTokens.findFirst({
    where: eq(refreshTokens.token, body.refreshToken),
    with: { user: true },
  });

  if (!refreshTokenRecord) {
    return reply.status(401).send({
      error: 'InvalidRefreshToken',
      message: 'Invalid refresh token',
    });
  }

  // Check if token is expired
  if (new Date() > refreshTokenRecord.expiresAt) {
    // Delete expired token
    await db.delete(refreshTokens).where(eq(refreshTokens.token, body.refreshToken));

    return reply.status(401).send({
      error: 'ExpiredRefreshToken',
      message: 'Refresh token has expired. Please log in again.',
    });
  }

  // Generate new access token
  const newAccessToken = generateKeywayToken({
    userId: refreshTokenRecord.user.id,
    githubId: refreshTokenRecord.user.githubId,
    username: refreshTokenRecord.user.username,
  });

  const accessTokenExpiresAt = getTokenExpiresAt(newAccessToken);

  // Update last used timestamp
  await db
    .update(refreshTokens)
    .set({ lastUsedAt: new Date() })
    .where(eq(refreshTokens.token, body.refreshToken));

  // Track analytics
  trackEvent(refreshTokenRecord.user.id, AnalyticsEvents.AUTH_SUCCESS, {
    username: refreshTokenRecord.user.username,
    method: 'refresh_token',
    isNewUser: false,
  });

  return {
    accessToken: newAccessToken,
    expiresAt: accessTokenExpiresAt.toISOString(),
    refreshToken: body.refreshToken, // Return the same refresh token
  };
});
```

#### g. Update Auth Routes Documentation Comment
Update the comment at the start of `authRoutes()` to include:
```typescript
/**
 * Auth routes
 * GET  /v1/auth/github/start     - Start web OAuth flow
 * GET  /v1/auth/callback         - OAuth callback
 * POST /v1/auth/device/start     - Start device flow
 * POST /v1/auth/device/poll      - Poll device flow
 * GET  /v1/auth/device/verify    - Device verification page
 * POST /v1/auth/device/verify    - Submit device verification
 * POST /v1/auth/token/validate   - Validate token
 * POST /v1/auth/refresh          - Refresh access token
 */
```

## Testing the Implementation

### 1. Apply Database Migration
```bash
cd keyway-backend
pnpm run db:migrate
```

### 2. Type Check
```bash
pnpm run type-check
```

### 3. Test the Refresh Endpoint

#### Step 1: Authenticate and Get Tokens
```bash
# Use CLI or web flow to authenticate
# This will return both keywayToken and refreshToken
```

#### Step 2: Use Refresh Token
```bash
curl -X POST http://localhost:3000/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN_HERE"}'
```

Expected response:
```json
{
  "accessToken": "new.jwt.token",
  "expiresAt": "2025-12-05T10:00:00.000Z",
  "refreshToken": "same-refresh-token"
}
```

### 4. Test Token Expiration
```bash
# Wait for access token to expire (7 days in production, can be shortened for testing)
# Try to use expired access token - should get 401
# Use refresh token to get new access token - should work
```

## Security Considerations

1. **Refresh Token Storage**:
   - Refresh tokens are stored in database, not in JWT
   - Allows for revocation if needed
   - Can track usage via `lastUsedAt`

2. **Token Rotation**:
   - Current implementation reuses the same refresh token
   - Could be enhanced to rotate refresh tokens on each use for added security

3. **Expiration**:
   - Access tokens: 7 days (can be adjusted)
   - Refresh tokens: 90 days (can be adjusted)
   - Expired refresh tokens are automatically deleted

4. **Tracking**:
   - User agent and IP address stored with refresh tokens
   - Can be used for security alerts
   - `lastUsedAt` tracks token usage

## Future Enhancements

1. **Token Rotation**: Implement refresh token rotation where each refresh generates a new refresh token
2. **Token Revocation Endpoint**: Add `POST /auth/revoke` to manually revoke refresh tokens
3. **Token Cleanup Job**: Background job to delete expired refresh tokens
4. **Rate Limiting**: Add rate limiting to refresh endpoint to prevent abuse
5. **Device Management**: Allow users to view and revoke tokens from specific devices

## CLI Integration

The CLI (`keyway-cli`) will need to be updated to:
1. Store refresh tokens alongside access tokens
2. Automatically refresh access tokens when they expire
3. Handle refresh token expiration gracefully

Update `keyway-cli/src/utils/auth.ts` to:
```typescript
// Store both tokens
config.set('accessToken', tokens.keywayToken);
config.set('refreshToken', tokens.refreshToken);
config.set('tokenExpiresAt', tokens.expiresAt);
config.set('refreshTokenExpiresAt', tokens.refreshTokenExpiresAt);

// Check and refresh if needed
if (isTokenExpired(config.get('tokenExpiresAt'))) {
  const refreshToken = config.get('refreshToken');
  const response = await api.post('/auth/refresh', { refreshToken });
  config.set('accessToken', response.accessToken);
  config.set('tokenExpiresAt', response.expiresAt);
}
```

## Rollback Plan

If issues arise, rollback is straightforward:
1. Remove the `POST /refresh` endpoint from auth routes
2. Remove refresh token generation from device flow
3. Run migration rollback (create a down migration):
```sql
DROP TABLE IF EXISTS "refresh_tokens";
```

## Questions & Answers

**Q: Why not use JWT for refresh tokens?**
A: Opaque tokens in database allow for easy revocation and tracking. JWTs cannot be revoked without maintaining a blacklist.

**Q: Why 90 days for refresh tokens?**
A: Balances convenience (less frequent re-authentication) with security. Can be adjusted based on requirements.

**Q: Should we rotate refresh tokens?**
A: Not in initial implementation to keep it simple. Can be added as enhancement if needed.

**Q: What happens to old refresh tokens when user re-authenticates?**
A: Currently, old tokens remain valid until expiration. Could add logic to revoke previous tokens on new login.
