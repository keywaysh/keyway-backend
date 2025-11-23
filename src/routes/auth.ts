import { FastifyInstance } from 'fastify';
import {
  GitHubCallbackRequestSchema,
  DeviceFlowPollRequestSchema,
} from '../types';
import { db, users, deviceCodes } from '../db';
import { eq } from 'drizzle-orm';
import { exchangeCodeForToken, getUserFromToken } from '../utils/github';
import { trackEvent, AnalyticsEvents } from '../utils/analytics';
import { generateDeviceCode, generateUserCode, DEVICE_FLOW_CONFIG } from '../utils/deviceCodes';
import { generateKeywayToken, getTokenExpiresAt } from '../utils/jwt';
import { config } from '../config';
import { NotFoundError } from '../errors';

export async function authRoutes(fastify: FastifyInstance) {
  /**
   * POST /auth/device/start
   * Start the device authorization flow
   */
  fastify.post('/device/start', async (request, reply) => {
    const deviceCode = generateDeviceCode();
    const userCode = generateUserCode();
    const expiresAt = new Date(Date.now() + DEVICE_FLOW_CONFIG.EXPIRES_IN * 1000);

    // Store device code in database
    await db.insert(deviceCodes).values({
      deviceCode,
      userCode,
      status: 'pending',
      expiresAt,
    });

    // Detect protocol from request (Railway uses X-Forwarded-Proto)
    const protocol = request.headers['x-forwarded-proto'] || (config.server.isDevelopment ? 'http' : 'https');
    const verificationUri = `${protocol}://${request.hostname}/auth/device/verify`;
    const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;

    fastify.log.info({
      deviceCode: deviceCode.slice(0, 8) + '...',
      userCode,
    }, 'Device flow started');

    return {
      deviceCode,
      userCode,
      verificationUri,
      verificationUriComplete,
      expiresIn: DEVICE_FLOW_CONFIG.EXPIRES_IN,
      interval: DEVICE_FLOW_CONFIG.POLL_INTERVAL,
    };
  });

  /**
   * POST /auth/device/poll
   * Poll for device authorization status
   */
  fastify.post('/device/poll', async (request, reply) => {
    const body = DeviceFlowPollRequestSchema.parse(request.body);

    // Find device code
    const deviceCodeRecord = await db.query.deviceCodes.findFirst({
      where: eq(deviceCodes.deviceCode, body.deviceCode),
      with: {
        user: true,
      },
    });

    if (!deviceCodeRecord) {
      throw new NotFoundError('Invalid device code');
    }

    // Check if expired
    if (new Date() > deviceCodeRecord.expiresAt) {
      // Update status to expired
      await db
        .update(deviceCodes)
        .set({ status: 'expired' })
        .where(eq(deviceCodes.deviceCode, body.deviceCode));

      return reply.status(400).send({
        status: 'expired',
        message: 'The device code has expired. Please restart the authentication flow.',
      });
    }

    // Check status
    if (deviceCodeRecord.status === 'pending') {
      return { status: 'pending' };
    }

    if (deviceCodeRecord.status === 'denied') {
      return reply.status(403).send({
        status: 'denied',
        message: 'User denied the authorization request.',
      });
    }

    if (deviceCodeRecord.status === 'expired') {
      return reply.status(400).send({
        status: 'expired',
        message: 'The device code has expired.',
      });
    }

    if (deviceCodeRecord.status === 'approved' && deviceCodeRecord.user) {
      // Generate Keyway token
      const keywayToken = generateKeywayToken({
        userId: deviceCodeRecord.user.id,
        githubId: deviceCodeRecord.user.githubId,
        username: deviceCodeRecord.user.username,
      });

      const expiresAt = getTokenExpiresAt(keywayToken);

      fastify.log.info({
        userId: deviceCodeRecord.user.id,
        username: deviceCodeRecord.user.username,
      }, 'Device flow approved');

      return {
        status: 'approved',
        keywayToken,
        githubLogin: deviceCodeRecord.user.username,
        expiresAt: expiresAt.toISOString(),
      };
    }

    // Fallback to pending (shouldn't reach here)
    return { status: 'pending' };
  });

  /**
   * GET /auth/device/verify
   * Device verification page (simple HTML form)
   */
  fastify.get('/device/verify', async (request, reply) => {
    const query = request.query as { user_code?: string };
    const userCode = query.user_code || '';

    // Auto-submit if code is provided
    const autoSubmit = userCode.length === 9; // Format: XXXX-XXXX

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Device Verification</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #1a202c; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    .info { background: #bee3f8; color: #2c5282; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
    form { display: flex; flex-direction: column; gap: 16px; }
    input {
      padding: 12px 16px;
      font-size: 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      text-transform: uppercase;
      letter-spacing: 2px;
      text-align: center;
      font-weight: 600;
    }
    input:focus { outline: none; border-color: #667eea; }
    button {
      background: #667eea;
      color: white;
      padding: 12px 24px;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
      position: relative;
    }
    button:hover { background: #5568d3; }
    button:disabled { background: #a0aec0; cursor: not-allowed; }
    button.loading::after {
      content: '';
      position: absolute;
      right: 16px;
      top: 50%;
      transform: translateY(-50%);
      width: 16px;
      height: 16px;
      border: 2px solid white;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
    }
    @keyframes spin {
      to { transform: translateY(-50%) rotate(360deg); }
    }
    .logo { font-size: 48px; text-align: center; margin-bottom: 20px; }
    .countdown { font-size: 12px; color: #718096; margin-top: 8px; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🔐</div>
    <h1>Verify Your Device</h1>
    ${autoSubmit
      ? '<p>Code detected! Redirecting to GitHub authentication...</p><div class="info">✅ Code <strong>' + userCode + '</strong> confirmed</div>'
      : '<p>Enter the code displayed on your device to continue with GitHub authentication.</p>'
    }

    <form id="verifyForm" action="/auth/device/verify" method="POST">
      <input
        type="text"
        name="user_code"
        id="userCodeInput"
        placeholder="XXXX-XXXX"
        value="${userCode}"
        pattern="[A-Z0-9]{4}-[A-Z0-9]{4}"
        maxlength="9"
        required
        ${autoSubmit ? 'readonly' : 'autofocus'}
      />
      <button type="submit" id="submitBtn"${autoSubmit ? ' class="loading" disabled' : ''}>
        ${autoSubmit ? 'Redirecting...' : 'Continue with GitHub'}
      </button>
    </form>
    ${autoSubmit ? '<div class="countdown" id="countdown">Redirecting in <span id="timer">2</span> seconds...</div>' : ''}
  </div>

  ${autoSubmit ? `
  <script>
    // Auto-submit after 2 seconds if code is pre-filled
    let timeLeft = 2;
    const timerEl = document.getElementById('timer');
    const countdownEl = document.getElementById('countdown');

    const countdown = setInterval(() => {
      timeLeft--;
      if (timerEl) timerEl.textContent = timeLeft;

      if (timeLeft <= 0) {
        clearInterval(countdown);
        document.getElementById('verifyForm').submit();
      }
    }, 1000);

    // Allow manual submission
    document.getElementById('verifyForm').addEventListener('submit', () => {
      clearInterval(countdown);
      if (countdownEl) countdownEl.textContent = 'Redirecting...';
    });
  </script>
  ` : ''}
</body>
</html>
    `;

    reply.type('text/html').send(html);
  });

  /**
   * POST /auth/device/verify
   * Verify user code and redirect to GitHub OAuth
   */
  fastify.post('/device/verify', async (request, reply) => {
    const body = request.body as { user_code: string };
    const userCode = body.user_code.trim().toUpperCase();

    // Find device code by user code
    const deviceCodeRecord = await db.query.deviceCodes.findFirst({
      where: eq(deviceCodes.userCode, userCode),
    });

    if (!deviceCodeRecord) {
      return reply.type('text/html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Invalid Code</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #c53030; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    a { color: #667eea; text-decoration: none; font-weight: 600; }
    .logo { font-size: 48px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">❌</div>
    <h1>Invalid Code</h1>
    <p>The code you entered is invalid or has expired. Please try again or restart the authentication flow.</p>
    <a href="/auth/device/verify">← Try Again</a>
  </div>
</body>
</html>
      `);
    }

    // Check if expired
    if (new Date() > deviceCodeRecord.expiresAt) {
      return reply.type('text/html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Code Expired</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #c53030; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    .logo { font-size: 48px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">⏰</div>
    <h1>Code Expired</h1>
    <p>This verification code has expired. Please restart the authentication flow from your device.</p>
  </div>
</body>
</html>
      `);
    }

    // Build GitHub OAuth URL with state containing the device code ID
    const state = Buffer.from(JSON.stringify({ deviceCodeId: deviceCodeRecord.id })).toString('base64');
    const protocol = request.headers['x-forwarded-proto'] || (config.server.isDevelopment ? 'http' : 'https');
    const redirectUri = `${protocol}://${request.hostname}/auth/device/callback`;

    const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
    githubAuthUrl.searchParams.set('client_id', config.github.clientId);
    githubAuthUrl.searchParams.set('redirect_uri', redirectUri);
    githubAuthUrl.searchParams.set('scope', 'repo read:user user:email');
    githubAuthUrl.searchParams.set('state', state);

    return reply.redirect(githubAuthUrl.toString());
  });

  /**
   * GET /auth/device/callback
   * GitHub OAuth callback for device flow
   */
  fastify.get('/device/callback', async (request, reply) => {
    const query = request.query as { code?: string; state?: string; error?: string };

    if (query.error) {
      return reply.type('text/html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Authorization Denied</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #c53030; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    .logo { font-size: 48px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🚫</div>
    <h1>Authorization Denied</h1>
    <p>You denied the authorization request. You can close this window.</p>
  </div>
</body>
</html>
      `);
    }

    if (!query.code || !query.state) {
      return reply.status(400).send({ error: 'Missing code or state' });
    }

    try {
      // Decode state to get device code ID
      const stateData = JSON.parse(Buffer.from(query.state, 'base64').toString());
      const deviceCodeId = stateData.deviceCodeId;

      // Exchange code for access token
      const accessToken = await exchangeCodeForToken(query.code);

      // Get user info from GitHub
      const githubUser = await getUserFromToken(accessToken);

      // Check if user exists, create or update
      const existingUser = await db.query.users.findFirst({
        where: eq(users.githubId, githubUser.githubId),
      });

      let user;

      if (existingUser) {
        // Update existing user
        const [updatedUser] = await db
          .update(users)
          .set({
            username: githubUser.username,
            email: githubUser.email,
            avatarUrl: githubUser.avatarUrl,
            accessToken,
            updatedAt: new Date(),
          })
          .where(eq(users.githubId, githubUser.githubId))
          .returning();

        user = updatedUser;
      } else {
        // Create new user
        const [newUser] = await db
          .insert(users)
          .values({
            githubId: githubUser.githubId,
            username: githubUser.username,
            email: githubUser.email,
            avatarUrl: githubUser.avatarUrl,
            accessToken,
          })
          .returning();

        user = newUser;
      }

      // Update device code status to approved
      await db
        .update(deviceCodes)
        .set({
          status: 'approved',
          userId: user.id,
        })
        .where(eq(deviceCodes.id, deviceCodeId));

      // Track successful auth
      trackEvent(user.id, AnalyticsEvents.AUTH_SUCCESS, {
        username: githubUser.username,
        method: 'device_flow',
      });

      fastify.log.info({
        userId: user.id,
        username: user.username,
        deviceCodeId,
      }, 'Device authorization approved');

      // Show success page
      return reply.type('text/html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Success</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #38a169; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    .logo { font-size: 48px; margin-bottom: 20px; }
    .user-info {
      background: #f7fafc;
      padding: 16px;
      border-radius: 8px;
      margin-top: 20px;
    }
    .user-info strong { color: #2d3748; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">✅</div>
    <h1>Success!</h1>
    <p>You have successfully authorized Keyway CLI. You can now close this window and return to your terminal.</p>
    <div class="user-info">
      <strong>Logged in as:</strong> ${user.username}
    </div>
  </div>
</body>
</html>
      `);
    } catch (error) {
      fastify.log.error({ err: error }, 'Device flow callback error');

      return reply.type('text/html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keyway - Error</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    h1 { font-size: 28px; margin-bottom: 12px; color: #c53030; }
    p { color: #4a5568; margin-bottom: 24px; line-height: 1.6; }
    .logo { font-size: 48px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">⚠️</div>
    <h1>Authentication Error</h1>
    <p>An error occurred during authentication. Please try again or restart the authentication flow.</p>
  </div>
</body>
</html>
      `);
    }
  });

  /**
   * POST /auth/github/callback
   * Exchange GitHub OAuth code for access token and create/update user
   */
  fastify.post('/github/callback', async (request, reply) => {
    try {
      const body = GitHubCallbackRequestSchema.parse(request.body);

      // Exchange code for access token
      const accessToken = await exchangeCodeForToken(body.code);

      // Get user info from GitHub
      const githubUser = await getUserFromToken(accessToken);

      // Check if user exists
      const existingUser = await db.query.users.findFirst({
        where: eq(users.githubId, githubUser.githubId),
      });

      let user;

      if (existingUser) {
        // Update existing user
        const [updatedUser] = await db
          .update(users)
          .set({
            username: githubUser.username,
            email: githubUser.email,
            avatarUrl: githubUser.avatarUrl,
            accessToken,
            updatedAt: new Date(),
          })
          .where(eq(users.githubId, githubUser.githubId))
          .returning();

        user = updatedUser;
      } else {
        // Create new user
        const [newUser] = await db
          .insert(users)
          .values({
            githubId: githubUser.githubId,
            username: githubUser.username,
            email: githubUser.email,
            avatarUrl: githubUser.avatarUrl,
            accessToken,
          })
          .returning();

        user = newUser;
      }

      // Track successful auth
      trackEvent(user.id, AnalyticsEvents.AUTH_SUCCESS, {
        username: githubUser.username,
        isNewUser: !existingUser,
      });

      return {
        accessToken,
        user: {
          id: githubUser.githubId,
          username: githubUser.username,
          email: githubUser.email,
          avatarUrl: githubUser.avatarUrl,
        },
      };
    } catch (error) {
      trackEvent('anonymous', AnalyticsEvents.AUTH_FAILURE, {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      if (error instanceof Error) {
        return reply.status(400).send({
          error: 'AuthenticationError',
          message: error.message,
        });
      }

      return reply.status(500).send({
        error: 'InternalServerError',
        message: 'Failed to authenticate with GitHub',
      });
    }
  });
}
