/**
 * Exemple d'implémentation du device flow pour Keyway CLI
 *
 * Usage dans la CLI:
 *   import { loginWithDeviceFlow } from './auth';
 *   const token = await loginWithDeviceFlow();
 */

import open from 'open'; // npm install open

interface DeviceFlowStartResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

interface DeviceFlowPollResponse {
  status: 'pending' | 'approved' | 'expired' | 'denied';
  keywayToken?: string;
  githubLogin?: string;
  expiresAt?: string;
  message?: string;
}

const API_URL = process.env.KEYWAY_API_URL || 'https://api.keyway.sh';

/**
 * Login with device flow OAuth
 *
 * Cette fonction simule ce que fera `keyway login`
 */
export async function loginWithDeviceFlow(): Promise<string> {
  console.log('🔐 Authenticating with Keyway...\n');

  // Step 1: Start device flow
  console.log('📝 Starting device flow...');
  const startResponse = await fetch(`${API_URL}/auth/device/start`, {
    method: 'POST',
  });

  if (!startResponse.ok) {
    throw new Error('Failed to start device flow');
  }

  const data: DeviceFlowStartResponse = await startResponse.json();

  console.log('');
  console.log('════════════════════════════════════════');
  console.log('✅ Device flow started!');
  console.log('════════════════════════════════════════');
  console.log('');
  console.log(`🔑 Code: ${data.userCode}`);
  console.log('');
  console.log('🌐 Opening browser for authentication...');
  console.log('   (If it doesn\'t open, visit this URL:)');
  console.log(`   ${data.verificationUri}`);
  console.log('');

  // Step 2: Open browser automatically with pre-filled code
  try {
    await open(data.verificationUriComplete);
  } catch (error) {
    console.log('⚠️  Could not open browser automatically.');
    console.log('   Please manually visit:');
    console.log(`   ${data.verificationUriComplete}`);
  }

  console.log('ℹ️  The page will auto-submit after 2 seconds');
  console.log('   Just click "Authorize" on GitHub!');
  console.log('');
  console.log('════════════════════════════════════════');
  console.log('⏳ Waiting for authentication...');
  console.log('════════════════════════════════════════');
  console.log('');

  // Step 3: Poll for approval
  const maxAttempts = Math.ceil(data.expiresIn / data.interval);
  let attempt = 0;
  let dots = '';

  while (attempt < maxAttempts) {
    attempt++;
    dots += '.';

    // Show progress
    process.stdout.write(`\r   Polling${dots} (${attempt}/${maxAttempts})`);

    const pollResponse = await fetch(`${API_URL}/auth/device/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceCode: data.deviceCode }),
    });

    const pollData: DeviceFlowPollResponse = await pollResponse.json();

    if (pollData.status === 'approved') {
      console.log('\n');
      console.log('════════════════════════════════════════');
      console.log('✅ Authentication successful!');
      console.log('════════════════════════════════════════');
      console.log('');
      console.log(`👤 Logged in as: ${pollData.githubLogin}`);
      console.log(`⏰ Token expires: ${pollData.expiresAt}`);
      console.log('');

      // Return the token
      return pollData.keywayToken!;
    } else if (pollData.status === 'expired') {
      throw new Error('\n❌ Device code expired. Please run `keyway login` again.');
    } else if (pollData.status === 'denied') {
      throw new Error('\n❌ Authentication denied. Please try again.');
    }

    // Reset dots every 10 attempts for cleaner output
    if (attempt % 10 === 0) {
      dots = '';
    }

    // Wait before next poll
    await sleep(data.interval * 1000);
  }

  throw new Error('\n❌ Authentication timeout. Please try again.');
}

/**
 * Example usage in CLI commands
 */
export async function exampleUsage() {
  try {
    // Login and get token
    const token = await loginWithDeviceFlow();

    // Save token to config file (e.g., ~/.keyway/config.json)
    // await saveToken(token);

    console.log('💾 Token saved successfully!');
    console.log('');
    console.log('🎉 You can now use Keyway CLI:');
    console.log('   keyway init owner/repo');
    console.log('   keyway push owner/repo production');
    console.log('   keyway pull owner/repo production');
    console.log('');

    return token;
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
}

/**
 * Use the token in API requests
 */
export async function exampleApiRequest(token: string) {
  const response = await fetch(`${API_URL}/vaults/owner/repo/production/pull`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('API request failed');
  }

  return await response.json();
}

// Helper
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// If running this file directly
if (require.main === module) {
  exampleUsage();
}
