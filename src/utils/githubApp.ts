/**
 * GitHub App Utilities
 * Handles GitHub App authentication, webhook verification, and installation tokens
 */

import { App, Octokit } from 'octokit';
import { createHmac, timingSafeEqual } from 'crypto';
import { config } from '../config';

// Singleton App instance (lazy initialized)
let appInstance: App | null = null;

// Cache for installation tokens (they expire after 1 hour)
const tokenCache = new Map<number, { token: string; expiresAt: Date }>();

/**
 * Get the GitHub App instance
 * Returns null if GitHub App is not configured
 */
export function getGitHubApp(): App | null {
  if (!config.githubApp.enabled || !config.githubApp.appId || !config.githubApp.privateKey) {
    return null;
  }

  if (!appInstance) {
    appInstance = new App({
      appId: config.githubApp.appId,
      privateKey: config.githubApp.privateKey,
    });
  }

  return appInstance;
}

/**
 * Verify GitHub webhook signature
 * Uses HMAC SHA-256 with timing-safe comparison
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string | undefined
): boolean {
  if (!config.githubApp.webhookSecret || !signature) {
    return false;
  }

  const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');

  // GitHub sends signature as "sha256=<hash>"
  const expectedSignature = `sha256=${createHmac('sha256', config.githubApp.webhookSecret)
    .update(payloadString)
    .digest('hex')}`;

  // Use timing-safe comparison to prevent timing attacks
  try {
    return timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    // Buffers have different lengths - signature is invalid
    return false;
  }
}

/**
 * Get an installation token for a specific installation
 * Tokens are cached for 50 minutes (they expire after 1 hour)
 */
export async function getInstallationToken(installationId: number): Promise<string> {
  const app = getGitHubApp();
  if (!app) {
    throw new Error('GitHub App is not configured');
  }

  // Check cache first
  const cached = tokenCache.get(installationId);
  if (cached && cached.expiresAt > new Date()) {
    return cached.token;
  }

  // Get fresh token
  const octokit = await app.getInstallationOctokit(installationId);
  const auth = await octokit.auth({ type: 'installation' }) as { token: string };

  // Cache for 50 minutes (tokens expire after 1 hour)
  const expiresAt = new Date(Date.now() + 50 * 60 * 1000);
  tokenCache.set(installationId, { token: auth.token, expiresAt });

  return auth.token;
}

/**
 * Get an Octokit instance authenticated as the installation
 */
export async function getInstallationOctokit(installationId: number): Promise<Octokit> {
  const token = await getInstallationToken(installationId);
  return new Octokit({ auth: token });
}

/**
 * Check if a user is a collaborator on a repository
 * Uses the installation token to make the API call
 */
export async function checkCollaborator(
  installationId: number,
  repoFullName: string,
  username: string
): Promise<{ hasAccess: boolean; permission: string }> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    const { data } = await octokit.rest.repos.getCollaboratorPermissionLevel({
      owner,
      repo,
      username,
    });

    // GitHub returns 'none', 'read', 'triage', 'write', 'maintain', 'admin'
    const hasAccess = ['write', 'maintain', 'admin'].includes(data.permission);

    return {
      hasAccess,
      permission: data.permission,
    };
  } catch (error) {
    // If we get a 404, the user is not a collaborator
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return { hasAccess: false, permission: 'none' };
    }
    throw error;
  }
}

/**
 * List repositories accessible by an installation
 */
export async function listInstallationRepositories(
  installationId: number
): Promise<Array<{ id: number; fullName: string; private: boolean }>> {
  const octokit = await getInstallationOctokit(installationId);

  const repos: Array<{ id: number; fullName: string; private: boolean }> = [];

  // Paginate through all repositories
  for await (const response of octokit.paginate.iterator(
    octokit.rest.apps.listReposAccessibleToInstallation,
    { per_page: 100 }
  )) {
    for (const repo of response.data) {
      repos.push({
        id: repo.id,
        fullName: repo.full_name,
        private: repo.private,
      });
    }
  }

  return repos;
}

/**
 * Get repository info using installation token
 */
export async function getRepository(
  installationId: number,
  repoFullName: string
): Promise<{ id: number; fullName: string; private: boolean; defaultBranch: string } | null> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    const { data } = await octokit.rest.repos.get({ owner, repo });
    return {
      id: data.id,
      fullName: data.full_name,
      private: data.private,
      defaultBranch: data.default_branch,
    };
  } catch (error) {
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return null;
    }
    throw error;
  }
}

/**
 * Clear token cache (useful for testing or when installation is suspended)
 */
export function clearTokenCache(installationId?: number): void {
  if (installationId) {
    tokenCache.delete(installationId);
  } else {
    tokenCache.clear();
  }
}

/**
 * Check if GitHub App is configured and enabled
 */
export function isGitHubAppEnabled(): boolean {
  return config.githubApp.enabled;
}

/**
 * Get the GitHub App installation URL
 * Note: GitHub doesn't support pre-selecting a specific repository via URL params
 * Users will need to select the repository during installation
 */
export function getInstallationUrl(_repoFullName?: string): string {
  return 'https://github.com/apps/keyway-secrets/installations/new';
}

// ==================== GitHub Actions Variables & Secrets ====================

export interface GitHubActionsVariable {
  name: string;
  value: string;
  created_at?: string;
  updated_at?: string;
}

export interface GitHubActionsSecret {
  name: string;
  created_at?: string;
  updated_at?: string;
}

/**
 * List all repository variables for GitHub Actions
 */
export async function listRepoVariables(
  installationId: number,
  repoFullName: string
): Promise<GitHubActionsVariable[]> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    const { data } = await octokit.rest.actions.listRepoVariables({
      owner,
      repo,
      per_page: 100,
    });
    return data.variables;
  } catch (error) {
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return [];
    }
    throw error;
  }
}

/**
 * Create or update a repository variable for GitHub Actions
 */
export async function setRepoVariable(
  installationId: number,
  repoFullName: string,
  name: string,
  value: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    // Try to update first
    await octokit.rest.actions.updateRepoVariable({
      owner,
      repo,
      name,
      value,
    });
  } catch (error) {
    // If variable doesn't exist (404), create it
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      await octokit.rest.actions.createRepoVariable({
        owner,
        repo,
        name,
        value,
      });
    } else {
      throw error;
    }
  }
}

/**
 * Delete a repository variable for GitHub Actions
 */
export async function deleteRepoVariable(
  installationId: number,
  repoFullName: string,
  name: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    await octokit.rest.actions.deleteRepoVariable({
      owner,
      repo,
      name,
    });
  } catch (error) {
    // Ignore 404 - variable already deleted
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return;
    }
    throw error;
  }
}

/**
 * List all repository secrets for GitHub Actions (names only, values are not returned)
 */
export async function listRepoSecrets(
  installationId: number,
  repoFullName: string
): Promise<GitHubActionsSecret[]> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    const { data } = await octokit.rest.actions.listRepoSecrets({
      owner,
      repo,
      per_page: 100,
    });
    return data.secrets;
  } catch (error) {
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return [];
    }
    throw error;
  }
}

/**
 * Get the public key for encrypting secrets
 */
export async function getRepoPublicKey(
  installationId: number,
  repoFullName: string
): Promise<{ key_id: string; key: string }> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  const { data } = await octokit.rest.actions.getRepoPublicKey({
    owner,
    repo,
  });

  return { key_id: data.key_id, key: data.key };
}

/**
 * Create or update a repository secret for GitHub Actions
 * Note: Secrets must be encrypted using the repository's public key
 */
export async function setRepoSecret(
  installationId: number,
  repoFullName: string,
  name: string,
  encryptedValue: string,
  keyId: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  await octokit.rest.actions.createOrUpdateRepoSecret({
    owner,
    repo,
    secret_name: name,
    encrypted_value: encryptedValue,
    key_id: keyId,
  });
}

/**
 * Delete a repository secret for GitHub Actions
 */
export async function deleteRepoSecret(
  installationId: number,
  repoFullName: string,
  name: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  try {
    await octokit.rest.actions.deleteRepoSecret({
      owner,
      repo,
      secret_name: name,
    });
  } catch (error) {
    // Ignore 404 - secret already deleted
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return;
    }
    throw error;
  }
}

// ==================== Environment Variables & Secrets ====================

/**
 * List environment variables
 */
export async function listEnvironmentVariables(
  installationId: number,
  repoFullName: string,
  environmentName: string
): Promise<GitHubActionsVariable[]> {
  const octokit = await getInstallationOctokit(installationId);
  const [owner, repo] = repoFullName.split('/');

  // First get the repository ID
  const repoData = await getRepository(installationId, repoFullName);
  if (!repoData) {
    throw new Error(`Repository ${repoFullName} not found`);
  }

  try {
    const { data } = await octokit.rest.actions.listEnvironmentVariables({
      repository_id: repoData.id,
      environment_name: environmentName,
      per_page: 100,
    });
    return data.variables;
  } catch (error) {
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      return [];
    }
    throw error;
  }
}

/**
 * Create or update an environment variable
 */
export async function setEnvironmentVariable(
  installationId: number,
  repoFullName: string,
  environmentName: string,
  name: string,
  value: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);

  const repoData = await getRepository(installationId, repoFullName);
  if (!repoData) {
    throw new Error(`Repository ${repoFullName} not found`);
  }

  try {
    // Try to update first
    await octokit.rest.actions.updateEnvironmentVariable({
      repository_id: repoData.id,
      environment_name: environmentName,
      name,
      value,
    });
  } catch (error) {
    // If variable doesn't exist (404), create it
    if (error instanceof Error && 'status' in error && (error as any).status === 404) {
      await octokit.rest.actions.createEnvironmentVariable({
        repository_id: repoData.id,
        environment_name: environmentName,
        name,
        value,
      });
    } else {
      throw error;
    }
  }
}

/**
 * Get the public key for encrypting environment secrets
 */
export async function getEnvironmentPublicKey(
  installationId: number,
  repoFullName: string,
  environmentName: string
): Promise<{ key_id: string; key: string }> {
  const octokit = await getInstallationOctokit(installationId);

  const repoData = await getRepository(installationId, repoFullName);
  if (!repoData) {
    throw new Error(`Repository ${repoFullName} not found`);
  }

  const { data } = await octokit.rest.actions.getEnvironmentPublicKey({
    repository_id: repoData.id,
    environment_name: environmentName,
  });

  return { key_id: data.key_id, key: data.key };
}

/**
 * Create or update an environment secret
 */
export async function setEnvironmentSecret(
  installationId: number,
  repoFullName: string,
  environmentName: string,
  name: string,
  encryptedValue: string,
  keyId: string
): Promise<void> {
  const octokit = await getInstallationOctokit(installationId);

  const repoData = await getRepository(installationId, repoFullName);
  if (!repoData) {
    throw new Error(`Repository ${repoFullName} not found`);
  }

  await octokit.rest.actions.createOrUpdateEnvironmentSecret({
    repository_id: repoData.id,
    environment_name: environmentName,
    secret_name: name,
    encrypted_value: encryptedValue,
    key_id: keyId,
  });
}
