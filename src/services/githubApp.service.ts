/**
 * GitHub App Service
 * Handles GitHub App installation management and repository access
 */

import { eq, and } from 'drizzle-orm';
import { db, githubAppInstallations, installationRepositories } from '../db';
import type { GitHubAppInstallation } from '../db/schema';
import {
  checkCollaborator,
  listInstallationRepositories,
  getInstallationUrl,
  isGitHubAppEnabled,
} from '../utils/githubApp';

// Types for webhook payloads
export interface InstallationCreatedPayload {
  action: 'created';
  installation: {
    id: number;
    account: {
      id: number;
      login: string;
      type: 'User' | 'Organization';
    };
  };
  repositories?: Array<{
    id: number;
    full_name: string;
  }>;
}

export interface InstallationDeletedPayload {
  action: 'deleted';
  installation: {
    id: number;
  };
}

export interface InstallationSuspendPayload {
  action: 'suspend' | 'unsuspend';
  installation: {
    id: number;
  };
}

export interface InstallationRepositoriesPayload {
  action: 'added' | 'removed';
  installation: {
    id: number;
  };
  repositories_added?: Array<{
    id: number;
    full_name: string;
  }>;
  repositories_removed?: Array<{
    id: number;
    full_name: string;
  }>;
}

/**
 * Handle installation.created webhook
 */
export async function handleInstallationCreated(
  payload: InstallationCreatedPayload
): Promise<GitHubAppInstallation> {
  const { installation, repositories } = payload;

  // Create the installation record
  const [newInstallation] = await db
    .insert(githubAppInstallations)
    .values({
      installationId: installation.id,
      accountType: installation.account.type,
      accountLogin: installation.account.login,
      accountId: installation.account.id,
      status: 'active',
    })
    .onConflictDoUpdate({
      target: githubAppInstallations.installationId,
      set: {
        accountType: installation.account.type,
        accountLogin: installation.account.login,
        accountId: installation.account.id,
        status: 'active',
        suspendedAt: null,
        updatedAt: new Date(),
      },
    })
    .returning();

  // Add initial repositories if provided
  if (repositories && repositories.length > 0) {
    await db.insert(installationRepositories).values(
      repositories.map((repo) => ({
        installationId: newInstallation.id,
        repoFullName: repo.full_name,
        repoId: repo.id,
      }))
    ).onConflictDoNothing();
  }

  return newInstallation;
}

/**
 * Handle installation.deleted webhook
 */
export async function handleInstallationDeleted(
  payload: InstallationDeletedPayload
): Promise<void> {
  const { installation } = payload;

  // Delete the installation (cascade will handle repositories)
  await db
    .delete(githubAppInstallations)
    .where(eq(githubAppInstallations.installationId, installation.id));
}

/**
 * Handle installation.suspend/unsuspend webhook
 */
export async function handleInstallationSuspend(
  payload: InstallationSuspendPayload
): Promise<void> {
  const { action, installation } = payload;

  await db
    .update(githubAppInstallations)
    .set({
      status: action === 'suspend' ? 'suspended' : 'active',
      suspendedAt: action === 'suspend' ? new Date() : null,
      updatedAt: new Date(),
    })
    .where(eq(githubAppInstallations.installationId, installation.id));
}

/**
 * Handle installation_repositories.added/removed webhook
 */
export async function handleInstallationRepositoriesChanged(
  payload: InstallationRepositoriesPayload
): Promise<void> {
  const { action, installation, repositories_added, repositories_removed } = payload;

  // Get the installation record
  const installationRecord = await db.query.githubAppInstallations.findFirst({
    where: eq(githubAppInstallations.installationId, installation.id),
  });

  if (!installationRecord) {
    console.warn(`[GitHubAppService] Installation ${installation.id} not found`);
    return;
  }

  if (action === 'added' && repositories_added) {
    await db.insert(installationRepositories).values(
      repositories_added.map((repo) => ({
        installationId: installationRecord.id,
        repoFullName: repo.full_name,
        repoId: repo.id,
      }))
    ).onConflictDoNothing();
  }

  if (action === 'removed' && repositories_removed) {
    for (const repo of repositories_removed) {
      await db
        .delete(installationRepositories)
        .where(
          and(
            eq(installationRepositories.installationId, installationRecord.id),
            eq(installationRepositories.repoFullName, repo.full_name)
          )
        );
    }
  }
}

/**
 * Check if a repository has the GitHub App installed
 */
export async function isAppInstalledOnRepo(
  repoFullName: string
): Promise<{ installed: boolean; installationId?: number; installUrl: string }> {
  const installUrl = getInstallationUrl(repoFullName);

  if (!isGitHubAppEnabled()) {
    // If GitHub App is not configured, assume it's installed (backward compatibility)
    return { installed: true, installUrl };
  }

  const repoRecord = await db.query.installationRepositories.findFirst({
    where: eq(installationRepositories.repoFullName, repoFullName),
    with: {
      installation: true,
    },
  });

  if (!repoRecord || repoRecord.installation.status === 'suspended') {
    return { installed: false, installUrl };
  }

  return {
    installed: true,
    installationId: repoRecord.installation.installationId,
    installUrl,
  };
}

/**
 * Get installation for a repository
 */
export async function getInstallationForRepo(
  repoFullName: string
): Promise<GitHubAppInstallation | null> {
  const repoRecord = await db.query.installationRepositories.findFirst({
    where: eq(installationRepositories.repoFullName, repoFullName),
    with: {
      installation: true,
    },
  });

  if (!repoRecord) return null;
  return repoRecord.installation;
}

/**
 * Check if a user has access to a repository via GitHub App
 * This replaces the old OAuth-based access check
 */
export async function checkUserRepoAccess(
  repoFullName: string,
  username: string
): Promise<{ hasAccess: boolean; permission: string; installationId?: number }> {
  // First check if app is installed
  const installCheck = await isAppInstalledOnRepo(repoFullName);

  if (!installCheck.installed || !installCheck.installationId) {
    return { hasAccess: false, permission: 'none' };
  }

  // Then check if user is a collaborator
  const { hasAccess, permission } = await checkCollaborator(
    installCheck.installationId,
    repoFullName,
    username
  );

  return {
    hasAccess,
    permission,
    installationId: installCheck.installationId,
  };
}

/**
 * Sync repositories for an installation (useful for reconciliation)
 */
export async function syncInstallationRepositories(
  installationId: number
): Promise<void> {
  const installation = await db.query.githubAppInstallations.findFirst({
    where: eq(githubAppInstallations.installationId, installationId),
  });

  if (!installation) {
    throw new Error(`Installation ${installationId} not found`);
  }

  // Get current repos from GitHub
  const githubRepos = await listInstallationRepositories(installationId);

  // Get current repos in DB
  const dbRepos = await db.query.installationRepositories.findMany({
    where: eq(installationRepositories.installationId, installation.id),
  });

  const githubRepoNames = new Set(githubRepos.map((r) => r.fullName));
  const dbRepoNames = new Set(dbRepos.map((r) => r.repoFullName));

  // Add new repos
  const toAdd = githubRepos.filter((r) => !dbRepoNames.has(r.fullName));
  if (toAdd.length > 0) {
    await db.insert(installationRepositories).values(
      toAdd.map((repo) => ({
        installationId: installation.id,
        repoFullName: repo.fullName,
        repoId: repo.id,
      }))
    ).onConflictDoNothing();
  }

  // Remove repos no longer accessible
  const toRemove = dbRepos.filter((r) => !githubRepoNames.has(r.repoFullName));
  for (const repo of toRemove) {
    await db
      .delete(installationRepositories)
      .where(eq(installationRepositories.id, repo.id));
  }
}

/**
 * List all installations (for admin purposes)
 */
export async function listAllInstallations(): Promise<GitHubAppInstallation[]> {
  return db.query.githubAppInstallations.findMany({
    orderBy: (installations, { desc }) => [desc(installations.createdAt)],
  });
}

/**
 * Get installation by GitHub installation ID
 */
export async function getInstallationByGitHubId(
  githubInstallationId: number
): Promise<GitHubAppInstallation | null> {
  const result = await db.query.githubAppInstallations.findFirst({
    where: eq(githubAppInstallations.installationId, githubInstallationId),
  });
  return result ?? null;
}
