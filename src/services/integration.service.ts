/**
 * Integration Service
 * Handles provider connections and sync operations
 */

import { eq, and } from 'drizzle-orm';
import { db, providerConnections, vaultSyncs, syncLogs, secrets, vaults } from '../db';
import { getProvider } from './providers';
import { encrypt, decrypt } from '../utils/encryption';
import type { SyncDirection, SyncStatus } from '../db/schema';

// Types
export interface ConnectionInfo {
  id: string;
  provider: string;
  providerUserId: string | null;
  providerTeamId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SyncPreview {
  toCreate: string[];
  toUpdate: string[];
  toDelete: string[];
  toSkip: string[];
}

export interface SyncResult {
  status: SyncStatus;
  created: number;
  updated: number;
  deleted: number;
  skipped: number;
  error?: string;
}

export interface SyncStatusInfo {
  isFirstSync: boolean;
  vaultIsEmpty: boolean;
  providerHasSecrets: boolean;
  providerSecretCount: number;
}

// Helper to encrypt provider token
function encryptProviderToken(token: string) {
  const encrypted = encrypt(token);
  return {
    encryptedAccessToken: encrypted.encryptedContent,
    accessTokenIv: encrypted.iv,
    accessTokenAuthTag: encrypted.authTag,
  };
}

// Helper to decrypt provider token
function decryptProviderToken(connection: {
  encryptedAccessToken: string;
  accessTokenIv: string;
  accessTokenAuthTag: string;
}) {
  return decrypt({
    encryptedContent: connection.encryptedAccessToken,
    iv: connection.accessTokenIv,
    authTag: connection.accessTokenAuthTag,
  });
}

/**
 * Get a user's connection to a provider
 */
export async function getConnection(
  userId: string,
  providerName: string,
  teamId?: string
): Promise<ConnectionInfo | null> {
  const conditions = [
    eq(providerConnections.userId, userId),
    eq(providerConnections.provider, providerName),
  ];

  if (teamId) {
    conditions.push(eq(providerConnections.providerTeamId, teamId));
  }

  const connection = await db.query.providerConnections.findFirst({
    where: and(...conditions),
  });

  if (!connection) return null;

  return {
    id: connection.id,
    provider: connection.provider,
    providerUserId: connection.providerUserId,
    providerTeamId: connection.providerTeamId,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
  };
}

/**
 * List all connections for a user
 */
export async function listConnections(userId: string): Promise<ConnectionInfo[]> {
  const connections = await db.query.providerConnections.findMany({
    where: eq(providerConnections.userId, userId),
  });

  return connections.map(c => ({
    id: c.id,
    provider: c.provider,
    providerUserId: c.providerUserId,
    providerTeamId: c.providerTeamId,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
  }));
}

/**
 * Store a new provider connection after OAuth
 */
export async function createConnection(
  userId: string,
  providerName: string,
  accessToken: string,
  providerUser: { id: string; teamId?: string },
  refreshToken?: string,
  expiresAt?: Date,
  scopes?: string[]
) {
  const encrypted = encryptProviderToken(accessToken);

  let refreshTokenData = {};
  if (refreshToken) {
    const encryptedRefresh = encrypt(refreshToken);
    refreshTokenData = {
      encryptedRefreshToken: encryptedRefresh.encryptedContent,
      refreshTokenIv: encryptedRefresh.iv,
      refreshTokenAuthTag: encryptedRefresh.authTag,
    };
  }

  const [connection] = await db
    .insert(providerConnections)
    .values({
      userId,
      provider: providerName,
      providerUserId: providerUser.id,
      providerTeamId: providerUser.teamId || null,
      ...encrypted,
      ...refreshTokenData,
      tokenExpiresAt: expiresAt || null,
      scopes: scopes || null,
    })
    .onConflictDoUpdate({
      target: [providerConnections.userId, providerConnections.provider, providerConnections.providerTeamId],
      set: {
        ...encrypted,
        ...refreshTokenData,
        providerUserId: providerUser.id,
        tokenExpiresAt: expiresAt || null,
        scopes: scopes || null,
        updatedAt: new Date(),
      },
    })
    .returning();

  return connection;
}

/**
 * Delete a provider connection
 */
export async function deleteConnection(userId: string, connectionId: string): Promise<boolean> {
  const result = await db
    .delete(providerConnections)
    .where(and(
      eq(providerConnections.id, connectionId),
      eq(providerConnections.userId, userId)
    ))
    .returning({ id: providerConnections.id });

  return result.length > 0;
}

/**
 * Get decrypted access token for a connection
 */
export async function getConnectionToken(connectionId: string): Promise<string | null> {
  const connection = await db.query.providerConnections.findFirst({
    where: eq(providerConnections.id, connectionId),
  });

  if (!connection) return null;

  return decryptProviderToken(connection);
}

/**
 * List provider projects for a connection
 */
export async function listProviderProjects(connectionId: string) {
  const connection = await db.query.providerConnections.findFirst({
    where: eq(providerConnections.id, connectionId),
  });

  if (!connection) {
    throw new Error('Connection not found');
  }

  const provider = getProvider(connection.provider);
  if (!provider) {
    throw new Error(`Provider ${connection.provider} not found`);
  }

  const accessToken = decryptProviderToken(connection);
  return provider.listProjects(accessToken, connection.providerTeamId || undefined);
}

/**
 * Get sync status (for first-time detection)
 */
export async function getSyncStatus(
  vaultId: string,
  connectionId: string,
  projectId: string,
  environment: string
): Promise<SyncStatusInfo> {
  // Check if there's been a previous sync
  const existingSync = await db.query.vaultSyncs.findFirst({
    where: and(
      eq(vaultSyncs.vaultId, vaultId),
      eq(vaultSyncs.connectionId, connectionId),
      eq(vaultSyncs.providerProjectId, projectId)
    ),
  });

  // Check if vault has secrets
  const vaultSecrets = await db.query.secrets.findMany({
    where: and(
      eq(secrets.vaultId, vaultId),
      eq(secrets.environment, environment)
    ),
  });

  // Get provider secrets count
  const connection = await db.query.providerConnections.findFirst({
    where: eq(providerConnections.id, connectionId),
  });

  let providerSecretCount = 0;
  if (connection) {
    const provider = getProvider(connection.provider);
    if (provider) {
      const accessToken = decryptProviderToken(connection);
      const providerEnvVars = await provider.listEnvVars(
        accessToken,
        projectId,
        environment,
        connection.providerTeamId || undefined
      );
      providerSecretCount = providerEnvVars.length;
    }
  }

  return {
    isFirstSync: !existingSync,
    vaultIsEmpty: vaultSecrets.length === 0,
    providerHasSecrets: providerSecretCount > 0,
    providerSecretCount,
  };
}

/**
 * Get sync preview (what would change)
 */
export async function getSyncPreview(
  vaultId: string,
  connectionId: string,
  projectId: string,
  keywayEnvironment: string,
  providerEnvironment: string,
  direction: SyncDirection,
  allowDelete: boolean
): Promise<SyncPreview> {
  const connection = await db.query.providerConnections.findFirst({
    where: eq(providerConnections.id, connectionId),
  });

  if (!connection) {
    throw new Error('Connection not found');
  }

  const provider = getProvider(connection.provider);
  if (!provider) {
    throw new Error(`Provider ${connection.provider} not found`);
  }

  const accessToken = decryptProviderToken(connection);

  // Get Keyway secrets
  const keywaySecrets = await db.query.secrets.findMany({
    where: and(
      eq(secrets.vaultId, vaultId),
      eq(secrets.environment, keywayEnvironment)
    ),
  });

  const keywaySecretsMap = new Map<string, string>();
  for (const secret of keywaySecrets) {
    const value = decrypt({
      encryptedContent: secret.encryptedValue,
      iv: secret.iv,
      authTag: secret.authTag,
    });
    keywaySecretsMap.set(secret.key, value);
  }

  // Get provider secrets
  const providerEnvVars = await provider.listEnvVars(
    accessToken,
    projectId,
    providerEnvironment,
    connection.providerTeamId || undefined
  );

  const providerSecretsMap = new Map<string, string>();
  for (const envVar of providerEnvVars) {
    if (envVar.value) {
      providerSecretsMap.set(envVar.key, envVar.value);
    }
  }

  const toCreate: string[] = [];
  const toUpdate: string[] = [];
  const toDelete: string[] = [];
  const toSkip: string[] = [];

  if (direction === 'push') {
    // Keyway → Provider
    for (const [key, value] of keywaySecretsMap) {
      const providerValue = providerSecretsMap.get(key);
      if (providerValue === undefined) {
        toCreate.push(key);
      } else if (providerValue !== value) {
        toUpdate.push(key);
      } else {
        toSkip.push(key);
      }
    }

    if (allowDelete) {
      for (const key of providerSecretsMap.keys()) {
        if (!keywaySecretsMap.has(key)) {
          toDelete.push(key);
        }
      }
    }
  } else {
    // Provider → Keyway (pull/import)
    for (const [key, value] of providerSecretsMap) {
      const keywayValue = keywaySecretsMap.get(key);
      if (keywayValue === undefined) {
        toCreate.push(key);
      } else if (keywayValue !== value) {
        // For import, we skip existing by default
        toSkip.push(key);
      } else {
        toSkip.push(key);
      }
    }
  }

  return { toCreate, toUpdate, toDelete, toSkip };
}

/**
 * Execute a sync operation
 */
export async function executeSync(
  vaultId: string,
  connectionId: string,
  projectId: string,
  keywayEnvironment: string,
  providerEnvironment: string,
  direction: SyncDirection,
  allowDelete: boolean,
  triggeredBy: string
): Promise<SyncResult> {
  const connection = await db.query.providerConnections.findFirst({
    where: eq(providerConnections.id, connectionId),
  });

  if (!connection) {
    throw new Error('Connection not found');
  }

  const provider = getProvider(connection.provider);
  if (!provider) {
    throw new Error(`Provider ${connection.provider} not found`);
  }

  const accessToken = decryptProviderToken(connection);

  // Get or create vault sync config
  let syncConfig = await db.query.vaultSyncs.findFirst({
    where: and(
      eq(vaultSyncs.vaultId, vaultId),
      eq(vaultSyncs.connectionId, connectionId),
      eq(vaultSyncs.providerProjectId, projectId),
      eq(vaultSyncs.providerEnvironment, providerEnvironment)
    ),
  });

  if (!syncConfig) {
    // Get project name
    let projectName: string | undefined;
    if (provider.getProject) {
      const project = await provider.getProject(accessToken, projectId, connection.providerTeamId || undefined);
      projectName = project?.name;
    }

    [syncConfig] = await db
      .insert(vaultSyncs)
      .values({
        vaultId,
        connectionId,
        provider: connection.provider,
        providerProjectId: projectId,
        providerProjectName: projectName,
        keywayEnvironment,
        providerEnvironment,
      })
      .returning();
  }

  let result: SyncResult;

  try {
    if (direction === 'push') {
      result = await executePush(
        vaultId,
        keywayEnvironment,
        provider,
        accessToken,
        projectId,
        providerEnvironment,
        connection.providerTeamId || undefined,
        allowDelete
      );
    } else {
      result = await executePull(
        vaultId,
        keywayEnvironment,
        provider,
        accessToken,
        projectId,
        providerEnvironment,
        connection.providerTeamId || undefined
      );
    }

    // Update last synced
    await db
      .update(vaultSyncs)
      .set({ lastSyncedAt: new Date() })
      .where(eq(vaultSyncs.id, syncConfig.id));

  } catch (error) {
    result = {
      status: 'failed',
      created: 0,
      updated: 0,
      deleted: 0,
      skipped: 0,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }

  // Log the sync
  await db.insert(syncLogs).values({
    syncId: syncConfig.id,
    vaultId,
    provider: connection.provider,
    direction,
    status: result.status,
    secretsCreated: result.created,
    secretsUpdated: result.updated,
    secretsDeleted: result.deleted,
    secretsSkipped: result.skipped,
    error: result.error,
    triggeredBy,
  });

  return result;
}

/**
 * Execute push: Keyway → Provider
 */
async function executePush(
  vaultId: string,
  keywayEnvironment: string,
  provider: ReturnType<typeof getProvider>,
  accessToken: string,
  projectId: string,
  providerEnvironment: string,
  teamId: string | undefined,
  allowDelete: boolean
): Promise<SyncResult> {
  if (!provider) throw new Error('Provider not found');

  // Get Keyway secrets
  const keywaySecrets = await db.query.secrets.findMany({
    where: and(
      eq(secrets.vaultId, vaultId),
      eq(secrets.environment, keywayEnvironment)
    ),
  });

  const varsToSet: Record<string, string> = {};
  for (const secret of keywaySecrets) {
    const value = decrypt({
      encryptedContent: secret.encryptedValue,
      iv: secret.iv,
      authTag: secret.authTag,
    });
    varsToSet[secret.key] = value;
  }

  // Set env vars
  const { created, updated } = await provider.setEnvVars(
    accessToken,
    projectId,
    providerEnvironment,
    varsToSet,
    teamId
  );

  let deleted = 0;
  if (allowDelete) {
    // Get provider env vars
    const providerEnvVars = await provider.listEnvVars(
      accessToken,
      projectId,
      providerEnvironment,
      teamId
    );

    const keysToDelete = providerEnvVars
      .filter(env => !varsToSet[env.key])
      .map(env => env.key);

    if (keysToDelete.length > 0) {
      if (provider.deleteEnvVars) {
        const result = await provider.deleteEnvVars(accessToken, projectId, providerEnvironment, keysToDelete, teamId);
        deleted = result.deleted;
      } else {
        for (const key of keysToDelete) {
          await provider.deleteEnvVar(accessToken, projectId, providerEnvironment, key, teamId);
          deleted++;
        }
      }
    }
  }

  return {
    status: 'success',
    created,
    updated,
    deleted,
    skipped: 0,
  };
}

/**
 * Execute pull: Provider → Keyway
 */
async function executePull(
  vaultId: string,
  keywayEnvironment: string,
  provider: ReturnType<typeof getProvider>,
  accessToken: string,
  projectId: string,
  providerEnvironment: string,
  teamId: string | undefined
): Promise<SyncResult> {
  if (!provider) throw new Error('Provider not found');

  // Get provider env vars
  const providerEnvVars = await provider.listEnvVars(
    accessToken,
    projectId,
    providerEnvironment,
    teamId
  );

  // Get existing Keyway secrets
  const existingSecrets = await db.query.secrets.findMany({
    where: and(
      eq(secrets.vaultId, vaultId),
      eq(secrets.environment, keywayEnvironment)
    ),
  });

  const existingKeys = new Set(existingSecrets.map(s => s.key));

  let created = 0;
  let skipped = 0;

  for (const envVar of providerEnvVars) {
    if (!envVar.value) {
      skipped++;
      continue;
    }

    if (existingKeys.has(envVar.key)) {
      skipped++;
      continue;
    }

    // Create new secret
    const encrypted = encrypt(envVar.value);
    await db.insert(secrets).values({
      vaultId,
      environment: keywayEnvironment,
      key: envVar.key,
      encryptedValue: encrypted.encryptedContent,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    });
    created++;
  }

  return {
    status: 'success',
    created,
    updated: 0,
    deleted: 0,
    skipped,
  };
}
