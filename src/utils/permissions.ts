import { db } from '../db';
import { environmentPermissions } from '../db/schema';
import { eq, and } from 'drizzle-orm';
import type { CollaboratorRole, PermissionType } from '../db/schema';

/**
 * Role hierarchy (from lowest to highest)
 */
const ROLE_HIERARCHY: CollaboratorRole[] = ['read', 'triage', 'write', 'maintain', 'admin'];

/**
 * Check if userRole meets or exceeds requiredRole
 */
function roleHasLevel(userRole: CollaboratorRole, requiredRole: CollaboratorRole): boolean {
  const userLevel = ROLE_HIERARCHY.indexOf(userRole);
  const requiredLevel = ROLE_HIERARCHY.indexOf(requiredRole);
  return userLevel >= requiredLevel;
}

/**
 * Environment classification
 */
function getEnvironmentType(environment: string): 'protected' | 'standard' | 'development' {
  const env = environment.toLowerCase();

  // Protected environments (production)
  if (['production', 'prod', 'main', 'master'].includes(env)) {
    return 'protected';
  }

  // Development environments
  if (['dev', 'development', 'local'].includes(env)) {
    return 'development';
  }

  // Standard environments (staging, test, qa, etc.)
  return 'standard';
}

/**
 * Default permission rules based on environment type
 */
const DEFAULT_PERMISSIONS: Record<
  'protected' | 'standard' | 'development',
  Record<PermissionType, CollaboratorRole>
> = {
  // Protected environments (production, prod, main, master)
  // - read/triage: No access
  // - write/maintain: Read-only
  // - admin: Full access
  protected: {
    read: 'write',  // Need at least 'write' role to read
    write: 'admin', // Need 'admin' role to write
  },

  // Standard environments (staging, test, qa, etc.)
  // - read/triage: Read-only
  // - write/maintain/admin: Full access
  standard: {
    read: 'read',   // Anyone with 'read' or higher can read
    write: 'write', // Need 'write' or higher to write
  },

  // Development environments (dev, development, local)
  // - Everyone: Full access
  development: {
    read: 'read',   // Anyone with 'read' or higher can read
    write: 'read',  // Anyone with 'read' or higher can write (development is permissive)
  },
};

/**
 * Check if user has permission to perform an action on an environment
 *
 * @param vaultId - The vault ID
 * @param environment - The environment name (e.g., "production", "staging")
 * @param userRole - The user's collaborator role
 * @param permissionType - The permission being requested ("read" or "write")
 * @returns true if user has permission, false otherwise
 */
export async function hasEnvironmentPermission(
  vaultId: string,
  environment: string,
  userRole: CollaboratorRole,
  permissionType: PermissionType
): Promise<boolean> {
  // First, check if there are custom permissions for this vault/environment
  const customPermissions = await db
    .select()
    .from(environmentPermissions)
    .where(
      and(
        eq(environmentPermissions.vaultId, vaultId),
        eq(environmentPermissions.environment, environment),
        eq(environmentPermissions.permissionType, permissionType)
      )
    );

  // If custom permission exists, use it
  if (customPermissions.length > 0) {
    const requiredRole = customPermissions[0].minRole;
    return roleHasLevel(userRole, requiredRole);
  }

  // Otherwise, use default permissions based on environment type
  const envType = getEnvironmentType(environment);
  const requiredRole = DEFAULT_PERMISSIONS[envType][permissionType];

  return roleHasLevel(userRole, requiredRole);
}

/**
 * Get the default minimum role required for an environment/permission
 * Used for displaying defaults in API responses
 */
export function getDefaultPermission(
  environment: string,
  permissionType: PermissionType
): CollaboratorRole {
  const envType = getEnvironmentType(environment);
  return DEFAULT_PERMISSIONS[envType][permissionType];
}

/**
 * Get all permission rules for a vault (custom + defaults for common environments)
 */
export async function getVaultPermissions(vaultId: string) {
  // Get custom permissions
  const custom = await db
    .select()
    .from(environmentPermissions)
    .where(eq(environmentPermissions.vaultId, vaultId));

  // Return custom permissions with environment type classification
  const customWithDefaults = custom.map((perm) => ({
    ...perm,
    isCustom: true,
    environmentType: getEnvironmentType(perm.environment),
  }));

  return {
    custom: customWithDefaults,
    defaults: DEFAULT_PERMISSIONS,
  };
}
