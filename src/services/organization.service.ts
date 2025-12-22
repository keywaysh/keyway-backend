import { db } from '../db';
import { organizations, organizationMembers, users, vaults } from '../db/schema';
import { eq, and, desc } from 'drizzle-orm';
import type { Organization, OrganizationMember, OrgRole, UserPlan, ForgeType } from '../db/schema';

// ============================================================================
// Types
// ============================================================================

export interface OrganizationInfo {
  id: string;
  forgeType: 'github' | 'gitlab' | 'bitbucket';
  forgeOrgId: string;
  login: string;
  displayName: string | null;
  avatarUrl: string | null;
  plan: UserPlan;
  memberCount: number;
  vaultCount: number;
  createdAt: string;
}

export interface OrganizationMemberInfo {
  id: string;
  userId: string;
  username: string;
  avatarUrl: string | null;
  email: string | null;
  orgRole: OrgRole;
  membershipState: string | null;
  joinedAt: string;
}

export interface OrganizationDetails extends OrganizationInfo {
  members: OrganizationMemberInfo[];
  defaultPermissions: Record<string, unknown>;
  stripeCustomerId: string | null;
}

// ============================================================================
// CRUD Operations
// ============================================================================

/**
 * Get or create an organization from VCS data
 */
export async function getOrCreateOrganization(
  forgeType: ForgeType,
  forgeOrgId: string,
  login: string,
  displayName?: string,
  avatarUrl?: string
): Promise<Organization> {
  // Try to find existing org
  const existingOrg = await db.query.organizations.findFirst({
    where: and(
      eq(organizations.forgeType, forgeType),
      eq(organizations.forgeOrgId, forgeOrgId)
    ),
  });

  if (existingOrg) {
    // Update if data changed
    if (
      existingOrg.login !== login ||
      existingOrg.displayName !== displayName ||
      existingOrg.avatarUrl !== avatarUrl
    ) {
      const [updated] = await db
        .update(organizations)
        .set({
          login,
          displayName: displayName ?? existingOrg.displayName,
          avatarUrl: avatarUrl ?? existingOrg.avatarUrl,
          updatedAt: new Date(),
        })
        .where(eq(organizations.id, existingOrg.id))
        .returning();
      return updated;
    }
    return existingOrg;
  }

  // Create new org
  const [newOrg] = await db
    .insert(organizations)
    .values({
      forgeType,
      forgeOrgId,
      login,
      displayName,
      avatarUrl,
    })
    .returning();

  return newOrg;
}

/**
 * Get organization by login (GitHub org name)
 */
export async function getOrganizationByLogin(login: string): Promise<Organization | null> {
  const org = await db.query.organizations.findFirst({
    where: eq(organizations.login, login),
  });
  return org ?? null;
}

/**
 * Get organization by ID
 */
export async function getOrganizationById(orgId: string): Promise<Organization | null> {
  const org = await db.query.organizations.findFirst({
    where: eq(organizations.id, orgId),
  });
  return org ?? null;
}

/**
 * Get organization with full details
 */
export async function getOrganizationDetails(orgId: string): Promise<OrganizationDetails | null> {
  const org = await db.query.organizations.findFirst({
    where: eq(organizations.id, orgId),
    with: {
      members: {
        with: {
          user: true,
        },
        orderBy: [desc(organizationMembers.createdAt)],
      },
      vaults: true,
    },
  });

  if (!org) return null;

  return {
    id: org.id,
    forgeType: org.forgeType,
    forgeOrgId: org.forgeOrgId,
    login: org.login,
    displayName: org.displayName,
    avatarUrl: org.avatarUrl,
    plan: org.plan,
    memberCount: org.members.length,
    vaultCount: org.vaults.length,
    members: org.members.map(m => ({
      id: m.id,
      userId: m.userId,
      username: m.user.username,
      avatarUrl: m.user.avatarUrl,
      email: m.user.email,
      orgRole: m.orgRole,
      membershipState: m.membershipState,
      joinedAt: m.createdAt.toISOString(),
    })),
    defaultPermissions: (org.defaultPermissions as Record<string, unknown>) ?? {},
    stripeCustomerId: org.stripeCustomerId,
    createdAt: org.createdAt.toISOString(),
  };
}

/**
 * Get all organizations for a user
 */
export async function getOrganizationsForUser(userId: string): Promise<OrganizationInfo[]> {
  const memberships = await db.query.organizationMembers.findMany({
    where: eq(organizationMembers.userId, userId),
    with: {
      organization: {
        with: {
          members: true,
          vaults: true,
        },
      },
    },
    orderBy: [desc(organizationMembers.createdAt)],
  });

  return memberships.map(m => ({
    id: m.organization.id,
    forgeType: m.organization.forgeType,
    forgeOrgId: m.organization.forgeOrgId,
    login: m.organization.login,
    displayName: m.organization.displayName,
    avatarUrl: m.organization.avatarUrl,
    plan: m.organization.plan,
    memberCount: m.organization.members.length,
    vaultCount: m.organization.vaults.length,
    createdAt: m.organization.createdAt.toISOString(),
  }));
}

/**
 * Update organization settings
 */
export async function updateOrganization(
  orgId: string,
  updates: {
    displayName?: string;
    defaultPermissions?: Record<string, unknown>;
  }
): Promise<Organization> {
  const [updated] = await db
    .update(organizations)
    .set({
      ...updates,
      updatedAt: new Date(),
    })
    .where(eq(organizations.id, orgId))
    .returning();

  return updated;
}

/**
 * Update organization plan (called from billing webhook)
 */
export async function updateOrganizationPlan(orgId: string, plan: UserPlan): Promise<void> {
  await db
    .update(organizations)
    .set({ plan, updatedAt: new Date() })
    .where(eq(organizations.id, orgId));
}

/**
 * Set Stripe customer ID for organization
 */
export async function setOrganizationStripeCustomerId(
  orgId: string,
  stripeCustomerId: string
): Promise<void> {
  await db
    .update(organizations)
    .set({ stripeCustomerId, updatedAt: new Date() })
    .where(eq(organizations.id, orgId));
}

// ============================================================================
// Member Operations
// ============================================================================

/**
 * Add or update a member in an organization
 */
export async function upsertOrganizationMember(
  orgId: string,
  userId: string,
  orgRole: OrgRole,
  membershipState: string = 'active'
): Promise<OrganizationMember> {
  // Check if membership exists
  const existing = await db.query.organizationMembers.findFirst({
    where: and(
      eq(organizationMembers.orgId, orgId),
      eq(organizationMembers.userId, userId)
    ),
  });

  if (existing) {
    // Update existing membership
    const [updated] = await db
      .update(organizationMembers)
      .set({
        orgRole,
        membershipState,
        updatedAt: new Date(),
      })
      .where(eq(organizationMembers.id, existing.id))
      .returning();
    return updated;
  }

  // Create new membership
  const [newMember] = await db
    .insert(organizationMembers)
    .values({
      orgId,
      userId,
      orgRole,
      membershipState,
    })
    .returning();

  return newMember;
}

/**
 * Remove a member from an organization
 */
export async function removeOrganizationMember(orgId: string, userId: string): Promise<void> {
  await db
    .delete(organizationMembers)
    .where(
      and(
        eq(organizationMembers.orgId, orgId),
        eq(organizationMembers.userId, userId)
      )
    );
}

/**
 * Get a user's membership in an organization
 */
export async function getOrganizationMembership(
  orgId: string,
  userId: string
): Promise<OrganizationMember | null> {
  const membership = await db.query.organizationMembers.findFirst({
    where: and(
      eq(organizationMembers.orgId, orgId),
      eq(organizationMembers.userId, userId)
    ),
  });
  return membership ?? null;
}

/**
 * Check if a user is an owner of an organization
 */
export async function isOrganizationOwner(orgId: string, userId: string): Promise<boolean> {
  const membership = await getOrganizationMembership(orgId, userId);
  return membership?.orgRole === 'owner';
}

/**
 * Get all members of an organization
 */
export async function getOrganizationMembers(orgId: string): Promise<OrganizationMemberInfo[]> {
  const members = await db.query.organizationMembers.findMany({
    where: eq(organizationMembers.orgId, orgId),
    with: {
      user: true,
    },
    orderBy: [desc(organizationMembers.createdAt)],
  });

  return members.map(m => ({
    id: m.id,
    userId: m.userId,
    username: m.user.username,
    avatarUrl: m.user.avatarUrl,
    email: m.user.email,
    orgRole: m.orgRole,
    membershipState: m.membershipState,
    joinedAt: m.createdAt.toISOString(),
  }));
}

// ============================================================================
// Vault Operations
// ============================================================================

/**
 * Associate a vault with an organization
 */
export async function associateVaultWithOrg(vaultId: string, orgId: string): Promise<void> {
  await db
    .update(vaults)
    .set({ orgId, updatedAt: new Date() })
    .where(eq(vaults.id, vaultId));
}

/**
 * Get all vaults for an organization
 */
export async function getOrganizationVaults(orgId: string) {
  return db.query.vaults.findMany({
    where: eq(vaults.orgId, orgId),
    with: {
      secrets: true,
    },
    orderBy: [desc(vaults.updatedAt)],
  });
}

// ============================================================================
// VCS Sync Operations
// ============================================================================

export interface VcsOrgMember {
  id: string;  // forgeUserId as string
  login: string;
  avatar_url: string;
  role: 'admin' | 'member';
}

/**
 * Sync organization members from VCS (GitHub, GitLab, etc.)
 * This should be called when:
 * - VCS App is installed on an org
 * - Webhook receives member_added/member_removed event
 * - Manual sync is requested
 */
export async function syncOrganizationMembers(
  orgId: string,
  forgeType: ForgeType,
  vcsMembers: VcsOrgMember[]
): Promise<{ added: number; updated: number; removed: number }> {
  const currentMembers = await db.query.organizationMembers.findMany({
    where: eq(organizationMembers.orgId, orgId),
    with: { user: true },
  });

  const currentMemberUserIds = new Set(currentMembers.map(m => m.user.forgeUserId));
  const vcsMemberIds = new Set(vcsMembers.map(m => m.id));

  let added = 0;
  let updated = 0;
  let removed = 0;

  // Add or update members from VCS
  for (const vcsMember of vcsMembers) {
    // Find corresponding Keyway user by forge type and user ID
    const keywayUser = await db.query.users.findFirst({
      where: and(
        eq(users.forgeType, forgeType),
        eq(users.forgeUserId, vcsMember.id)
      ),
    });

    if (!keywayUser) {
      // User hasn't logged into Keyway yet, skip
      continue;
    }

    const orgRole: OrgRole = vcsMember.role === 'admin' ? 'owner' : 'member';
    const existingMember = currentMembers.find(m => m.user.forgeUserId === vcsMember.id);

    if (existingMember) {
      // Update if role changed
      if (existingMember.orgRole !== orgRole) {
        await upsertOrganizationMember(orgId, keywayUser.id, orgRole);
        updated++;
      }
    } else {
      // Add new member
      await upsertOrganizationMember(orgId, keywayUser.id, orgRole);
      added++;
    }
  }

  // Remove members no longer in VCS org
  for (const member of currentMembers) {
    if (!vcsMemberIds.has(member.user.forgeUserId)) {
      await removeOrganizationMember(orgId, member.userId);
      removed++;
    }
  }

  return { added, updated, removed };
}

/**
 * Get the effective plan for a vault (org plan or user plan)
 */
export async function getEffectivePlanForVault(vaultId: string): Promise<UserPlan> {
  const vault = await db.query.vaults.findFirst({
    where: eq(vaults.id, vaultId),
    with: {
      organization: true,
      owner: true,
    },
  });

  if (!vault) {
    return 'free';
  }

  // If vault belongs to an org, use org's plan
  if (vault.organization) {
    return vault.organization.plan;
  }

  // Otherwise use owner's plan
  return vault.owner.plan;
}
