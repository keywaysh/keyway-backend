/**
 * Migration script: Populate organizations from existing GitHub App installations
 *
 * This script:
 * 1. Creates organization entries from GitHub App installations where accountType = 'Organization'
 * 2. Associates existing vaults with their organizations based on repoFullName owner
 *
 * Usage: pnpm tsx scripts/migrate-organizations.ts
 */

import 'dotenv/config';
import { db } from '../src/db';
import { githubAppInstallations, organizations, vaults } from '../src/db/schema';
import { eq, and, isNull } from 'drizzle-orm';

async function migrateOrganizations() {
  console.log('Starting organization migration...\n');

  // Step 1: Find all Organization-type installations
  const orgInstallations = await db.query.githubAppInstallations.findMany({
    where: eq(githubAppInstallations.accountType, 'Organization'),
  });

  console.log(`Found ${orgInstallations.length} organization installations\n`);

  let createdOrgs = 0;
  let skippedOrgs = 0;

  for (const installation of orgInstallations) {
    // Check if organization already exists
    const existingOrg = await db.query.organizations.findFirst({
      where: eq(organizations.githubOrgId, installation.accountId),
    });

    if (existingOrg) {
      console.log(`⏭️  Skipping ${installation.accountLogin} - already exists`);
      skippedOrgs++;
      continue;
    }

    // Create the organization
    await db.insert(organizations).values({
      githubOrgId: installation.accountId,
      login: installation.accountLogin,
      displayName: installation.accountLogin,
      plan: 'free', // Default plan
    });

    console.log(`✅ Created organization: ${installation.accountLogin}`);
    createdOrgs++;
  }

  console.log(`\nOrganizations: ${createdOrgs} created, ${skippedOrgs} skipped\n`);

  // Step 2: Associate vaults with organizations
  // Find vaults without orgId that belong to an organization
  const unlinkedVaults = await db.query.vaults.findMany({
    where: isNull(vaults.orgId),
  });

  console.log(`Found ${unlinkedVaults.length} vaults without organization link\n`);

  let linkedVaults = 0;
  let userVaults = 0;

  for (const vault of unlinkedVaults) {
    // Extract owner from repoFullName (e.g., "owner/repo" -> "owner")
    const owner = vault.repoFullName.split('/')[0];

    // Check if there's an organization with this login
    const org = await db.query.organizations.findFirst({
      where: eq(organizations.login, owner),
    });

    if (org) {
      // Link vault to organization
      await db.update(vaults)
        .set({
          orgId: org.id,
          updatedAt: new Date(),
        })
        .where(eq(vaults.id, vault.id));

      console.log(`🔗 Linked vault ${vault.repoFullName} to org ${org.login}`);
      linkedVaults++;
    } else {
      // This is a user's personal vault
      console.log(`👤 Vault ${vault.repoFullName} belongs to a user (no org)`);
      userVaults++;
    }
  }

  console.log(`\nVaults: ${linkedVaults} linked to orgs, ${userVaults} are personal vaults\n`);

  console.log('Migration complete! Summary:');
  console.log('----------------------------');
  console.log(`Organizations created: ${createdOrgs}`);
  console.log(`Organizations skipped: ${skippedOrgs}`);
  console.log(`Vaults linked to orgs: ${linkedVaults}`);
  console.log(`Personal vaults: ${userVaults}`);
}

// Run the migration
migrateOrganizations()
  .then(() => {
    console.log('\n✨ Migration finished successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  });
