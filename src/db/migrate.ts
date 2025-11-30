import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import * as dotenv from 'dotenv';
import { validateMigrations } from './validateMigrations';

dotenv.config();

const runMigrations = async () => {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not defined');
  }

  // Validate that all SQL files have journal entries
  console.log('Validating migrations...');
  const validation = await validateMigrations();

  if (validation.missingFromJournal.length > 0) {
    console.error('❌ ERROR: Found SQL files not registered in _journal.json:');
    validation.missingFromJournal.forEach(f => console.error(`   - ${f}.sql`));
    console.error('\nThese migrations will NOT be applied by drizzle!');
    console.error('Add entries to drizzle/meta/_journal.json or regenerate migrations.');
    process.exit(1);
  }

  if (validation.orphanedInJournal.length > 0) {
    console.warn('⚠️  Warning: Journal entries without SQL files:');
    validation.orphanedInJournal.forEach(f => console.warn(`   - ${f}`));
  }

  const connection = postgres(process.env.DATABASE_URL, { max: 1 });
  const db = drizzle(connection);

  console.log('Running migrations...');

  await migrate(db, { migrationsFolder: './drizzle' });

  console.log('✅ Migrations completed!');

  await connection.end();
  process.exit(0);
};

runMigrations().catch((err) => {
  console.error('Migration failed!');
  console.error(err);
  process.exit(1);
});
