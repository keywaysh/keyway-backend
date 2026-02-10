import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is required");
}

const connectionString = process.env.DATABASE_URL;

const poolMax = parseInt(process.env.DB_POOL_MAX ?? "", 10);

// Create postgres connection with pool configuration
export const sql = postgres(connectionString, {
  max: Number.isFinite(poolMax) && poolMax > 0 ? poolMax : 20,
  idle_timeout: 20,
  connect_timeout: 10,
});

// Create drizzle instance
export const db = drizzle(sql, { schema });

export * from "./schema";
