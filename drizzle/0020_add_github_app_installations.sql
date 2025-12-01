-- GitHub App installations support
-- Migration: 0020_add_github_app_installations.sql

-- Create enum for installation status
DO $$ BEGIN
  CREATE TYPE "app_installation_status" AS ENUM ('active', 'suspended');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- Table for GitHub App installations
CREATE TABLE IF NOT EXISTS "github_app_installations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "installation_id" integer NOT NULL UNIQUE,
  "account_type" text NOT NULL,
  "account_login" text NOT NULL,
  "account_id" integer NOT NULL,
  "status" "app_installation_status" DEFAULT 'active' NOT NULL,
  "suspended_at" timestamp,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

-- Table for repositories accessible via installation
CREATE TABLE IF NOT EXISTS "installation_repositories" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "installation_id" uuid NOT NULL REFERENCES "github_app_installations"("id") ON DELETE CASCADE,
  "repo_full_name" text NOT NULL,
  "repo_id" integer NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS "idx_github_app_installations_account_login" ON "github_app_installations" ("account_login");
CREATE INDEX IF NOT EXISTS "idx_installation_repositories_repo_full_name" ON "installation_repositories" ("repo_full_name");
CREATE INDEX IF NOT EXISTS "idx_installation_repositories_installation_id" ON "installation_repositories" ("installation_id");

-- Unique constraint to prevent duplicate repos per installation
CREATE UNIQUE INDEX IF NOT EXISTS "idx_installation_repositories_unique" ON "installation_repositories" ("installation_id", "repo_full_name");
