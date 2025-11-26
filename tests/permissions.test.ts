import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getDefaultPermission } from '../src/utils/permissions';
import type { CollaboratorRole, PermissionType } from '../src/db/schema';

// Test pure functions without DB
describe('Permissions Utils (Security Critical)', () => {
  describe('getDefaultPermission', () => {
    describe('protected environments (production)', () => {
      const protectedEnvs = ['production', 'prod', 'main', 'master', 'PRODUCTION', 'Prod'];

      protectedEnvs.forEach((env) => {
        it(`should require 'write' role to read from ${env}`, () => {
          const minRole = getDefaultPermission(env, 'read');
          expect(minRole).toBe('write');
        });

        it(`should require 'admin' role to write to ${env}`, () => {
          const minRole = getDefaultPermission(env, 'write');
          expect(minRole).toBe('admin');
        });
      });
    });

    describe('standard environments (staging, test)', () => {
      const standardEnvs = ['staging', 'test', 'qa', 'uat', 'preview'];

      standardEnvs.forEach((env) => {
        it(`should require 'read' role to read from ${env}`, () => {
          const minRole = getDefaultPermission(env, 'read');
          expect(minRole).toBe('read');
        });

        it(`should require 'write' role to write to ${env}`, () => {
          const minRole = getDefaultPermission(env, 'write');
          expect(minRole).toBe('write');
        });
      });
    });

    describe('development environments', () => {
      const devEnvs = ['dev', 'development', 'local', 'DEV', 'Development'];

      devEnvs.forEach((env) => {
        it(`should require 'read' role to read from ${env}`, () => {
          const minRole = getDefaultPermission(env, 'read');
          expect(minRole).toBe('read');
        });

        it(`should require 'read' role to write to ${env} (permissive)`, () => {
          const minRole = getDefaultPermission(env, 'write');
          expect(minRole).toBe('read');
        });
      });
    });

    describe('default environment', () => {
      it('should treat "default" as standard environment', () => {
        expect(getDefaultPermission('default', 'read')).toBe('read');
        expect(getDefaultPermission('default', 'write')).toBe('write');
      });
    });
  });

  describe('Role hierarchy validation', () => {
    const roles: CollaboratorRole[] = ['read', 'triage', 'write', 'maintain', 'admin'];

    it('should have correct role order', () => {
      // admin > maintain > write > triage > read
      expect(roles.indexOf('admin')).toBeGreaterThan(roles.indexOf('maintain'));
      expect(roles.indexOf('maintain')).toBeGreaterThan(roles.indexOf('write'));
      expect(roles.indexOf('write')).toBeGreaterThan(roles.indexOf('triage'));
      expect(roles.indexOf('triage')).toBeGreaterThan(roles.indexOf('read'));
    });
  });

  describe('Security scenarios', () => {
    it('should protect production from read-only users', () => {
      const minReadRole = getDefaultPermission('production', 'read');
      // read and triage users should NOT be able to read production
      expect(['read', 'triage'].includes(minReadRole)).toBe(false);
    });

    it('should protect production from write users for writes', () => {
      const minWriteRole = getDefaultPermission('production', 'write');
      // Only admin can write to production by default
      expect(minWriteRole).toBe('admin');
    });

    it('should allow developers full access to dev environments', () => {
      // Even read-only collaborators can write to dev (permissive for development)
      expect(getDefaultPermission('dev', 'write')).toBe('read');
      expect(getDefaultPermission('local', 'write')).toBe('read');
    });

    it('should handle case-insensitive environment names', () => {
      expect(getDefaultPermission('PRODUCTION', 'write')).toBe('admin');
      expect(getDefaultPermission('Production', 'write')).toBe('admin');
      expect(getDefaultPermission('DEV', 'write')).toBe('read');
    });

    it('should default unknown environments to standard permissions', () => {
      // Unknown environments should be treated as standard (not permissive)
      expect(getDefaultPermission('custom-env', 'read')).toBe('read');
      expect(getDefaultPermission('custom-env', 'write')).toBe('write');
      expect(getDefaultPermission('my-feature-branch', 'write')).toBe('write');
    });
  });
});

describe('Role hierarchy logic', () => {
  // Simulate the roleHasLevel function logic for testing
  const ROLE_HIERARCHY: CollaboratorRole[] = ['read', 'triage', 'write', 'maintain', 'admin'];

  function roleHasLevel(userRole: CollaboratorRole, requiredRole: CollaboratorRole): boolean {
    const userLevel = ROLE_HIERARCHY.indexOf(userRole);
    const requiredLevel = ROLE_HIERARCHY.indexOf(requiredRole);
    return userLevel >= requiredLevel;
  }

  describe('roleHasLevel', () => {
    it('admin should have all permissions', () => {
      expect(roleHasLevel('admin', 'admin')).toBe(true);
      expect(roleHasLevel('admin', 'maintain')).toBe(true);
      expect(roleHasLevel('admin', 'write')).toBe(true);
      expect(roleHasLevel('admin', 'triage')).toBe(true);
      expect(roleHasLevel('admin', 'read')).toBe(true);
    });

    it('maintain should have maintain and below', () => {
      expect(roleHasLevel('maintain', 'admin')).toBe(false);
      expect(roleHasLevel('maintain', 'maintain')).toBe(true);
      expect(roleHasLevel('maintain', 'write')).toBe(true);
      expect(roleHasLevel('maintain', 'triage')).toBe(true);
      expect(roleHasLevel('maintain', 'read')).toBe(true);
    });

    it('write should have write and below', () => {
      expect(roleHasLevel('write', 'admin')).toBe(false);
      expect(roleHasLevel('write', 'maintain')).toBe(false);
      expect(roleHasLevel('write', 'write')).toBe(true);
      expect(roleHasLevel('write', 'triage')).toBe(true);
      expect(roleHasLevel('write', 'read')).toBe(true);
    });

    it('triage should have triage and below', () => {
      expect(roleHasLevel('triage', 'admin')).toBe(false);
      expect(roleHasLevel('triage', 'maintain')).toBe(false);
      expect(roleHasLevel('triage', 'write')).toBe(false);
      expect(roleHasLevel('triage', 'triage')).toBe(true);
      expect(roleHasLevel('triage', 'read')).toBe(true);
    });

    it('read should only have read', () => {
      expect(roleHasLevel('read', 'admin')).toBe(false);
      expect(roleHasLevel('read', 'maintain')).toBe(false);
      expect(roleHasLevel('read', 'write')).toBe(false);
      expect(roleHasLevel('read', 'triage')).toBe(false);
      expect(roleHasLevel('read', 'read')).toBe(true);
    });
  });

  describe('Production access matrix', () => {
    it('should deny read-only users from reading production', () => {
      const requiredRead = 'write'; // getDefaultPermission('production', 'read')
      expect(roleHasLevel('read', requiredRead)).toBe(false);
      expect(roleHasLevel('triage', requiredRead)).toBe(false);
    });

    it('should allow write+ users to read production', () => {
      const requiredRead = 'write';
      expect(roleHasLevel('write', requiredRead)).toBe(true);
      expect(roleHasLevel('maintain', requiredRead)).toBe(true);
      expect(roleHasLevel('admin', requiredRead)).toBe(true);
    });

    it('should only allow admin to write to production', () => {
      const requiredWrite = 'admin'; // getDefaultPermission('production', 'write')
      expect(roleHasLevel('read', requiredWrite)).toBe(false);
      expect(roleHasLevel('triage', requiredWrite)).toBe(false);
      expect(roleHasLevel('write', requiredWrite)).toBe(false);
      expect(roleHasLevel('maintain', requiredWrite)).toBe(false);
      expect(roleHasLevel('admin', requiredWrite)).toBe(true);
    });
  });
});
