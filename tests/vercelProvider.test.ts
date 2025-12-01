import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock config before importing provider
vi.mock('../src/config', () => ({
  config: {
    server: { isDevelopment: false },
    vercel: {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
    },
  },
}));

describe('Vercel Provider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getAuthorizationUrl', () => {
    it('should return correct OAuth authorization URL with PKCE', async () => {
      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const result = vercelProvider.getAuthorizationUrl('test-state', 'http://localhost:3000/callback');

      // Should return object with url and codeVerifier
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('codeVerifier');
      expect(typeof result.codeVerifier).toBe('string');
      expect(result.codeVerifier!.length).toBeGreaterThan(0);

      // URL should be the correct OAuth endpoint (not marketplace integrations)
      expect(result.url).toContain('https://vercel.com/oauth/authorize');
      expect(result.url).not.toContain('integrations/install/new');

      // Should include required OAuth params
      expect(result.url).toContain('client_id=test-client-id');
      expect(result.url).toContain('response_type=code');
      expect(result.url).toContain('redirect_uri=');

      // Should include PKCE params
      expect(result.url).toContain('code_challenge=');
      expect(result.url).toContain('code_challenge_method=S256');
    });

    it('should generate different PKCE codes for each call', async () => {
      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const result1 = vercelProvider.getAuthorizationUrl('state1', 'http://localhost:3000/callback');
      const result2 = vercelProvider.getAuthorizationUrl('state2', 'http://localhost:3000/callback');

      expect(result1.codeVerifier).not.toBe(result2.codeVerifier);
    });
  });

  describe('exchangeCodeForToken', () => {
    it('should exchange code for access token using correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          access_token: 'vercel-access-token',
          token_type: 'Bearer',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const result = await vercelProvider.exchangeCodeForToken('auth-code', 'http://localhost:3000/callback');

      expect(result.accessToken).toBe('vercel-access-token');
      expect(result.tokenType).toBe('Bearer');

      // Should use the correct OIDC token endpoint (not /v2/oauth/access_token)
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.vercel.com/login/oauth/token',
        expect.objectContaining({
          method: 'POST',
        })
      );
    });

    it('should include code_verifier when provided (PKCE)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          access_token: 'vercel-access-token',
          token_type: 'Bearer',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await vercelProvider.exchangeCodeForToken('auth-code', 'http://localhost:3000/callback', 'test-code-verifier');

      // Verify the body includes code_verifier
      const fetchCall = mockFetch.mock.calls[0];
      const body = fetchCall[1].body as URLSearchParams;
      expect(body.get('code_verifier')).toBe('test-code-verifier');
    });

    it('should throw error on failed token exchange', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: () => Promise.resolve({
          error: 'invalid_grant',
          error_description: 'Invalid authorization code',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await expect(vercelProvider.exchangeCodeForToken('invalid-code', 'http://localhost:3000/callback'))
        .rejects.toThrow('Invalid authorization code');
    });
  });

  describe('getUser', () => {
    it('should fetch user info from OIDC userinfo endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          // OIDC userinfo response format
          sub: 'user-123',
          email: 'test@vercel.com',
          email_verified: true,
          name: 'Test User',
          preferred_username: 'testuser',
          picture: 'https://vercel.com/api/avatar/123',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const user = await vercelProvider.getUser('access-token');

      expect(user.id).toBe('user-123');
      expect(user.username).toBe('testuser');
      expect(user.email).toBe('test@vercel.com');

      // Should use the correct OIDC userinfo endpoint (not /v2/user)
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.vercel.com/login/oauth/userinfo',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer access-token',
          }),
        })
      );
    });

    it('should fallback to email or sub when preferred_username is missing', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          sub: 'user-456',
          email: 'fallback@vercel.com',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const user = await vercelProvider.getUser('access-token');

      expect(user.id).toBe('user-456');
      expect(user.username).toBe('fallback@vercel.com'); // Falls back to email
    });

    it('should fallback to sub when both preferred_username and email are missing', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          sub: 'user-789',
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const user = await vercelProvider.getUser('access-token');

      expect(user.id).toBe('user-789');
      expect(user.username).toBe('user-789'); // Falls back to sub
    });
  });

  describe('listProjects', () => {
    it('should list user projects', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          projects: [
            {
              id: 'prj_123',
              name: 'my-project',
              framework: 'nextjs',
              createdAt: Date.now(),
              link: { type: 'github', org: 'testuser', repo: 'my-repo' },
            },
            {
              id: 'prj_456',
              name: 'another-project',
              createdAt: Date.now(),
            },
          ],
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const projects = await vercelProvider.listProjects('access-token');

      expect(projects).toHaveLength(2);
      expect(projects[0].id).toBe('prj_123');
      expect(projects[0].linkedRepo).toBe('testuser/my-repo');
      expect(projects[1].linkedRepo).toBeUndefined();
    });

    it('should include teamId in query when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ projects: [] }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await vercelProvider.listProjects('access-token', 'team_123');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('teamId=team_123'),
        expect.any(Object)
      );
    });
  });

  describe('listEnvVars', () => {
    it('should list environment variables for target environment', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          envs: [
            { id: 'env1', key: 'API_KEY', value: 'secret', target: ['production'], type: 'encrypted', createdAt: Date.now(), updatedAt: Date.now() },
            { id: 'env2', key: 'DEBUG', value: 'true', target: ['development'], type: 'plain', createdAt: Date.now(), updatedAt: Date.now() },
            { id: 'env3', key: 'SHARED', value: 'shared', target: ['production', 'development'], type: 'plain', createdAt: Date.now(), updatedAt: Date.now() },
          ],
        }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const envVars = await vercelProvider.listEnvVars('access-token', 'prj_123', 'production');

      expect(envVars).toHaveLength(2);
      expect(envVars.map(e => e.key)).toEqual(['API_KEY', 'SHARED']);
    });
  });

  describe('setEnvVars', () => {
    it('should create new env vars', async () => {
      // First call: get existing env vars (empty)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ envs: [] }),
      });
      // Second call: create env var
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'env1', key: 'NEW_VAR' }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const result = await vercelProvider.setEnvVars('access-token', 'prj_123', 'production', {
        NEW_VAR: 'new-value',
      });

      expect(result.created).toBe(1);
      expect(result.updated).toBe(0);
    });

    it('should update existing env vars', async () => {
      // First call: get existing env vars
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          envs: [
            { id: 'env1', key: 'EXISTING_VAR', target: ['production'] },
          ],
        }),
      });
      // Second call: update env var
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'env1' }),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      const result = await vercelProvider.setEnvVars('access-token', 'prj_123', 'production', {
        EXISTING_VAR: 'updated-value',
      });

      expect(result.created).toBe(0);
      expect(result.updated).toBe(1);
    });
  });

  describe('deleteEnvVar', () => {
    it('should delete env var entirely when only one target', async () => {
      // Get existing env vars
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          envs: [
            { id: 'env1', key: 'TO_DELETE', target: ['production'] },
          ],
        }),
      });
      // Delete env var
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await vercelProvider.deleteEnvVar('access-token', 'prj_123', 'production', 'TO_DELETE');

      expect(mockFetch).toHaveBeenLastCalledWith(
        expect.stringContaining('/env/env1'),
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('should only remove target when env var has multiple targets', async () => {
      // Get existing env vars
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          envs: [
            { id: 'env1', key: 'MULTI_TARGET', target: ['production', 'preview'] },
          ],
        }),
      });
      // Patch to remove target
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await vercelProvider.deleteEnvVar('access-token', 'prj_123', 'production', 'MULTI_TARGET');

      expect(mockFetch).toHaveBeenLastCalledWith(
        expect.stringContaining('/env/env1'),
        expect.objectContaining({ method: 'PATCH' })
      );
    });
  });

  describe('error handling', () => {
    it('should handle rate limiting', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: {
          get: (name: string) => name === 'Retry-After' ? '60' : null,
        },
        json: () => Promise.resolve({}),
      });

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await expect(vercelProvider.getUser('access-token'))
        .rejects.toThrow(/rate limited/i);
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('fetch failed'));

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await expect(vercelProvider.getUser('access-token'))
        .rejects.toThrow(/network error/i);
    });

    it('should handle timeout', async () => {
      // Mock AbortError
      const abortError = new Error('Aborted');
      abortError.name = 'AbortError';
      mockFetch.mockRejectedValueOnce(abortError);

      const { vercelProvider } = await import('../src/services/providers/vercel.provider');

      await expect(vercelProvider.getUser('access-token'))
        .rejects.toThrow(/timed out/i);
    });
  });
});
