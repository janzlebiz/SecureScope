import assert from 'assert';
import crypto from 'crypto';
import { PolicyEngine } from '../src/server/services/policyEngine';
import { NormalizerAndCorrelator } from '../src/server/services/normalizer';
import { DbStore } from '../src/server/services/dbStore';

const BASE_URL = 'http://127.0.0.1:3000';

async function runTests() {
  console.log('========================================================================');
  console.log('       SECURESCOPE END-TO-END HTTP API ADVERSARIAL SECURITY SUITE       ');
  console.log('========================================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err: any) {
      console.error(`[FAIL] ${name}`);
      console.error(`       Error: ${err.message}`);
      if (err.stack) console.error(`       Stack: ${err.stack.split('\n')[1]}`);
      console.error('');
      failed++;
    }
  }

  // --- Dynamic Auth Helper ---
  async function login(email: string): Promise<string> {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' })
    });
    if (!res.ok) {
      throw new Error(`Login failed for ${email}: Status ${res.status}`);
    }
    const body = await res.json() as any;
    return body.token;
  }

  // ========================================================================
  // SS-01 & SS-07: AUTHENTICATION, RBAC & IDOR TEST CASES
  // ========================================================================

  await test('SS-01: Reject Unauthenticated Request with 401', async () => {
    const res = await fetch(`${BASE_URL}/api/projects`);
    assert.strictEqual(res.status, 401, 'Request without Authorization header must be rejected with 401');
    const body = await res.json() as any;
    assert.ok(body.error.includes('Missing or malformed Bearer Token'), 'Error body must state missing token');
  });

  await test('SS-01: Successful Dynamic Authentication & Profile Verification', async () => {
    const ownerToken = await login('alex.mercer@acme-fintech.com');
    assert.ok(ownerToken && ownerToken.startsWith('sess-'), 'Should yield randomized dynamic session token');

    const profileRes = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { 'Authorization': `Bearer ${ownerToken}` }
    });
    assert.strictEqual(profileRes.status, 200, 'Authenticated check must succeed with 200');
    const user = await profileRes.json() as any;
    assert.strictEqual(user.email, 'alex.mercer@acme-fintech.com', 'Returns correct profile details');
    assert.strictEqual(user.role, 'OWNER', 'Role should resolve to OWNER');
  });

  await test('SS-01: Enforce Strict IDOR Project Isolation', async () => {
    // Sarah Chen (ADMIN) should NOT be able to view pay portal project proj-fintech-core
    const adminToken = await login('sarah.chen@medicare-cloud.org');

    const idorRes = await fetch(`${BASE_URL}/api/projects/proj-fintech-core`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    // Should return 404/403 to prevent project existance leaks or access bypass
    assert.ok([403, 404].includes(idorRes.status), 'Cross-project access must fail with 403 or 404');
  });

  await test('SS-01: Enforce Strict Viewer Role Read-Only RBAC restrictions', async () => {
    const viewerToken = await login('viewer@secure.com');

    // Trying to start scan as Viewer must return 403
    const scanPayload = {
      projectId: 'proj-fintech-core',
      assetId: 'ast-fintech-web',
      profile: 'STANDARD',
      authorizationConfirmed: true,
      authorizationStatement: 'Viewer unauthorized run test'
    };

    const runRes = await fetch(`${BASE_URL}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${viewerToken}`
      },
      body: JSON.stringify(scanPayload)
    });
    assert.strictEqual(runRes.status, 403, 'Modify action by VIEWER must return 403 Forbidden');
    const body = await runRes.json() as any;
    assert.ok(body.error.includes('restricted to roles'), 'Must explicitly print role block description');
  });

  // ========================================================================
  // SS-02: SSRF & DNS RESOLUTION GATE TESTS
  // ========================================================================

  await test('SS-02: IP Blacklist Validation (SSRF Prevention API check)', async () => {
    // Standard block checklist
    const loopbackIps = ['127.0.0.1', '127.0.0.12', '127.5.5.5'];
    const privateIps = ['10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1'];
    const metadataIps = ['169.254.169.254'];
    const ipv6Unsafe = ['::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1'];

    for (const ip of [...loopbackIps, ...privateIps, ...metadataIps, ...ipv6Unsafe]) {
      assert.strictEqual(PolicyEngine.isIpUnsafe(ip), true, `IP ${ip} must be blocked by isIpUnsafe`);
    }

    // Standard permits checklist
    const publicIps = ['8.8.8.8', '1.1.1.1', '104.244.42.1'];
    for (const ip of publicIps) {
      assert.strictEqual(PolicyEngine.isIpUnsafe(ip), false, `Public IP ${ip} must be permitted by isIpUnsafe`);
    }
  });

  await test('SS-02: Block Loopback SSRF Scanning on Scan launch API', async () => {
    const ownerToken = await login('alex.mercer@acme-fintech.com');

    // Create a local loopback asset inside Project fintech-core
    const assetRes = await fetch(`${BASE_URL}/api/projects/proj-fintech-core/assets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`
      },
      body: JSON.stringify({
        name: 'Internal Server Target',
        type: 'WEB_URL',
        identifier: 'http://127.0.0.1:8000',
        environment: 'DEVELOPMENT',
        criticality: 'LOW'
      })
    });
    assert.strictEqual(assetRes.status, 201, 'Seeding target asset should succeed');
    const asset = await assetRes.json() as any;

    // Launch scan against seeded loopback asset
    const scanRes = await fetch(`${BASE_URL}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`
      },
      body: JSON.stringify({
        projectId: 'proj-fintech-core',
        assetId: asset.id,
        profile: 'STANDARD',
        authorizationConfirmed: true,
        authorizationStatement: 'Authorized E2E validation'
      })
    });
    assert.strictEqual(scanRes.status, 400, 'Scan against loopback IP must be denied by SSRF validator with 400');
    const scanBody = await scanRes.json() as any;
    assert.ok(scanBody.error.includes('blocked by scope policy'), 'Must report block in error message');
  });

  // ========================================================================
  // SS-03: DOMAIN SCOPE / SUFFIX BYPASS TESTS
  // ========================================================================

  await test('SS-03: Domain boundary Suffix Spoofing Checks', () => {
    const allowed = ['acme-fintech.com'];

    // Label checks
    assert.strictEqual(PolicyEngine.isDomainAllowed('malicious-acme-fintech.com', allowed), false, 'Suffix spoofing check must block lookalike suffixes');
    assert.strictEqual(PolicyEngine.isDomainAllowed('acme-fintech.com.attacker.example', allowed), false, 'Root domains in subdomains must be blocked');
    assert.strictEqual(PolicyEngine.isDomainAllowed('pay.acme-fintech.com', allowed), true, 'Canonical subdomain should match base allowed suffix');
  });

  // ========================================================================
  // SS-05: zod SCHEMA SCHEMAS VALIDATION TESTS
  // ========================================================================

  await test('SS-05: Input Zod Schema and Negative Constraints validation', async () => {
    const ownerToken = await login('alex.mercer@acme-fintech.com');

    // Missing assetId on scan creation should be blocked by Zod schemas
    const malformedScanRes = await fetch(`${BASE_URL}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`
      },
      body: JSON.stringify({
        projectId: 'proj-fintech-core',
        profile: 'STANDARD',
        authorizationConfirmed: true
      })
    });
    assert.strictEqual(malformedScanRes.status, 400, 'Malformed scan launch must be blocked by Zod validation with 400');
    const errBody = await malformedScanRes.json() as any;
    assert.strictEqual(errBody.error, 'Validation Error', 'Returns a schema validation error message');
  });

  // ========================================================================
  // SS-06: DETECT DETERMINISTIC COMPLETED SHA-256 HASH
  // ========================================================================

  await test('SS-06: Complete 64-char Cryptographic SHA-256 Digest Validation', () => {
    const fp = NormalizerAndCorrelator.generateFingerprint(
      'https://api.acme-fintech.com/v2',
      'CWE-89',
      'Injection',
      'src/controllers/userController.ts:48',
      'SQLi in search parameter'
    );

    assert.strictEqual(fp.startsWith('fp-'), true, 'Fingerprint must begin with fp-');
    // SHA-256 digest is exactly 64 hex characters. Combined with fp- prefix (3 chars), the total length must be 67!
    assert.strictEqual(fp.length, 67, 'Fingerprint must hold complete 64 hex character digest (total length 67)');
  });

  // ==========================================
  // FINAL TEST SUMMARIES
  // ==========================================
  console.log('\n========================================================================');
  console.log(` END-TO-END SUITE RUN COMPLETE: ${passed} PASSED | ${failed} FAILED`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal crash running test suite:', err);
  process.exit(1);
});
