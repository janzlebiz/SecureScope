import assert from 'assert';
import crypto from 'crypto';
import { PolicyEngine } from '../src/server/services/policyEngine';
import { NormalizerAndCorrelator } from '../src/server/services/normalizer';
import { DbStore, hashPassword } from '../src/server/services/dbStore';

async function runTests() {
  console.log('====================================================');
  console.log(' SECURESCOPE ADVERSARIAL SECURITY INTEGRATION TESTS ');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name: string, fn: () => any) {
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err: any) {
      console.error(`[FAIL] ${name}`);
      console.error(`       Error: ${err.message}\n`);
      failed++;
    }
  }

  function testAsync(name: string, fn: () => Promise<any>) {
    return fn()
      .then(() => {
        console.log(`[PASS] ${name}`);
        passed++;
      })
      .catch((err: any) => {
        console.error(`[FAIL] ${name}`);
        console.error(`       Error: ${err.message}\n`);
        failed++;
      });
  }

  // ==========================================
  // SS-01 & SS-07: AUTHENTICATION, RBAC & IDOR
  // ==========================================
  
  test('SS-01/07: Local Password Hashing & Database Seed Check', () => {
    const rawPass = 'Password123!';
    const hashed = hashPassword(rawPass);
    assert.ok(hashed && hashed.length > 30, 'Password should be cryptographically hashed');

    // Retrieve seeded users
    const owner = DbStore.getUserByEmail('alex.mercer@acme-fintech.com');
    assert.strictEqual(owner?.role, 'OWNER', 'Owner role should be seeded correctly');
    assert.strictEqual(owner?.passwordHash, hashed, 'Seeded user password hashes should match standard seed');

    const admin = DbStore.getUserByEmail('sarah.chen@medicare-cloud.org');
    assert.strictEqual(admin?.role, 'ADMIN', 'Admin role should be seeded correctly');
  });

  // ==========================================
  // SS-02: SSRF & IP BLACKLIST VALIDATION
  // ==========================================

  test('SS-02: IP Blacklist Validation (SSRF Prevention)', () => {
    // Unsafe IPv4 check
    assert.strictEqual(PolicyEngine.isIpUnsafe('127.0.0.1'), true, 'Loopback IPv4 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('10.0.0.1'), true, 'Private Class A IPv4 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('172.16.5.2'), true, 'Private Class B IPv4 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('192.168.1.100'), true, 'Private Class C IPv4 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('169.254.169.254'), true, 'Metadata IPv4 must be blocked');
    
    // Unsafe IPv6 check
    assert.strictEqual(PolicyEngine.isIpUnsafe('::1'), true, 'IPv6 loopback must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('fc00::1'), true, 'ULA IPv6 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('fd12:3456::7890'), true, 'ULA IPv6 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('fe80::1'), true, 'Link-local IPv6 must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('::ffff:127.0.0.1'), true, 'IPv4-mapped IPv6 loopback must be blocked');
    assert.strictEqual(PolicyEngine.isIpUnsafe('::ffff:10.0.0.5'), true, 'IPv4-mapped IPv6 private IP must be blocked');

    // Safe IP check
    assert.strictEqual(PolicyEngine.isIpUnsafe('8.8.8.8'), false, 'Public DNS IPv4 must be permitted');
    assert.strictEqual(PolicyEngine.isIpUnsafe('2607:f8b0:4005:805::200e'), false, 'Public IPv6 must be permitted');
  });

  await testAsync('SS-02: Active DNS Resolution SSRF Target Block', async () => {
    const policy = {
      allowedDomains: ['localhost', '127.0.0.1'],
      excludedPaths: [],
      allowPrivateIPs: false,
      maxRequestsPerSecond: 10,
      maxScanDurationMinutes: 30,
      allowedProfiles: ['SAFE_BASELINE', 'STANDARD']
    };

    // DNS Resolution check of localhost triggers SSRF block
    const decision = await PolicyEngine.evaluateTarget('http://localhost', 'WEB_URL', 'STANDARD', policy, true);
    assert.strictEqual(decision.allowed, false, 'Localhost target evaluation must be denied');
    assert.ok(decision.reasons.some(r => r.includes('SSRF Violation')), 'Decision reasons must declare SSRF block violation');
  });

  // ==========================================
  // SS-03: DOMAIN SCOPE & WILDCARDS BYPASS
  // ==========================================

  test('SS-03: Label-Boundary Suffix Spoofing Protection', () => {
    const allowed = ['acme-fintech.com', '*.medicare-cloud.org'];

    // Suffix spoofing block
    assert.strictEqual(PolicyEngine.isDomainAllowed('malicious-acme-fintech.com', allowed), false, 'Suffix matching bypass must be blocked');
    assert.strictEqual(PolicyEngine.isDomainAllowed('acme-fintech.com.evil.com', allowed), false, 'Subdomain spoofing with allowed root suffix must be blocked');
    assert.strictEqual(PolicyEngine.isDomainAllowed('evilacme-fintech.com', allowed), false, 'Prefix spoofing must be blocked');

    // Strict subdomains wildcard check
    assert.strictEqual(PolicyEngine.isDomainAllowed('medicare-cloud.org', allowed), false, 'Wildcard *.medicare-cloud.org must NOT match base domain medicare-cloud.org');
    assert.strictEqual(PolicyEngine.isDomainAllowed('api.medicare-cloud.org', allowed), true, 'Wildcard *.medicare-cloud.org must match standard subdomain');
    assert.strictEqual(PolicyEngine.isDomainAllowed('nested.api.medicare-cloud.org', allowed), true, 'Wildcard *.medicare-cloud.org must match deeply nested subdomains');

    // Fail closed on empty list
    assert.strictEqual(PolicyEngine.isDomainAllowed('acme-fintech.com', []), false, 'Empty allowlist must fail-closed');
  });

  // ==========================================
  // SS-06: DETECT DETERMINISTIC SHA-256 FINGERPRINT
  // ==========================================

  test('SS-06: Cryptographic SHA-256 Fingerprint Deduplication', () => {
    const fp1 = NormalizerAndCorrelator.generateFingerprint(
      'https://api.acme-fintech.com/v2',
      'CWE-89',
      'Injection',
      'src/controllers/userController.ts:48',
      'SQLi in search parameter'
    );

    const fp2 = NormalizerAndCorrelator.generateFingerprint(
      'https://api.acme-fintech.com/v2',
      'CWE-89',
      'Injection',
      'src/controllers/userController.ts:48',
      'SQLi in search parameter'
    );

    const fpDifferent = NormalizerAndCorrelator.generateFingerprint(
      'https://api.acme-fintech.com/v2',
      'CWE-79',
      'XSS',
      'src/controllers/userController.ts:48',
      'XSS in query parameter'
    );

    assert.strictEqual(fp1.startsWith('fp-'), true, 'Fingerprint must begin with standard fp- prefix');
    assert.strictEqual(fp1.length, 19, 'Fingerprint hash length must match 3-char prefix + 16 hex SHA-256 chars');
    assert.strictEqual(fp1, fp2, 'Identical findings must resolve to the exact same cryptographic fingerprint');
    assert.notStrictEqual(fp1, fpDifferent, 'Varying vulnerability parameters must resolve to different fingerprints');
  });

  // ==========================================
  // FINAL VERIFICATION
  // ==========================================
  console.log('\n====================================================');
  console.log(` TESTS RUN COMPLETE: ${passed} PASSED | ${failed} FAILED`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
