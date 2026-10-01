import { Project, Asset, Scan, Finding, AuditEvent } from '../types/securescope';

export const INITIAL_PROJECTS: Project[] = [
  {
    id: 'proj-fintech-core',
    name: 'FinTech Payment Gateway',
    description: 'Core web portal, REST API endpoints, and mobile merchant app for processing card transactions.',
    ownerId: 'usr-1',
    ownerName: 'Alex Mercer (AppSec Lead)',
    scopePolicy: {
      allowedDomains: ['pay.acme-fintech.internal', 'api.acme-fintech.com', 'com.acmecorp.merchant'],
      excludedPaths: ['/api/v1/health', '/metrics'],
      allowPrivateIPs: true,
      maxRequestsPerSecond: 20,
      maxScanDurationMinutes: 60,
      allowedProfiles: ['SAFE_BASELINE', 'STANDARD', 'DEEP_AUTHORIZED']
    },
    createdAt: '2026-09-15T09:00:00Z',
    updatedAt: '2026-10-01T10:30:00Z'
  },
  {
    id: 'proj-healthtech-portal',
    name: 'MediCare Health Cloud',
    description: 'HIPAA-compliant web portal and mobile patient records viewer.',
    ownerId: 'usr-2',
    ownerName: 'Dr. Sarah Chen (Security Manager)',
    scopePolicy: {
      allowedDomains: ['portal.medicare-cloud.org', 'api.medicare-cloud.org'],
      excludedPaths: ['/logout'],
      allowPrivateIPs: false,
      maxRequestsPerSecond: 10,
      maxScanDurationMinutes: 30,
      allowedProfiles: ['SAFE_BASELINE', 'STANDARD']
    },
    createdAt: '2026-09-20T14:15:00Z',
    updatedAt: '2026-09-28T16:00:00Z'
  }
];

export const INITIAL_ASSETS: Asset[] = [
  {
    id: 'ast-fintech-web',
    projectId: 'proj-fintech-core',
    type: 'WEB_URL',
    name: 'Payment Web Portal',
    identifier: 'https://pay.acme-fintech.internal',
    environment: 'STAGING',
    criticality: 'CRITICAL',
    createdAt: '2026-09-15T09:30:00Z'
  },
  {
    id: 'ast-fintech-api',
    projectId: 'proj-fintech-core',
    type: 'API_ENDPOINT',
    name: 'Merchant REST API',
    identifier: 'https://api.acme-fintech.com/v2',
    environment: 'PRODUCTION',
    criticality: 'CRITICAL',
    createdAt: '2026-09-15T10:00:00Z'
  },
  {
    id: 'ast-fintech-apk',
    projectId: 'proj-fintech-core',
    type: 'MOBILE_PACKAGE',
    name: 'Merchant POS Android App',
    identifier: 'com.acmecorp.merchant.apk',
    environment: 'STAGING',
    criticality: 'HIGH',
    metadata: {
      fileSizeMb: 24.5,
      targetVersion: 'v2.4.1-rc3'
    },
    createdAt: '2026-09-18T11:20:00Z'
  },
  {
    id: 'ast-fintech-repo',
    projectId: 'proj-fintech-core',
    type: 'SOURCE_REPO',
    name: 'Payment Backend Repository',
    identifier: 'https://github.com/acme-fintech/payment-service.git',
    environment: 'DEVELOPMENT',
    criticality: 'CRITICAL',
    createdAt: '2026-09-22T08:00:00Z'
  }
];

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: 'fnd-101',
    fingerprint: 'fp-sqli-01',
    scanId: 'scn-1001',
    projectId: 'proj-fintech-core',
    assetId: 'ast-fintech-repo',
    assetIdentifier: 'https://github.com/acme-fintech/payment-service.git',
    title: 'Potential SQL Injection via Unescaped String Concatenation',
    description: 'Raw SQL query string constructed using unescaped dynamic variable concatenation instead of parameterized prepared statements.',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Static Code Analysis (SAST)',
    status: 'OPEN',
    cwe: 'CWE-89',
    cve: 'CVE-2023-SQLI-01',
    cvssScore: 8.8,
    owaspTop10: 'A03:2021-Injection',
    owaspWstg: 'WSTG-INPV-05',
    affectedLocation: 'src/controllers/userController.ts:48',
    remediation: 'Use parameterized queries or ORM prepared statements (e.g., Prisma, Drizzle, or Knex).',
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
    occurrences: [
      {
        scannerId: 'semgrep',
        scannerName: 'Semgrep SAST',
        scannerVersion: '1.68.0',
        rawFindingId: 'semgrep-sqli-raw-query',
        detectedAt: '2026-10-01T09:15:00Z',
        evidence: {
          type: 'source',
          filePath: 'src/controllers/userController.ts',
          startLine: 48,
          endLine: 50,
          codeSnippet: 'const query = "SELECT * FROM users WHERE email = \'" + req.body.email + "\'";\nconst result = await db.query(query);',
          ruleId: 'typescript.express.security.audit.sqli'
        }
      }
    ],
    firstSeen: '2026-10-01T09:15:00Z',
    lastSeen: '2026-10-01T09:15:00Z'
  },
  {
    id: 'fnd-102',
    fingerprint: 'fp-clickjacking-01',
    scanId: 'scn-1002',
    projectId: 'proj-fintech-core',
    assetId: 'ast-fintech-web',
    assetIdentifier: 'https://pay.acme-fintech.internal',
    title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
    description: 'The response does not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, allowing the page to be rendered within an iframe.',
    severity: 'MEDIUM',
    confidence: 'VERIFIED',
    category: 'Web Security Headers',
    status: 'OPEN',
    cwe: 'CWE-1021',
    owaspTop10: 'A05:2021-Security Misconfiguration',
    owaspWstg: 'WSTG-CLNT-09',
    affectedLocation: 'https://pay.acme-fintech.internal/',
    remediation: 'Configure X-Frame-Options: DENY or SAMEORIGIN in reverse proxy or web application middleware.',
    references: ['https://owasp.org/www-community/attacks/Clickjacking'],
    occurrences: [
      {
        scannerId: 'zap',
        scannerName: 'OWASP ZAP',
        scannerVersion: '2.14.0',
        rawFindingId: 'zap-10020',
        detectedAt: '2026-10-01T09:30:00Z',
        evidence: {
          type: 'http',
          location: 'https://pay.acme-fintech.internal/',
          method: 'GET',
          statusCode: 200,
          responseHeaders: {
            'content-type': 'text/html; charset=utf-8',
            'server': 'nginx/1.24.0'
          }
        }
      }
    ],
    firstSeen: '2026-10-01T09:30:00Z',
    lastSeen: '2026-10-01T09:30:00Z'
  },
  {
    id: 'fnd-103',
    fingerprint: 'fp-backup-01',
    scanId: 'scn-1003',
    projectId: 'proj-fintech-core',
    assetId: 'ast-fintech-apk',
    assetIdentifier: 'com.acmecorp.merchant.apk',
    title: 'Android Backup Allowed (android:allowBackup=true)',
    description: 'The mobile app permits ADB backup operations, allowing arbitrary backup data extraction on unlocked hardware.',
    severity: 'HIGH',
    confidence: 'VERIFIED',
    category: 'Mobile Storage Security',
    status: 'CONFIRMED',
    cwe: 'CWE-538',
    owaspMasvs: 'MASVS-STORAGE-1 (Data Protection)',
    affectedLocation: 'AndroidManifest.xml',
    remediation: 'Set `android:allowBackup="false"` in AndroidManifest.xml.',
    references: ['https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0004/'],
    occurrences: [
      {
        scannerId: 'mobsf',
        scannerName: 'OWASP MobSF',
        scannerVersion: '3.8.0',
        rawFindingId: 'mobsf-android-allow-backup',
        detectedAt: '2026-10-01T10:00:00Z',
        evidence: {
          type: 'mobile',
          component: 'AndroidManifest.xml',
          issueDescription: 'android:allowBackup attribute is set to true in application manifest.'
        }
      }
    ],
    firstSeen: '2026-10-01T10:00:00Z',
    lastSeen: '2026-10-01T10:00:00Z'
  }
];

export const INITIAL_SCANS: Scan[] = [
  {
    id: 'scn-1001',
    projectId: 'proj-fintech-core',
    assetId: 'ast-fintech-repo',
    assetName: 'Payment Backend Repository',
    assetIdentifier: 'https://github.com/acme-fintech/payment-service.git',
    assetType: 'SOURCE_REPO',
    profile: 'STANDARD',
    status: 'COMPLETED',
    initiatedBy: 'usr-1',
    initiatedByName: 'Alex Mercer',
    authorizationConfirmedAt: '2026-10-01T09:00:00Z',
    authorizationStatement: 'I confirm that I am the authorized owner or authorized security analyst for this target repository.',
    startedAt: '2026-10-01T09:10:00Z',
    completedAt: '2026-10-01T09:15:00Z',
    durationSeconds: 300,
    jobs: [
      {
        id: 'job-1',
        scanId: 'scn-1001',
        scannerId: 'semgrep',
        scannerName: 'Semgrep SAST',
        status: 'COMPLETED',
        startedAt: '2026-10-01T09:10:00Z',
        completedAt: '2026-10-01T09:13:00Z',
        findingsCount: 1,
        logs: ['[Semgrep SAST] Scanning 84 source files...', '[Semgrep SAST] 1 SQLi rule match found.']
      },
      {
        id: 'job-2',
        scanId: 'scn-1001',
        scannerId: 'trivy',
        scannerName: 'Aqua Security Trivy',
        status: 'COMPLETED',
        startedAt: '2026-10-01T09:13:00Z',
        completedAt: '2026-10-01T09:15:00Z',
        findingsCount: 0,
        logs: ['[Trivy SCA] Auditing package-lock.json...', '[Trivy SCA] Clean.']
      }
    ],
    findingsSummary: {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 1
    }
  }
];

export const INITIAL_AUDIT_LOGS: AuditEvent[] = [
  {
    id: 'aud-1',
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'AUTHORIZATION_CONFIRMED',
    resourceType: 'ASSET',
    resourceId: 'ast-fintech-repo',
    details: 'User acknowledged ownership and legal testing authorization for target https://github.com/acme-fintech/payment-service.git',
    timestamp: '2026-10-01T09:00:00Z'
  },
  {
    id: 'aud-2',
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'SCAN_STARTED',
    resourceType: 'SCAN',
    resourceId: 'scn-1001',
    details: 'Initiated STANDARD scan profile against Payment Backend Repository with Semgrep and Trivy adapters.',
    timestamp: '2026-10-01T09:10:00Z'
  }
];
