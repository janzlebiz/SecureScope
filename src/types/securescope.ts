export type AssetType = 'WEB_URL' | 'API_ENDPOINT' | 'MOBILE_PACKAGE' | 'SOURCE_REPO';
export type Environment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type ScanProfile = 'SAFE_BASELINE' | 'STANDARD' | 'DEEP_AUTHORIZED';
export type ScanStatus = 
  | 'QUEUED'
  | 'VALIDATING'
  | 'RUNNING'
  | 'PARTIALLY_COMPLETE'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'BLOCKED_BY_POLICY';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingConfidence = 'VERIFIED' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'REMEDIATED';

export type UserRole = 'OWNER' | 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarUrl?: string;
  passwordHash?: string;
}

export interface ScopePolicy {
  allowedDomains: string[];
  excludedPaths: string[];
  allowPrivateIPs: boolean;
  maxRequestsPerSecond: number;
  maxScanDurationMinutes: number;
  allowedProfiles: ScanProfile[];
}

export interface Project {
  id: string;
  name: string;
  description: string;
  ownerId: string;
  ownerName: string;
  scopePolicy: ScopePolicy;
  createdAt: string;
  updatedAt: string;
}

export interface Asset {
  id: string;
  projectId: string;
  type: AssetType;
  name: string;
  identifier: string; // URL, domain, package name, git repo
  environment: Environment;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  metadata?: {
    fileSizeMb?: number;
    fileHash?: string;
    targetVersion?: string;
    openApiUrl?: string;
    authType?: 'NONE' | 'BEARER' | 'COOKIE' | 'API_KEY';
  };
  createdAt: string;
}

export interface PolicyDecision {
  allowed: boolean;
  reasons: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'PROHIBITED';
  targetNormalized: string;
  ipAddressesResolved?: string[];
  isPrivateOrLoopback?: boolean;
}

export interface ScanJob {
  id: string;
  scanId: string;
  scannerId: string;
  scannerName: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  startedAt?: string;
  completedAt?: string;
  exitCode?: number;
  findingsCount: number;
  errorSummary?: string;
  logs: string[];
}

export interface Scan {
  id: string;
  projectId: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: AssetType;
  profile: ScanProfile;
  status: ScanStatus;
  initiatedBy: string;
  initiatedByName: string;
  authorizationConfirmedAt: string;
  authorizationStatement: string;
  startedAt: string;
  completedAt?: string;
  durationSeconds?: number;
  jobs: ScanJob[];
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

export interface EvidenceHttp {
  type: 'http';
  location: string;
  method?: string;
  statusCode?: number;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBodyExcerpt?: string;
  redactions?: string[];
}

export interface EvidenceSource {
  type: 'source';
  filePath: string;
  startLine: number;
  endLine?: number;
  codeSnippet: string;
  ruleId?: string;
}

export interface EvidenceMobile {
  type: 'mobile';
  component: string;
  permission?: string;
  decompiledClass?: string;
  issueDescription: string;
}

export type Evidence = EvidenceHttp | EvidenceSource | EvidenceMobile;

export interface FindingOccurrence {
  scannerId: string;
  scannerName: string;
  scannerVersion: string;
  rawFindingId: string;
  detectedAt: string;
  evidence: Evidence;
}

export interface Finding {
  id: string;
  fingerprint: string;
  scanId: string;
  projectId: string;
  assetId: string;
  assetIdentifier: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: string;
  status: FindingStatus;
  cwe?: string;
  cve?: string;
  cvssScore?: number;
  owaspTop10?: string;
  owaspWstg?: string;
  owaspMasvs?: string;
  owaspAsvs?: string;
  affectedLocation: string;
  remediation: string;
  references: string[];
  occurrences: FindingOccurrence[];
  firstSeen: string;
  lastSeen: string;
  aiAnalysis?: {
    summary: string;
    businessImpact: string;
    remediationCodeSnippet?: string;
    verificationSteps: string[];
    analyzedAt: string;
  };
}

export interface ScannerRegistryEntry {
  id: string;
  name: string;
  category: string;
  version: string;
  license: string;
  capabilities: string[];
  containerImage: string;
  isolationMode: string;
  status: 'ACTIVE' | 'OPTIONAL' | 'DISABLED';
  notes: string;
  enabledByDefault: boolean;
}

export interface AuditEvent {
  id: string;
  actorName: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId: string;
  details: string;
  timestamp: string;
}

export interface ReportModel {
  title: string;
  generatedAt: string;
  projectId: string;
  projectName: string;
  scanId: string;
  scanProfile: ScanProfile;
  assetName: string;
  assetIdentifier: string;
  executiveSummary: string;
  findings: Finding[];
  scannersUsed: { name: string; version: string }[];
  limitations: string;
  scopeConfirmedBy: string;
}
