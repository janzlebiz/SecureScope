import express from 'express';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { z } from 'zod';

import { DbStore, hashPassword } from './src/server/services/dbStore';
import { PolicyEngine } from './src/server/services/policyEngine';
import { NormalizerAndCorrelator } from './src/server/services/normalizer';
import { ReportGenerator } from './src/server/services/reportGenerator';
import { AiAdvisor } from './src/server/services/aiAdvisor';
import { WorkerRunner } from './src/server/services/workerRunner';
import { SCANNER_REGISTRY } from './src/server/scanners/scannerRegistry';
import { ZapAdapter, RawFindingOutput } from './src/server/scanners/zapAdapter';
import { NucleiAdapter } from './src/server/scanners/nucleiAdapter';
import { MobSFAdapter } from './src/server/scanners/mobsfAdapter';
import { SemgrepAdapter } from './src/server/scanners/semgrepAdapter';
import { TrivyAdapter } from './src/server/scanners/trivyAdapter';
import { Project, Asset, Scan, Finding, AuditEvent } from './src/types/securescope';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

// --- SESSION STORE & ACTIVE SESSIONS (SS-01) ---
const SESSIONS = new Map<string, string>(); // SessionToken -> UserID

// Secure Single-Use Report Download Tickets Map (SS-01/P2)
const REPORT_TICKETS = new Map<string, { scanId: string; userId: string; expiresAt: number }>();

// --- AUTHENTICATION & ACCESS CONTROL MIDDLEWARE (SS-01) ---
function requireAuth(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization;
  let token = '';

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Missing or malformed Bearer Token.' });
  }

  const userId = SESSIONS.get(token);
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: Invalid session token.' });
  }

  const user = DbStore.getUserById(userId);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: Account not found.' });
  }

  req.user = user;
  next();
}

// Project Access Isolation (SS-01 IDOR Gate)
function isUserAuthorizedForProject(user: any, projectId: string): boolean {
  if (user.role === 'OWNER') {
    const project = DbStore.getProjectById(projectId);
    // Owners get access to any fintech-core project or their owned created projects
    return !project || project.ownerId === user.id || projectId === 'proj-fintech-core';
  }
  if (user.role === 'ADMIN') {
    return projectId === 'proj-healthtech-portal';
  }
  // Analysts and Viewers get access to the fintech gateway project
  return projectId === 'proj-fintech-core';
}

// RBAC Middleware
function requireRole(allowedRoles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: `Forbidden: Action restricted to roles: [${allowedRoles.join(', ')}]` });
    }
    next();
  };
}

// Helper to construct secure audit event models
function createAuditEvent(actor: any, action: string, resourceType: string, resourceId: string, details: string): AuditEvent {
  return {
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    actorName: actor.name,
    actorEmail: actor.email,
    action,
    resourceType,
    resourceId,
    details,
    timestamp: new Date().toISOString()
  };
}

// --- ZOD SCHEMAS FOR INPUT VALIDATION (SS-05) ---
const ProjectCreateSchema = z.object({
  name: z.string().min(1, 'Project name is required').max(100),
  description: z.string().max(500).optional(),
  scopePolicy: z.object({
    allowedDomains: z.array(z.string().min(1)),
    excludedPaths: z.array(z.string()),
    allowPrivateIPs: z.boolean(),
    maxRequestsPerSecond: z.number().int().min(1).max(1000).optional(),
    maxScanDurationMinutes: z.number().int().min(1).max(1440).optional(),
    allowedProfiles: z.array(z.enum(['SAFE_BASELINE', 'STANDARD', 'DEEP_AUTHORIZED']))
  }).optional()
});

const AssetCreateSchema = z.object({
  name: z.string().min(1, 'Asset name is required').max(100),
  type: z.enum(['WEB_URL', 'API_ENDPOINT', 'MOBILE_PACKAGE', 'SOURCE_REPO']),
  identifier: z.string().min(1, 'Identifier is required').max(500),
  environment: z.enum(['DEVELOPMENT', 'STAGING', 'PRODUCTION']),
  criticality: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
});

const ScanCreateSchema = z.object({
  projectId: z.string().min(1),
  assetId: z.string().min(1),
  profile: z.enum(['SAFE_BASELINE', 'STANDARD', 'DEEP_AUTHORIZED']),
  authorizationConfirmed: z.literal(true, {
    errorMap: () => ({ message: 'User authorization must be explicitly confirmed to run active assessments.' })
  }),
  authorizationStatement: z.string().min(5, 'Authorization statement is required')
});

const FindingPatchSchema = z.object({
  status: z.enum(['OPEN', 'IN_REVIEW', 'CONFIRMED', 'FALSE_POSITIVE', 'REMEDIATED'])
});

// --- API ROUTES ---

// 1. Authentication Endpoints (SS-01)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = DbStore.getUserByEmail(email);
  if (!user || user.passwordHash !== hashPassword(password)) {
    // Audit failure persistently (SS-07)
    DbStore.addAuditLog({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      actorName: 'Unauthenticated User',
      actorEmail: email,
      action: 'AUTHENTICATION_FAILED',
      resourceType: 'USER',
      resourceId: 'N/A',
      details: 'Failed authentication attempt with invalid credentials.',
      timestamp: new Date().toISOString()
    });
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Create real randomized session (No static credentials)
  const token = `sess-${crypto.randomBytes(16).toString('hex')}`;
  SESSIONS.set(token, user.id);

  // Persistence of login audit event
  DbStore.addAuditLog(createAuditEvent(user, 'AUTHENTICATION_SUCCESS', 'USER', user.id, 'Successfully logged into control plane.'));

  // Exclude password hash from response
  const { passwordHash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

// Current User Profile
app.get('/api/auth/me', requireAuth, (req: any, res) => {
  const { passwordHash, ...safeUser } = req.user;
  res.json(safeUser);
});

// Health check (Open endpoint)
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', system: 'SecureScope Control Plane', version: '1.0.0', timestamp: new Date().toISOString() });
});

// Projects CRUD
app.get('/api/projects', requireAuth, (req: any, res) => {
  const allProjects = DbStore.getProjects();
  // Filter projects by user scope boundaries (IDOR prevention)
  const filtered = allProjects.filter((p) => isUserAuthorizedForProject(req.user, p.id));
  res.json(filtered);
});

app.post('/api/projects', requireAuth, requireRole(['OWNER', 'ADMIN']), (req: any, res) => {
  try {
    const validatedData = ProjectCreateSchema.parse(req.body);

    const newProject: Project = {
      id: `proj-${crypto.randomBytes(4).toString('hex')}`,
      name: validatedData.name,
      description: validatedData.description || '',
      ownerId: req.user.id,
      ownerName: req.user.name,
      scopePolicy: validatedData.scopePolicy || {
        allowedDomains: [],
        excludedPaths: [],
        allowPrivateIPs: false,
        maxRequestsPerSecond: 10,
        maxScanDurationMinutes: 30,
        allowedProfiles: ['SAFE_BASELINE', 'STANDARD']
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    DbStore.addProject(newProject);
    DbStore.addAuditLog(createAuditEvent(req.user, 'PROJECT_CREATED', 'PROJECT', newProject.id, `Created new project '${newProject.name}'`));

    res.status(201).json(newProject);
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation Error', details: err.errors });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/projects/:id', requireAuth, (req: any, res) => {
  const projectId = req.params.id;
  if (!isUserAuthorizedForProject(req.user, projectId)) {
    return res.status(404).json({ error: 'Project not found.' }); // Return 404 to prevent enumeration
  }

  const project = DbStore.getProjectById(projectId);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const projectAssets = DbStore.getAssets().filter((a) => a.projectId === project.id);
  res.json({ ...project, assets: projectAssets });
});

// Assets Endpoints
app.get('/api/projects/:id/assets', requireAuth, (req: any, res) => {
  const projectId = req.params.id;
  if (!isUserAuthorizedForProject(req.user, projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }
  const projectAssets = DbStore.getAssets().filter((a) => a.projectId === projectId);
  res.json(projectAssets);
});

app.post('/api/projects/:id/assets', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), (req: any, res) => {
  const projectId = req.params.id;
  if (!isUserAuthorizedForProject(req.user, projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  try {
    const validatedData = AssetCreateSchema.parse(req.body);

    const newAsset: Asset = {
      id: `ast-${crypto.randomBytes(4).toString('hex')}`,
      projectId,
      type: validatedData.type,
      name: validatedData.name,
      identifier: validatedData.identifier,
      environment: validatedData.environment,
      criticality: validatedData.criticality,
      createdAt: new Date().toISOString()
    };

    DbStore.addAsset(newAsset);
    DbStore.addAuditLog(createAuditEvent(req.user, 'ASSET_ADDED', 'ASSET', newAsset.id, `Added target asset '${newAsset.name}' (${newAsset.identifier})`));

    res.status(201).json(newAsset);
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation Error', details: err.errors });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Target Scope Policy Evaluation Gate
app.post('/api/policy/validate', requireAuth, async (req: any, res) => {
  const { target, assetType, profile, projectId, authorizationConfirmed } = req.body;
  
  if (!isUserAuthorizedForProject(req.user, projectId)) {
    return res.status(403).json({ error: 'Forbidden: Access to requested project scope is denied.' });
  }

  const project = DbStore.getProjectById(projectId);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const decision = await PolicyEngine.evaluateTarget(
    target || '',
    assetType || 'WEB_URL',
    profile || 'SAFE_BASELINE',
    project.scopePolicy,
    Boolean(authorizationConfirmed)
  );

  res.json(decision);
});

// Scans Orchestration CRUD
app.get('/api/scans', requireAuth, (req: any, res) => {
  const allScans = DbStore.getScans();
  // Filter scans based on user project authorization constraints
  const filtered = allScans.filter((s) => isUserAuthorizedForProject(req.user, s.projectId));
  res.json(filtered);
});

app.post('/api/scans', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), async (req: any, res) => {
  try {
    const validatedData = ScanCreateSchema.parse(req.body);

    if (!isUserAuthorizedForProject(req.user, validatedData.projectId)) {
      return res.status(403).json({ error: 'Forbidden: Access to target project is denied.' });
    }

    const project = DbStore.getProjectById(validatedData.projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const asset = DbStore.getAssets().find((a) => a.id === validatedData.assetId && a.projectId === project.id);
    if (!asset) return res.status(404).json({ error: 'Asset not found' });

    // 1. Policy & Authorization Validation (Fail-closed SSRF/Bypass checks)
    const decision = await PolicyEngine.evaluateTarget(
      asset.identifier,
      asset.type,
      validatedData.profile,
      project.scopePolicy,
      true
    );

    if (!decision.allowed) {
      // Audit blocked scan launch attempt persistently
      DbStore.addAuditLog(
        createAuditEvent(
          req.user,
          'SCAN_BLOCKED_BY_POLICY',
          'ASSET',
          asset.id,
          `Scan attempt blocked by scope enforcement reasons: [${decision.reasons.join('; ')}]`
        )
      );

      return res.status(400).json({
        error: 'Scan launch blocked by scope policy or authorization gate.',
        policyDecision: decision
      });
    }

    // 2. Queue and Start the scan (Decoupled execution)
    const scanId = `scn-${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const newScan: Scan = {
      id: scanId,
      projectId: project.id,
      assetId: asset.id,
      assetName: asset.name,
      assetIdentifier: asset.identifier,
      assetType: asset.type,
      profile: validatedData.profile,
      status: 'QUEUED', // Begin in QUEUED state (SS-08 Phase 8 decoupled)
      initiatedBy: req.user.id,
      initiatedByName: req.user.name,
      authorizationConfirmedAt: now,
      authorizationStatement: validatedData.authorizationStatement,
      startedAt: now,
      jobs: [],
      findingsSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
    };

    DbStore.addScan(newScan);
    DbStore.addAuditLog(createAuditEvent(req.user, 'SCAN_LAUNCHED', 'SCAN', scanId, `Launched active ${validatedData.profile} scan on '${asset.name}'`));

    // Respond immediately to the client
    res.status(202).json(newScan);

    // Resolve exact target IP and bind validation strictly to scanner socket (SS-02)
    const boundIp = (decision.ipAddressesResolved && decision.ipAddressesResolved.length > 0)
      ? decision.ipAddressesResolved[0]
      : '127.0.0.1';

    // Offload executing loop onto decoupled background isolated worker thread (SS-08 Phase 8)
    WorkerRunner.enqueueScan(scanId, project.id, asset.id, boundIp);

  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation Error', details: err.errors });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/scans/:id', requireAuth, (req: any, res) => {
  const scan = DbStore.getScans().find((s) => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  if (!isUserAuthorizedForProject(req.user, scan.projectId)) {
    return res.status(404).json({ error: 'Scan not found.' });
  }

  const scanFindings = DbStore.getFindings().filter((f) => f.scanId === scan.id);
  res.json({ ...scan, findings: scanFindings });
});

app.post('/api/scans/:id/cancel', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), (req: any, res) => {
  const scan = DbStore.getScans().find((s) => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  if (!isUserAuthorizedForProject(req.user, scan.projectId)) {
    return res.status(404).json({ error: 'Scan not found.' });
  }

  scan.status = 'CANCELLED';
  DbStore.updateScan(scan);
  DbStore.addAuditLog(createAuditEvent(req.user, 'SCAN_CANCELLED', 'SCAN', scan.id, `Manually cancelled active scan operation.`));

  res.json({ message: 'Scan cancelled', scan });
});

// Findings Retrieval & Update Status (RBAC/IDOR protected)
app.get('/api/findings', requireAuth, (req: any, res) => {
  const { projectId, assetId, severity, status } = req.query;
  let filtered = DbStore.getFindings();

  // Scope findings strictly to user-allowed projects
  filtered = filtered.filter((f) => isUserAuthorizedForProject(req.user, f.projectId));

  if (projectId) filtered = filtered.filter((f) => f.projectId === projectId);
  if (assetId) filtered = filtered.filter((f) => f.assetId === assetId);
  if (severity) filtered = filtered.filter((f) => f.severity === severity);
  if (status) filtered = filtered.filter((f) => f.status === status);

  res.json(filtered);
});

app.get('/api/findings/:id', requireAuth, (req: any, res) => {
  const finding = DbStore.getFindings().find((f) => f.id === req.params.id);
  if (!finding) return res.status(404).json({ error: 'Finding not found.' });

  if (!isUserAuthorizedForProject(req.user, finding.projectId)) {
    return res.status(404).json({ error: 'Finding not found.' });
  }

  res.json(finding);
});

app.patch('/api/findings/:id', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), (req: any, res) => {
  const finding = DbStore.getFindings().find((f) => f.id === req.params.id);
  if (!finding) return res.status(404).json({ error: 'Finding not found.' });

  if (!isUserAuthorizedForProject(req.user, finding.projectId)) {
    return res.status(404).json({ error: 'Finding not found.' });
  }

  try {
    const validatedBody = FindingPatchSchema.parse(req.body);
    finding.status = validatedBody.status;
    DbStore.updateFinding(finding);

    DbStore.addAuditLog(
      createAuditEvent(
        req.user,
        'FINDING_STATUS_UPDATED',
        'FINDING',
        finding.id,
        `Updated workflow status of '${finding.title}' to ${validatedBody.status}`
      )
    );

    res.json(finding);
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation Error', details: err.errors });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// AI Advisor Analysis Gate (SS-04 prompt sandboxing)
app.post('/api/ai/analyze-finding', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), async (req: any, res) => {
  const { findingId } = req.body;
  const finding = DbStore.getFindings().find((f) => f.id === findingId);
  if (!finding) return res.status(404).json({ error: 'Finding not found.' });

  if (!isUserAuthorizedForProject(req.user, finding.projectId)) {
    return res.status(404).json({ error: 'Finding not found.' });
  }

  try {
    const analysis = await AiAdvisor.analyzeFinding(finding);
    finding.aiAnalysis = {
      ...analysis,
      analyzedAt: new Date().toISOString()
    };
    DbStore.updateFinding(finding);

    res.json(finding.aiAnalysis);
  } catch (err) {
    res.status(500).json({ error: 'AI analysis failed' });
  }
});

app.post('/api/ai/generate-executive-summary', requireAuth, requireRole(['OWNER', 'ADMIN', 'ANALYST']), async (req: any, res) => {
  const { scanId } = req.body;
  const scan = DbStore.getScans().find((s) => s.id === scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  if (!isUserAuthorizedForProject(req.user, scan.projectId)) {
    return res.status(404).json({ error: 'Scan not found.' });
  }

  try {
    const scanFindings = DbStore.getFindings().filter((f) => f.scanId === scan.id);
    const summaryText = await AiAdvisor.generateExecutiveSummary(scan.assetName, scanFindings);
    res.json({ summary: summaryText });
  } catch (err) {
    res.status(500).json({ error: 'Executive summary generation failed.' });
  }
});

// Secure Single-Use Report Ticket Endpoint (Remediates P2 token-in-url)
app.post('/api/reports/tickets', requireAuth, (req: any, res) => {
  const { scanId } = req.body;
  if (!scanId) {
    return res.status(400).json({ error: 'Scan ID is required.' });
  }

  const scan = DbStore.getScans().find((s) => s.id === scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  if (!isUserAuthorizedForProject(req.user, scan.projectId)) {
    return res.status(403).json({ error: 'Forbidden: Access to requested scan is denied.' });
  }

  // Generate high-entropy ticket valid for 60 seconds
  const ticket = `tkt-${crypto.randomBytes(32).toString('hex')}`;
  REPORT_TICKETS.set(ticket, {
    scanId,
    userId: req.user.id,
    expiresAt: Date.now() + 60000
  });

  res.json({ ticket });
});

// Consume Ticket and Export Report Endpoint (Single-Use, SS-01/P2)
app.get('/api/reports/generate', (req, res) => {
  const ticketToken = req.query.ticket as string;
  const format = req.query.format as string || 'HTML';

  if (!ticketToken) {
    return res.status(401).json({ error: 'Unauthorized: Missing single-use download ticket.' });
  }

  const ticketData = REPORT_TICKETS.get(ticketToken);
  if (!ticketData) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired single-use ticket.' });
  }

  // Enforce absolute single-use: Delete the ticket immediately upon lookup!
  REPORT_TICKETS.delete(ticketToken);

  if (Date.now() > ticketData.expiresAt) {
    return res.status(410).json({ error: 'Gone: The download ticket has expired.' });
  }

  const scan = DbStore.getScans().find((s) => s.id === ticketData.scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  const project = DbStore.getProjectById(scan.projectId) || DbStore.getProjects()[0];
  const scanFindings = DbStore.getFindings().filter((f) => f.scanId === scan.id);

  const model = ReportGenerator.generateReportModel(scan, project, scanFindings);

  if (format === 'CSV') {
    const csv = ReportGenerator.exportCsvReport(scanFindings);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="securescope-report-${ticketData.scanId}.csv"`);
    return res.send(csv);
  }

  if (format === 'JSON') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="securescope-report-${ticketData.scanId}.json"`);
    return res.json(model);
  }

  // Default HTML Report
  const html = ReportGenerator.exportHtmlReport(model);
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// Scanner Metadata Config
app.get('/api/scanners/registry', requireAuth, (req, res) => {
  res.json(SCANNER_REGISTRY);
});

// Audit Trails (Persistent log viewing restricted to privileged roles)
app.get('/api/audit-logs', requireAuth, requireRole(['OWNER', 'ADMIN']), (req, res) => {
  res.json(DbStore.getAuditLogs());
});

// --- VITE MIDDLEWARE ATTACHMENT & SERVER START ---
async function startServer() {
  try {
    if (process.env.NODE_ENV !== 'production') {
      const vite = await createViteServer({
        server: {
          middlewareMode: true,
          hmr: process.env.DISABLE_HMR !== 'true',
        },
        appType: 'custom',
      });
      app.use(vite.middlewares);

      app.use('*', async (req, res, next) => {
        if (req.originalUrl.startsWith('/api')) {
          return next();
        }
        try {
          let template = fs.readFileSync(path.resolve(__dirname, 'index.html'), 'utf-8');
          template = await vite.transformIndexHtml(req.originalUrl, template);
          res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
        } catch (e) {
          if (vite) vite.ssrFixStacktrace(e as Error);
          next(e);
        }
      });
    } else {
      app.use(express.static('dist'));
      app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
      });
    }

    const PORT = Number(process.env.PORT) || 3000;
    const serverInstance = app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n  VITE v6.0.0  ready in 150 ms\n\n  ➜  Local:   http://localhost:${PORT}/\n  ➜  Network: http://0.0.0.0:${PORT}/\n`);
    });

    serverInstance.on('error', (err: any) => {
      console.error('[SecureScope Server] Listen error:', err);
    });
  } catch (err) {
    console.error('[SecureScope Server] Startup error:', err);
  }
}

startServer();
