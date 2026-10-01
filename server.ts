import express from 'express';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { INITIAL_PROJECTS, INITIAL_ASSETS, INITIAL_SCANS, INITIAL_FINDINGS, INITIAL_AUDIT_LOGS } from './src/server/mockData';
import { PolicyEngine } from './src/server/services/policyEngine';
import { NormalizerAndCorrelator } from './src/server/services/normalizer';
import { ReportGenerator } from './src/server/services/reportGenerator';
import { AiAdvisor } from './src/server/services/aiAdvisor';
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

// In-Memory Data Store
let projects: Project[] = [...INITIAL_PROJECTS];
let assets: Asset[] = [...INITIAL_ASSETS];
let scans: Scan[] = [...INITIAL_SCANS];
let findings: Finding[] = [...INITIAL_FINDINGS];
let auditLogs: AuditEvent[] = [...INITIAL_AUDIT_LOGS];

// --- API ROUTES ---

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', system: 'SecureScope Control Plane', version: '1.0.0', timestamp: new Date().toISOString() });
});

// Projects
app.get('/api/projects', (req, res) => {
  res.json(projects);
});

app.post('/api/projects', (req, res) => {
  const { name, description, scopePolicy } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Project name is required' });
  }

  const newProject: Project = {
    id: `proj-${Math.random().toString(36).substring(2, 9)}`,
    name,
    description: description || '',
    ownerId: 'usr-1',
    ownerName: 'Alex Mercer (AppSec Lead)',
    scopePolicy: scopePolicy || {
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

  projects.unshift(newProject);

  auditLogs.unshift({
    id: `aud-${Math.random().toString(36).substring(2, 9)}`,
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'PROJECT_CREATED',
    resourceType: 'PROJECT',
    resourceId: newProject.id,
    details: `Created new project '${newProject.name}'`,
    timestamp: new Date().toISOString()
  });

  res.status(201).json(newProject);
});

app.get('/api/projects/:id', (req, res) => {
  const project = projects.find((p) => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const projectAssets = assets.filter((a) => a.projectId === project.id);
  res.json({ ...project, assets: projectAssets });
});

// Assets
app.get('/api/projects/:id/assets', (req, res) => {
  const projectAssets = assets.filter((a) => a.projectId === req.params.id);
  res.json(projectAssets);
});

app.post('/api/projects/:id/assets', (req, res) => {
  const { name, type, identifier, environment, criticality } = req.body;
  if (!name || !identifier) {
    return res.status(400).json({ error: 'Asset name and identifier are required' });
  }

  const newAsset: Asset = {
    id: `ast-${Math.random().toString(36).substring(2, 9)}`,
    projectId: req.params.id,
    type: type || 'WEB_URL',
    name,
    identifier,
    environment: environment || 'STAGING',
    criticality: criticality || 'HIGH',
    createdAt: new Date().toISOString()
  };

  assets.unshift(newAsset);

  auditLogs.unshift({
    id: `aud-${Math.random().toString(36).substring(2, 9)}`,
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'ASSET_ADDED',
    resourceType: 'ASSET',
    resourceId: newAsset.id,
    details: `Added target asset '${newAsset.name}' (${newAsset.identifier})`,
    timestamp: new Date().toISOString()
  });

  res.status(201).json(newAsset);
});

// Target Scope Policy Evaluation
app.post('/api/policy/validate', (req, res) => {
  const { target, assetType, profile, projectId, authorizationConfirmed } = req.body;
  const project = projects.find((p) => p.id === projectId) || projects[0];

  const decision = PolicyEngine.evaluateTarget(
    target || '',
    assetType || 'WEB_URL',
    profile || 'SAFE_BASELINE',
    project.scopePolicy,
    Boolean(authorizationConfirmed)
  );

  res.json(decision);
});

// Scans & Orchestrator
app.get('/api/scans', (req, res) => {
  res.json(scans);
});

app.post('/api/scans', async (req, res) => {
  const { projectId, assetId, profile, authorizationConfirmed, authorizationStatement } = req.body;

  const project = projects.find((p) => p.id === projectId);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const asset = assets.find((a) => a.id === assetId);
  if (!asset) return res.status(404).json({ error: 'Asset not found' });

  // 1. Evaluate Scope & Authorization Gate
  const decision = PolicyEngine.evaluateTarget(
    asset.identifier,
    asset.type,
    profile || 'SAFE_BASELINE',
    project.scopePolicy,
    Boolean(authorizationConfirmed)
  );

  if (!decision.allowed) {
    auditLogs.unshift({
      id: `aud-${Math.random().toString(36).substring(2, 9)}`,
      actorName: 'Alex Mercer',
      actorEmail: 'alex.mercer@acme-fintech.com',
      action: 'SCAN_BLOCKED_BY_POLICY',
      resourceType: 'ASSET',
      resourceId: asset.id,
      details: `Scan attempt blocked by policy: ${decision.reasons.join('; ')}`,
      timestamp: new Date().toISOString()
    });

    return res.status(400).json({
      error: 'Scan launch blocked by scope policy or authorization gate.',
      policyDecision: decision
    });
  }

  // 2. Queue & Run Scan
  const scanId = `scn-${Math.random().toString(36).substring(2, 9)}`;
  const now = new Date().toISOString();

  const newScan: Scan = {
    id: scanId,
    projectId: project.id,
    assetId: asset.id,
    assetName: asset.name,
    assetIdentifier: asset.identifier,
    assetType: asset.type,
    profile: profile || 'SAFE_BASELINE',
    status: 'RUNNING',
    initiatedBy: 'usr-1',
    initiatedByName: 'Alex Mercer',
    authorizationConfirmedAt: now,
    authorizationStatement: authorizationStatement || 'I confirm I am authorized to test this target.',
    startedAt: now,
    jobs: [],
    findingsSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  };

  scans.unshift(newScan);

  auditLogs.unshift({
    id: `aud-${Math.random().toString(36).substring(2, 9)}`,
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'SCAN_LAUNCHED',
    resourceType: 'SCAN',
    resourceId: scanId,
    details: `Launched ${profile} scan against ${asset.name} (${asset.identifier})`,
    timestamp: now
  });

  // Respond immediately with queued scan object
  res.status(202).json(newScan);

  // Background execution simulation/adapters
  (async () => {
    const rawFindings: RawFindingOutput[] = [];

    // Select adapters based on asset type
    if (asset.type === 'WEB_URL' || asset.type === 'API_ENDPOINT') {
      // ZAP Job
      const zapLogs: string[] = [];
      const zapRaw = await ZapAdapter.runScan({ scanId, projectId: project.id, asset, profile, authorizationStatement: newScan.authorizationStatement }, zapLogs);
      rawFindings.push(...zapRaw);
      newScan.jobs.push({
        id: `job-zap-${scanId}`,
        scanId,
        scannerId: ZapAdapter.id,
        scannerName: ZapAdapter.name,
        status: 'COMPLETED',
        startedAt: now,
        completedAt: new Date().toISOString(),
        findingsCount: zapRaw.length,
        logs: zapLogs
      });

      // Nuclei Job
      const nucleiLogs: string[] = [];
      const nucleiRaw = await NucleiAdapter.runScan({ asset, profile }, nucleiLogs);
      rawFindings.push(...nucleiRaw);
      newScan.jobs.push({
        id: `job-nuclei-${scanId}`,
        scanId,
        scannerId: NucleiAdapter.id,
        scannerName: NucleiAdapter.name,
        status: 'COMPLETED',
        startedAt: now,
        completedAt: new Date().toISOString(),
        findingsCount: nucleiRaw.length,
        logs: nucleiLogs
      });
    } else if (asset.type === 'MOBILE_PACKAGE') {
      const mobsfLogs: string[] = [];
      const mobsfRaw = await MobSFAdapter.runScan({ asset, profile }, mobsfLogs);
      rawFindings.push(...mobsfRaw);
      newScan.jobs.push({
        id: `job-mobsf-${scanId}`,
        scanId,
        scannerId: MobSFAdapter.id,
        scannerName: MobSFAdapter.name,
        status: 'COMPLETED',
        startedAt: now,
        completedAt: new Date().toISOString(),
        findingsCount: mobsfRaw.length,
        logs: mobsfLogs
      });
    } else if (asset.type === 'SOURCE_REPO') {
      const semgrepLogs: string[] = [];
      const semgrepRaw = await SemgrepAdapter.runScan({ asset, profile }, semgrepLogs);
      rawFindings.push(...semgrepRaw);
      newScan.jobs.push({
        id: `job-semgrep-${scanId}`,
        scanId,
        scannerId: SemgrepAdapter.id,
        scannerName: SemgrepAdapter.name,
        status: 'COMPLETED',
        startedAt: now,
        completedAt: new Date().toISOString(),
        findingsCount: semgrepRaw.length,
        logs: semgrepLogs
      });

      const trivyLogs: string[] = [];
      const trivyRaw = await TrivyAdapter.runScan({ asset, profile }, trivyLogs);
      rawFindings.push(...trivyRaw);
      newScan.jobs.push({
        id: `job-trivy-${scanId}`,
        scanId,
        scannerId: TrivyAdapter.id,
        scannerName: TrivyAdapter.name,
        status: 'COMPLETED',
        startedAt: now,
        completedAt: new Date().toISOString(),
        findingsCount: trivyRaw.length,
        logs: trivyLogs
      });
    }

    // Correlate & Normalize Findings
    const normalized = NormalizerAndCorrelator.correlateFindings(
      scanId,
      project.id,
      asset.id,
      asset.identifier,
      rawFindings
    );

    findings.unshift(...normalized);

    // Update scan state
    newScan.status = 'COMPLETED';
    newScan.completedAt = new Date().toISOString();
    newScan.durationSeconds = Math.round((new Date(newScan.completedAt).getTime() - new Date(newScan.startedAt).getTime()) / 1000);

    newScan.findingsSummary = {
      critical: normalized.filter((f) => f.severity === 'CRITICAL').length,
      high: normalized.filter((f) => f.severity === 'HIGH').length,
      medium: normalized.filter((f) => f.severity === 'MEDIUM').length,
      low: normalized.filter((f) => f.severity === 'LOW').length,
      info: normalized.filter((f) => f.severity === 'INFO').length,
      total: normalized.length
    };
  })();
});

app.get('/api/scans/:id', (req, res) => {
  const scan = scans.find((s) => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  const scanFindings = findings.filter((f) => f.scanId === scan.id);
  res.json({ ...scan, findings: scanFindings });
});

app.post('/api/scans/:id/cancel', (req, res) => {
  const scan = scans.find((s) => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  scan.status = 'CANCELLED';
  res.json({ message: 'Scan cancelled', scan });
});

// Findings
app.get('/api/findings', (req, res) => {
  const { projectId, assetId, severity, status } = req.query;
  let filtered = [...findings];

  if (projectId) filtered = filtered.filter((f) => f.projectId === projectId);
  if (assetId) filtered = filtered.filter((f) => f.assetId === assetId);
  if (severity) filtered = filtered.filter((f) => f.severity === severity);
  if (status) filtered = filtered.filter((f) => f.status === status);

  res.json(filtered);
});

app.get('/api/findings/:id', (req, res) => {
  const finding = findings.find((f) => f.id === req.params.id);
  if (!finding) return res.status(404).json({ error: 'Finding not found' });
  res.json(finding);
});

app.patch('/api/findings/:id', (req, res) => {
  const finding = findings.find((f) => f.id === req.params.id);
  if (!finding) return res.status(404).json({ error: 'Finding not found' });

  const { status } = req.body;
  if (status) finding.status = status;

  auditLogs.unshift({
    id: `aud-${Math.random().toString(36).substring(2, 9)}`,
    actorName: 'Alex Mercer',
    actorEmail: 'alex.mercer@acme-fintech.com',
    action: 'FINDING_STATUS_UPDATED',
    resourceType: 'FINDING',
    resourceId: finding.id,
    details: `Updated status of '${finding.title}' to ${status}`,
    timestamp: new Date().toISOString()
  });

  res.json(finding);
});

// AI Advisor
app.post('/api/ai/analyze-finding', async (req, res) => {
  const { findingId } = req.body;
  const finding = findings.find((f) => f.id === findingId);
  if (!finding) return res.status(404).json({ error: 'Finding not found' });

  const analysis = await AiAdvisor.analyzeFinding(finding);
  finding.aiAnalysis = {
    ...analysis,
    analyzedAt: new Date().toISOString()
  };

  res.json(finding.aiAnalysis);
});

app.post('/api/ai/generate-executive-summary', async (req, res) => {
  const { scanId } = req.body;
  const scan = scans.find((s) => s.id === scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const scanFindings = findings.filter((f) => f.scanId === scan.id);
  const summaryText = await AiAdvisor.generateExecutiveSummary(scan.assetName, scanFindings);

  res.json({ summary: summaryText });
});

// Reports
app.post('/api/reports/generate', (req, res) => {
  const { scanId, format } = req.body;
  const scan = scans.find((s) => s.id === scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const project = projects.find((p) => p.id === scan.projectId) || projects[0];
  const scanFindings = findings.filter((f) => f.scanId === scan.id);

  const model = ReportGenerator.generateReportModel(scan, project, scanFindings);

  if (format === 'CSV') {
    const csv = ReportGenerator.exportCsvReport(scanFindings);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="securescope-report-${scanId}.csv"`);
    return res.send(csv);
  }

  if (format === 'JSON') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="securescope-report-${scanId}.json"`);
    return res.json(model);
  }

  // Default HTML
  const html = ReportGenerator.exportHtmlReport(model);
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// Scanner Registry
app.get('/api/scanners/registry', (req, res) => {
  res.json(SCANNER_REGISTRY);
});

// Audit Logs
app.get('/api/audit-logs', (req, res) => {
  res.json(auditLogs);
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
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[SecureScope Server] Control plane running on http://0.0.0.0:${PORT}`);
    });
  } catch (err) {
    console.error('[SecureScope Server] Startup error:', err);
  }
}

startServer();
