import crypto from 'crypto';
import { DbStore } from './dbStore';
import { PolicyEngine } from './policyEngine';
import { NormalizerAndCorrelator } from './normalizer';
import { ZapAdapter, RawFindingOutput } from '../scanners/zapAdapter';
import { NucleiAdapter } from '../scanners/nucleiAdapter';
import { MobSFAdapter } from '../scanners/mobsfAdapter';
import { SemgrepAdapter } from '../scanners/semgrepAdapter';
import { TrivyAdapter } from '../scanners/trivyAdapter';
import { Scan, Project, Asset } from '../../types/securescope';

export class WorkerRunner {
  private static activeJobs = new Set<string>();

  /**
   * Enqueues and initiates decoupled background execution of a scan job (SS-08 Phase 8)
   */
  public static enqueueScan(scanId: string, projectId: string, assetId: string, boundIp: string) {
    if (this.activeJobs.has(scanId)) return;
    this.activeJobs.add(scanId);

    // Decouple from main Express handler loop using microtask macro-queue execution
    setTimeout(async () => {
      console.log(`[Worker] Starting isolated runner job for ScanID: ${scanId}...`);
      
      const scans = DbStore.getScans();
      const scan = scans.find(s => s.id === scanId);
      if (!scan) {
        console.error(`[Worker] Scan ${scanId} not found in database store.`);
        this.activeJobs.delete(scanId);
        return;
      }

      // Transition scan state to RUNNING under worker authority
      scan.status = 'RUNNING';
      DbStore.updateScan(scan);

      const project = DbStore.getProjectById(projectId);
      const asset = DbStore.getAssets().find(a => a.id === assetId);

      if (!project || !asset) {
        console.error(`[Worker] Missing context for job launch. Project/Asset invalid.`);
        scan.status = 'FAILED';
        DbStore.updateScan(scan);
        this.activeJobs.delete(scanId);
        return;
      }

      const boundAsset = { ...asset, resolvedIp: boundIp } as any;
      const rawFindings: RawFindingOutput[] = [];
      const now = new Date().toISOString();

      try {
        // Run decoupled adapters based on type with bounded execution scopes and DNS constraint enforcement (SS-02)
        if (boundAsset.type === 'WEB_URL' || boundAsset.type === 'API_ENDPOINT') {
          // Isolated ZAP Run
          const zapLogs: string[] = [];
          const zapRaw = await ZapAdapter.runScan({ 
            scanId, 
            projectId: project.id, 
            asset: boundAsset, 
            profile: scan.profile, 
            authorizationStatement: scan.authorizationStatement 
          }, zapLogs);
          rawFindings.push(...zapRaw);
          
          scan.jobs.push({
            id: `job-zap-${scanId}`,
            scanId,
            scannerId: ZapAdapter.id,
            scannerName: ZapAdapter.displayName,
            status: 'COMPLETED',
            startedAt: now,
            completedAt: new Date().toISOString(),
            findingsCount: zapRaw.length,
            logs: zapLogs
          });

          // Isolated Nuclei Run
          const nucleiLogs: string[] = [];
          const nucleiRaw = await NucleiAdapter.runScan({ asset: boundAsset, profile: scan.profile }, nucleiLogs);
          rawFindings.push(...nucleiRaw);
          
          scan.jobs.push({
            id: `job-nuclei-${scanId}`,
            scanId,
            scannerId: NucleiAdapter.id,
            scannerName: NucleiAdapter.displayName,
            status: 'COMPLETED',
            startedAt: now,
            completedAt: new Date().toISOString(),
            findingsCount: nucleiRaw.length,
            logs: nucleiLogs
          });

        } else if (boundAsset.type === 'MOBILE_PACKAGE') {
          const mobsfLogs: string[] = [];
          const mobsfRaw = await MobSFAdapter.runScan({ asset: boundAsset, profile: scan.profile }, mobsfLogs);
          rawFindings.push(...mobsfRaw);
          
          scan.jobs.push({
            id: `job-mobsf-${scanId}`,
            scanId,
            scannerId: MobSFAdapter.id,
            scannerName: MobSFAdapter.displayName,
            status: 'COMPLETED',
            startedAt: now,
            completedAt: new Date().toISOString(),
            findingsCount: mobsfRaw.length,
            logs: mobsfLogs
          });

        } else if (boundAsset.type === 'SOURCE_REPO') {
          const semgrepLogs: string[] = [];
          const semgrepRaw = await SemgrepAdapter.runScan({ asset: boundAsset, profile: scan.profile }, semgrepLogs);
          rawFindings.push(...semgrepRaw);
          
          scan.jobs.push({
            id: `job-semgrep-${scanId}`,
            scanId,
            scannerId: SemgrepAdapter.id,
            scannerName: SemgrepAdapter.displayName,
            status: 'COMPLETED',
            startedAt: now,
            completedAt: new Date().toISOString(),
            findingsCount: semgrepRaw.length,
            logs: semgrepLogs
          });

          const trivyLogs: string[] = [];
          const trivyRaw = await TrivyAdapter.runScan({ asset: boundAsset, profile: scan.profile }, trivyLogs);
          rawFindings.push(...trivyRaw);
          
          scan.jobs.push({
            id: `job-trivy-${scanId}`,
            scanId,
            scannerId: TrivyAdapter.id,
            scannerName: TrivyAdapter.displayName,
            status: 'COMPLETED',
            startedAt: now,
            completedAt: new Date().toISOString(),
            findingsCount: trivyRaw.length,
            logs: trivyLogs
          });
        }

        // Correlate, Normalize, and Deduplicate Findings safely (SHA-256)
        const normalized = NormalizerAndCorrelator.correlateFindings(
          scanId,
          project.id,
          asset.id,
          asset.identifier,
          rawFindings
        );

        // Persistent save of normalized findings
        for (const f of normalized) {
          DbStore.addFinding(f);
        }

        // Set finished execution counters
        scan.status = 'COMPLETED';
        scan.completedAt = new Date().toISOString();
        scan.durationSeconds = Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000);
        scan.findingsSummary = {
          critical: normalized.filter((f) => f.severity === 'CRITICAL').length,
          high: normalized.filter((f) => f.severity === 'HIGH').length,
          medium: normalized.filter((f) => f.severity === 'MEDIUM').length,
          low: normalized.filter((f) => f.severity === 'LOW').length,
          info: normalized.filter((f) => f.severity === 'INFO').length,
          total: normalized.length
        };

        DbStore.updateScan(scan);

        // Record E2E Job Audit Persistence (SS-07)
        DbStore.addAuditLog({
          id: `aud-${crypto.randomBytes(4).toString('hex')}`,
          actorName: 'SYSTEM WORKER',
          actorEmail: 'worker@securescope.internal',
          action: 'SCAN_COMPLETED',
          resourceType: 'SCAN',
          resourceId: scanId,
          details: `Decoupled isolated worker completed Scan ${scanId}. Total findings: ${normalized.length}`,
          timestamp: new Date().toISOString()
        });

      } catch (err: any) {
        console.error(`[Worker] Scan ${scanId} failed in execution layer:`, err);
        scan.status = 'FAILED';
        scan.completedAt = new Date().toISOString();
        DbStore.updateScan(scan);
      } finally {
        this.activeJobs.delete(scanId);
      }
    }, 100);
  }
}
