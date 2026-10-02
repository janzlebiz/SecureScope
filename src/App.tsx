import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar, ViewTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ProjectsView } from './components/ProjectsView';
import { ScanOrchestratorView } from './components/ScanOrchestratorView';
import { FindingsView } from './components/FindingsView';
import { FindingDetailModal } from './components/FindingDetailModal';
import { AiAdvisorView } from './components/AiAdvisorView';
import { StandardsView } from './components/StandardsView';
import { ReportsView } from './components/ReportsView';
import { AuditView } from './components/AuditView';
import { ShieldAlert } from 'lucide-react';
import {
  Project,
  Asset,
  Scan,
  Finding,
  AuditEvent,
  ScannerRegistryEntry,
  FindingStatus,
  AssetType,
  Environment,
  ScanProfile
} from './types/securescope';

export default function App() {
  const [activeTab, setActiveTab] = useState<ViewTab>('dashboard');
  const [activeRole, setActiveRole] = useState<'owner' | 'admin' | 'analyst' | 'viewer'>('owner');
  const [tokens, setTokens] = useState<Record<string, string>>({});

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [scanners, setScanners] = useState<ScannerRegistryEntry[]>([]);

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [preSelectedAssetForScan, setPreSelectedAssetForScan] = useState<Asset | null>(null);

  // Error toast or status message if action gets denied by backend RBAC/IDOR (SS-01)
  const [denialError, setDenialError] = useState<string | null>(null);

  const activeToken = tokens[activeRole] || '';

  // Dynamic production session initialization (SS-01)
  useEffect(() => {
    const fetchToken = async () => {
      if (tokens[activeRole]) return;

      let email = 'alex.mercer@acme-fintech.com';
      if (activeRole === 'admin') email = 'sarah.chen@medicare-cloud.org';
      if (activeRole === 'analyst') email = 'analyst@secure.com';
      if (activeRole === 'viewer') email = 'viewer@secure.com';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password: 'Password123!' })
        });
        if (res.ok) {
          const body = await res.json();
          setTokens(prev => ({ ...prev, [activeRole]: body.token }));
        }
      } catch (err) {
        console.error('[Dynamic Login] Failed:', err);
      }
    };

    fetchToken();
  }, [activeRole]);

  // Custom authenticated fetch wrapper (SS-01)
  const authFetch = async (url: string, options: any = {}) => {
    if (!activeToken) {
      // Return a simulated failing promise or wait until token is fetched
      return new Response(JSON.stringify({ error: 'Session initializing...' }), { status: 401 });
    }

    const headers = {
      ...(options.headers || {}),
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${activeToken}`
    };
    const res = await fetch(url, { ...options, headers });
    
    if (res.status === 403) {
      const errBody = await res.json().catch(() => ({}));
      triggerDenialToast(errBody.error || 'Access Denied: Role permissions violated.');
    } else if (res.status === 401) {
      triggerDenialToast('Session expired or unauthorized request.');
    }
    
    return res;
  };

  const triggerDenialToast = (msg: string) => {
    setDenialError(msg);
    setTimeout(() => setDenialError(null), 5000);
  };

  // Fetch state scoped to the active authorized identity (IDOR & RBAC)
  const fetchData = async () => {
    if (!activeToken) return;
    try {
      const projRes = await authFetch('/api/projects');
      if (!projRes.ok) return;
      const projData = await projRes.json();
      setProjects(projData);

      // Auto-set or sync selected project based on authorized projects list
      let nextProject = selectedProject;
      if (projData.length > 0) {
        const stillAuthorized = projData.some((p: Project) => p.id === selectedProject?.id);
        if (!stillAuthorized || !selectedProject) {
          nextProject = projData[0];
          setSelectedProject(projData[0]);
        }
      } else {
        nextProject = null;
        setSelectedProject(null);
      }

      const scanRes = await authFetch('/api/scans');
      const findRes = await authFetch('/api/findings');
      const regRes = await authFetch('/api/scanners/registry');

      if (scanRes.ok) setScans(await scanRes.json());
      if (findRes.ok) setFindings(await findRes.json());
      if (regRes.ok) setScanners(await regRes.json());

      // Fetch audit logs (restricted endpoint; handles 403 internally)
      const auditRes = await authFetch('/api/audit-logs');
      if (auditRes.ok) {
        setAuditLogs(await auditRes.json());
      } else {
        setAuditLogs([]);
      }

      if (nextProject) {
        const assetsRes = await authFetch(`/api/projects/${nextProject.id}/assets`);
        if (assetsRes.ok) {
          setAssets(await assetsRes.json());
        }
      } else {
        setAssets([]);
      }
    } catch (err) {
      console.error('Failed to fetch SecureScope state:', err);
    }
  };

  // Fetch initial/periodic state
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, [activeRole, selectedProject?.id]);

  // Sync assets when selected project changes
  useEffect(() => {
    if (selectedProject) {
      authFetch(`/api/projects/${selectedProject.id}/assets`)
        .then((res) => {
          if (res.ok) return res.json();
          return [];
        })
        .then((data) => setAssets(data))
        .catch((err) => console.error('Failed to load assets:', err));
    }
  }, [selectedProject, activeRole]);

  // Handlers
  const handleCreateProject = async (name: string, description: string) => {
    const res = await authFetch('/api/projects', {
      method: 'POST',
      body: JSON.stringify({ name, description })
    });
    if (res.ok) {
      const newProj = await res.json();
      setProjects((prev) => [newProj, ...prev]);
      setSelectedProject(newProj);
    }
  };

  const handleAddAsset = async (assetData: {
    projectId: string;
    name: string;
    type: AssetType;
    identifier: string;
    environment: Environment;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }) => {
    const res = await authFetch(`/api/projects/${assetData.projectId}/assets`, {
      method: 'POST',
      body: JSON.stringify(assetData)
    });
    if (res.ok) {
      const newAsset = await res.json();
      setAssets((prev) => [newAsset, ...prev]);
    }
  };

  const handleLaunchScan = async (params: {
    projectId: string;
    assetId: string;
    profile: ScanProfile;
    authorizationConfirmed: boolean;
    authorizationStatement: string;
  }) => {
    const res = await authFetch('/api/scans', {
      method: 'POST',
      body: JSON.stringify(params)
    });

    if (res.ok) {
      const newScan = await res.json();
      setScans((prev) => [newScan, ...prev]);
      setActiveTab('orchestrator');
    }
  };

  const handleCancelScan = async (scanId: string) => {
    const res = await authFetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
    if (res.ok) {
      fetchData();
    }
  };

  const handleUpdateFindingStatus = async (id: string, status: FindingStatus) => {
    const res = await authFetch(`/api/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
    if (res.ok) {
      const updated = await res.json();
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (selectedFinding?.id === id) {
        setSelectedFinding(updated);
      }
    }
  };

  const handleAnalyzeFindingWithAi = async (findingId: string) => {
    const res = await authFetch('/api/ai/analyze-finding', {
      method: 'POST',
      body: JSON.stringify({ findingId })
    });
    if (res.ok) {
      const aiData = await res.json();
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, aiAnalysis: aiData } : f))
      );
      if (selectedFinding?.id === findingId) {
        setSelectedFinding((prev) => (prev ? { ...prev, aiAnalysis: aiData } : null));
      }
      return aiData;
    }
    return null;
  };

  const handleGenerateExecutiveSummaryWithAi = async (scanId: string) => {
    const res = await authFetch('/api/ai/generate-executive-summary', {
      method: 'POST',
      body: JSON.stringify({ scanId })
    });
    if (res.ok) {
      const data = await res.json();
      return data.summary;
    }
    return 'Summary generation failed due to authorization limits.';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200 relative">
      {/* Denial Notification Overlay (SS-01 AAA demo indicator) */}
      {denialError && (
        <div className="fixed top-20 right-6 z-50 max-w-sm bg-red-950/90 border border-red-500/40 rounded-xl p-4 shadow-lg shadow-red-950/50 flex items-start gap-3 backdrop-blur-md animate-in fade-in slide-in-from-top-4 duration-300">
          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="text-xs font-bold text-red-200 uppercase tracking-wide font-mono">Enforcement Block</h4>
            <p className="text-[11px] text-red-300 mt-1">{denialError}</p>
          </div>
        </div>
      )}

      {/* Top Header */}
      <Header
        projects={projects}
        selectedProject={selectedProject}
        onSelectProject={setSelectedProject}
        onOpenNewScan={() => setActiveTab('orchestrator')}
        onOpenNewProject={() => setActiveTab('projects')}
        activeRole={activeRole}
        onSelectRole={setActiveRole}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Workspace Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          openScansCount={scans.filter((s) => s.status === 'RUNNING').length}
          openFindingsCount={findings.filter((f) => f.status === 'OPEN').length}
        />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto bg-slate-950">
          {activeTab === 'dashboard' && (
            <DashboardView
              project={selectedProject}
              scans={scans}
              findings={findings}
              scanners={scanners}
              onSelectFinding={setSelectedFinding}
              onOpenNewScan={() => setActiveTab('orchestrator')}
              onNavigateToTab={setActiveTab}
            />
          )}

          {activeTab === 'projects' && (
            <ProjectsView
              projects={projects}
              assets={assets}
              selectedProject={selectedProject}
              onSelectProject={setSelectedProject}
              onCreateProject={handleCreateProject}
              onAddAsset={handleAddAsset}
              onOpenScanForAsset={(ast) => {
                setPreSelectedAssetForScan(ast);
                setActiveTab('orchestrator');
              }}
            />
          )}

          {activeTab === 'orchestrator' && (
            <ScanOrchestratorView
              project={selectedProject}
              assets={assets}
              scans={scans}
              preSelectedAsset={preSelectedAssetForScan}
              onLaunchScan={handleLaunchScan}
              onCancelScan={handleCancelScan}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsView
              findings={findings}
              onSelectFinding={setSelectedFinding}
              onUpdateStatus={handleUpdateFindingStatus}
            />
          )}

          {activeTab === 'standards' && <StandardsView findings={findings} />}

          {activeTab === 'ai-advisor' && (
            <AiAdvisorView
              findings={findings}
              scans={scans}
              onAnalyzeFinding={handleAnalyzeFindingWithAi}
              onGenerateExecutiveSummary={handleGenerateExecutiveSummaryWithAi}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView scans={scans} projects={projects} findings={findings} activeToken={activeToken} />
          )}

          {activeTab === 'audit' && (
            <AuditView auditLogs={auditLogs} scanners={scanners} />
          )}

          {activeTab === 'registry' && (
            <AuditView auditLogs={auditLogs} scanners={scanners} />
          )}
        </main>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onUpdateStatus={handleUpdateFindingStatus}
          onAnalyzeWithAi={handleAnalyzeFindingWithAi}
        />
      )}
    </div>
  );
}
