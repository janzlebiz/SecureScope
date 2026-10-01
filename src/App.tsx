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

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [scanners, setScanners] = useState<ScannerRegistryEntry[]>([]);

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [preSelectedAssetForScan, setPreSelectedAssetForScan] = useState<Asset | null>(null);

  // Fetch initial state
  const fetchData = async () => {
    try {
      const [projRes, scanRes, findRes, auditRes, regRes] = await Promise.all([
        fetch('/api/projects'),
        fetch('/api/scans'),
        fetch('/api/findings'),
        fetch('/api/audit-logs'),
        fetch('/api/scanners/registry')
      ]);

      const projData = await projRes.json();
      const scanData = await scanRes.json();
      const findData = await findRes.json();
      const auditData = await auditRes.json();
      const regData = await regRes.json();

      setProjects(projData);
      if (!selectedProject && projData.length > 0) {
        setSelectedProject(projData[0]);
      }
      setScans(scanData);
      setFindings(findData);
      setAuditLogs(auditData);
      setScanners(regData);

      if (projData.length > 0) {
        const assetsRes = await fetch(`/api/projects/${projData[0].id}/assets`);
        const assetsData = await assetsRes.json();
        setAssets(assetsData);
      }
    } catch (err) {
      console.error('Failed to fetch SecureScope state:', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Sync assets when selected project changes
  useEffect(() => {
    if (selectedProject) {
      fetch(`/api/projects/${selectedProject.id}/assets`)
        .then((res) => res.json())
        .then((data) => setAssets(data))
        .catch((err) => console.error('Failed to load assets:', err));
    }
  }, [selectedProject]);

  // Handlers
  const handleCreateProject = async (name: string, description: string) => {
    const res = await fetch('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description })
    });
    const newProj = await res.json();
    setProjects((prev) => [newProj, ...prev]);
    setSelectedProject(newProj);
  };

  const handleAddAsset = async (assetData: {
    projectId: string;
    name: string;
    type: AssetType;
    identifier: string;
    environment: Environment;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }) => {
    const res = await fetch(`/api/projects/${assetData.projectId}/assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assetData)
    });
    const newAsset = await res.json();
    setAssets((prev) => [newAsset, ...prev]);
  };

  const handleLaunchScan = async (params: {
    projectId: string;
    assetId: string;
    profile: ScanProfile;
    authorizationConfirmed: boolean;
    authorizationStatement: string;
  }) => {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });

    if (res.ok) {
      const newScan = await res.json();
      setScans((prev) => [newScan, ...prev]);
      setActiveTab('orchestrator');
    }
  };

  const handleCancelScan = async (scanId: string) => {
    await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
    fetchData();
  };

  const handleUpdateFindingStatus = async (id: string, status: FindingStatus) => {
    const res = await fetch(`/api/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    const updated = await res.json();
    setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
    if (selectedFinding?.id === id) {
      setSelectedFinding(updated);
    }
  };

  const handleAnalyzeFindingWithAi = async (findingId: string) => {
    const res = await fetch('/api/ai/analyze-finding', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findingId })
    });
    const aiData = await res.json();
    setFindings((prev) =>
      prev.map((f) => (f.id === findingId ? { ...f, aiAnalysis: aiData } : f))
    );
    if (selectedFinding?.id === findingId) {
      setSelectedFinding((prev) => (prev ? { ...prev, aiAnalysis: aiData } : null));
    }
    return aiData;
  };

  const handleGenerateExecutiveSummaryWithAi = async (scanId: string) => {
    const res = await fetch('/api/ai/generate-executive-summary', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanId })
    });
    const data = await res.json();
    return data.summary;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Top Header */}
      <Header
        projects={projects}
        selectedProject={selectedProject}
        onSelectProject={setSelectedProject}
        onOpenNewScan={() => setActiveTab('orchestrator')}
        onOpenNewProject={() => setActiveTab('projects')}
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
            <ReportsView scans={scans} projects={projects} findings={findings} />
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
