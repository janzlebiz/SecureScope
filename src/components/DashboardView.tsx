import React from 'react';
import {
  ShieldAlert,
  Zap,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  Info,
  ArrowUpRight,
  Sparkles,
  Lock,
  Cpu
} from 'lucide-react';
import { Scan, Finding, Project, ScannerRegistryEntry } from '../types/securescope';

interface DashboardViewProps {
  project: Project | null;
  scans: Scan[];
  findings: Finding[];
  scanners: ScannerRegistryEntry[];
  onSelectFinding: (f: Finding) => void;
  onOpenNewScan: () => void;
  onNavigateToTab: (tab: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  project,
  scans,
  findings,
  scanners,
  onSelectFinding,
  onOpenNewScan,
  onNavigateToTab
}) => {
  const critical = findings.filter((f) => f.severity === 'CRITICAL' && f.status !== 'REMEDIATED').length;
  const high = findings.filter((f) => f.severity === 'HIGH' && f.status !== 'REMEDIATED').length;
  const medium = findings.filter((f) => f.severity === 'MEDIUM' && f.status !== 'REMEDIATED').length;
  const low = findings.filter((f) => f.severity === 'LOW' && f.status !== 'REMEDIATED').length;
  const activeScans = scans.filter((s) => s.status === 'RUNNING' || s.status === 'QUEUED');

  // Compute Posture Score
  const postureScore = Math.max(0, 100 - (critical * 25 + high * 10 + medium * 3));

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-sky-400 mb-1">
            <Lock className="w-3.5 h-3.5" />
            <span>PROJECT: {project?.name || 'All Workspaces'}</span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Posture & Assessment Control Plane
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Controlled multi-engine security assessment orchestrator. Automated target scope validation, SSRF protection, and cross-scanner finding normalization.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onOpenNewScan}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs rounded-lg transition-colors flex items-center gap-2 shadow-sm shadow-sky-950/50"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Launch Authorized Scan</span>
          </button>
        </div>
      </div>

      {/* Metric Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Security Posture Index */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase">Posture Index</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono tabular-nums">{postureScore}</span>
            <span className="text-xs text-slate-400">/ 100</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Scope Enforcement: Active</span>
            <span className="text-emerald-400 font-mono font-semibold">100% Policy</span>
          </div>
        </div>

        {/* Critical & High Findings */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase">Critical / High Vulnerabilities</span>
            <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-3">
            <span className="text-3xl font-extrabold text-red-400 font-mono tabular-nums">{critical + high}</span>
            <span className="text-xs text-slate-400 font-mono font-medium">({critical} Critical, {high} High)</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Action required: Review evidence & apply fixes
          </div>
        </div>

        {/* Total Correlated Findings */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase">Total Correlated Findings</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-mono tabular-nums">{findings.length}</span>
            <span className="text-xs text-slate-400 font-mono">Deduplicated</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Across ZAP, Nuclei, MobSF, Semgrep, Trivy
          </div>
        </div>

        {/* Active Scan Jobs */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase">Active Scans</span>
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Zap className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-sky-400 font-mono tabular-nums">{activeScans.length}</span>
            <span className="text-xs text-slate-400">In Execution</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
            <span>Worker Queue Nominal</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Recent Findings & Active Scans / Scanner Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Unresolved Findings */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Priority Vulnerability Findings</span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Correlated findings sorted by severity with source evidence
              </p>
            </div>
            <button
              onClick={() => onNavigateToTab('findings')}
              className="text-xs font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {findings.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No findings reported yet. Run a scan to populate vulnerability results.
              </div>
            ) : (
              findings.slice(0, 5).map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className="p-3.5 bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 rounded-lg cursor-pointer transition-colors flex items-start justify-between gap-3 group"
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : finding.severity === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : finding.severity === 'MEDIUM'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-sky-500/10 text-sky-400 border-sky-500/30'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs font-semibold text-white group-hover:text-sky-400 transition-colors truncate">
                        {finding.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono truncate">
                      <span>{finding.cwe || finding.category}</span>
                      <span>·</span>
                      <span className="truncate">{finding.affectedLocation}</span>
                    </div>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {finding.occurrences.length} Scanner{finding.occurrences.length > 1 ? 's' : ''}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Col: Active Scanner Engines Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sky-400" />
              <span>Registered Scanner Adapters</span>
            </h2>
            <button
              onClick={() => onNavigateToTab('registry')}
              className="text-xs font-mono text-sky-400 hover:text-sky-300"
            >
              Registry
            </button>
          </div>

          <div className="space-y-2.5">
            {scanners.slice(0, 5).map((s) => (
              <div key={s.id} className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-200">{s.name}</div>
                  <div className="text-[10px] font-mono text-slate-500">{s.category} · v{s.version}</div>
                </div>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    s.status === 'ACTIVE'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {s.status}
                </span>
              </div>
            ))}
          </div>

          <div className="p-3 bg-sky-950/20 border border-sky-800/30 rounded-lg text-xs text-sky-300 space-y-1">
            <div className="font-semibold flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>AI Security Analyst Ready</span>
            </div>
            <p className="text-[11px] text-sky-400/80 leading-relaxed">
              Select any finding to trigger Gemini AI remediation code generation & technical explanation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
