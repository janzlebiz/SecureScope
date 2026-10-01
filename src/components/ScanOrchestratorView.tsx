import { useState, useEffect, FormEvent } from 'react';
import {
  Zap,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Terminal,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu
} from 'lucide-react';
import { Asset, Scan, ScanProfile, PolicyDecision, Project } from '../types/securescope';

interface ScanOrchestratorViewProps {
  project: Project | null;
  assets: Asset[];
  scans: Scan[];
  preSelectedAsset?: Asset | null;
  onLaunchScan: (params: {
    projectId: string;
    assetId: string;
    profile: ScanProfile;
    authorizationConfirmed: boolean;
    authorizationStatement: string;
  }) => void;
  onCancelScan: (scanId: string) => void;
}

export const ScanOrchestratorView = ({
  project,
  assets,
  scans,
  preSelectedAsset,
  onLaunchScan,
  onCancelScan
}: ScanOrchestratorViewProps) => {
  const currentAssets = assets.filter((a) => a.projectId === project?.id);
  const [selectedAssetId, setSelectedAssetId] = useState<string>(
    preSelectedAsset?.id || (currentAssets[0]?.id || '')
  );
  const [profile, setProfile] = useState<ScanProfile>('SAFE_BASELINE');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [authStatement, setAuthStatement] = useState(
    'I explicitly confirm that I am the authorized owner or authorized security analyst for this target, and I acknowledge that testing will be recorded in audit logs.'
  );

  // Live Scope Policy Decision Preview
  const [policyDecision, setPolicyDecision] = useState<PolicyDecision | null>(null);
  const [isEvaluatingPolicy, setIsEvaluatingPolicy] = useState(false);

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || currentAssets[0];

  // Evaluate Target Scope Policy live
  useEffect(() => {
    if (!selectedAsset || !project) return;
    setIsEvaluatingPolicy(true);

    fetch('/api/policy/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: selectedAsset.identifier,
        assetType: selectedAsset.type,
        profile,
        projectId: project.id,
        authorizationConfirmed
      })
    })
      .then((res) => res.json())
      .then((data) => {
        setPolicyDecision(data);
        setIsEvaluatingPolicy(false);
      })
      .catch(() => setIsEvaluatingPolicy(false));
  }, [selectedAssetId, profile, authorizationConfirmed, project]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!project || !selectedAssetId || !authorizationConfirmed) return;

    onLaunchScan({
      projectId: project.id,
      assetId: selectedAssetId,
      profile,
      authorizationConfirmed,
      authorizationStatement: authStatement
    });
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <Zap className="w-5 h-5 text-sky-400" />
            <span>Scan Orchestrator & Worker Pipeline</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure target profiles, verify scope policies & SSRF rules, sign testing authorization, and monitor active workers.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Scan Launchpad & Authorization Gate */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            <span>Launch Security Assessment</span>
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Target Asset Picker */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Target Asset *</label>
              <select
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
              >
                {currentAssets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.type})
                  </option>
                ))}
              </select>
              {selectedAsset && (
                <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                  Target: <code>{selectedAsset.identifier}</code>
                </div>
              )}
            </div>

            {/* Assessment Profile Selector */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Assessment Profile</label>
              <div className="space-y-2">
                {[
                  {
                    id: 'SAFE_BASELINE' as ScanProfile,
                    title: 'Safe Baseline (Passive)',
                    desc: 'Low-impact passive HTTP/TLS audit, security headers, tech discovery, static checks.'
                  },
                  {
                    id: 'STANDARD' as ScanProfile,
                    title: 'Standard Active Scan',
                    desc: 'Active crawler, Nuclei CVE templates, API assessment, SAST/SCA rule checks.'
                  },
                  {
                    id: 'DEEP_AUTHORIZED' as ScanProfile,
                    title: 'Deep / Intrusive Assessment',
                    desc: 'Deeper active vulnerability rules & fuzzing. Requires explicit authorization approval.'
                  }
                ].map((item) => (
                  <label
                    key={item.id}
                    className={`block p-3 rounded-lg border cursor-pointer transition-colors ${
                      profile === item.id
                        ? 'bg-sky-500/10 border-sky-500/30 text-white'
                        : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <input
                        type="radio"
                        name="profile"
                        value={item.id}
                        checked={profile === item.id}
                        onChange={() => setProfile(item.id)}
                        className="text-sky-500 focus:ring-0"
                      />
                      <span className="text-xs font-semibold">{item.title}</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 leading-relaxed pl-5">{item.desc}</p>
                  </label>
                ))}
              </div>
            </div>

            {/* Target Scope Policy Evaluation Widget */}
            <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between text-xs font-mono font-semibold">
                <span className="text-slate-300">Target Scope & SSRF Policy</span>
                {isEvaluatingPolicy ? (
                  <span className="text-slate-500 text-[10px]">Evaluating...</span>
                ) : policyDecision?.allowed ? (
                  <span className="text-emerald-400 flex items-center gap-1 text-[10px]">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>PASSED</span>
                  </span>
                ) : (
                  <span className="text-red-400 flex items-center gap-1 text-[10px]">
                    <XCircle className="w-3 h-3" />
                    <span>POLICY REJECTED</span>
                  </span>
                )}
              </div>

              {policyDecision && (
                <div className="text-[11px] font-mono space-y-1">
                  <div className="text-slate-400">
                    Target: <code>{policyDecision.targetNormalized}</code>
                  </div>
                  {policyDecision.reasons.length > 0 && (
                    <div className="text-red-400 text-[10px] space-y-0.5">
                      {policyDecision.reasons.map((r, i) => (
                        <div key={i}>&bull; {r}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Authorization Confirmation Gate */}
            <div className="p-3.5 bg-sky-950/20 border border-sky-800/40 rounded-lg space-y-2">
              <div className="flex items-start gap-2">
                <input
                  type="checkbox"
                  id="authConfirm"
                  checked={authorizationConfirmed}
                  onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
                  className="mt-0.5 rounded text-sky-500 focus:ring-0"
                />
                <label htmlFor="authConfirm" className="text-xs text-sky-200 font-medium cursor-pointer">
                  Authorization Gate Confirmation
                </label>
              </div>
              <p className="text-[10px] text-sky-400/80 leading-relaxed pl-5">
                I acknowledge ownership or explicit security assessment authorization for this target. Actions are logged to audit trail.
              </p>
            </div>

            <button
              type="submit"
              disabled={!authorizationConfirmed || !policyDecision?.allowed}
              className={`w-full py-2.5 rounded-lg text-xs font-bold font-mono transition-colors flex items-center justify-center gap-2 ${
                authorizationConfirmed && policyDecision?.allowed
                  ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-sm shadow-sky-950/50 cursor-pointer'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed'
              }`}
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>LAUNCH SCAN JOBS</span>
            </button>
          </form>
        </div>

        {/* Right 2 Cols: Active & Recent Scan Jobs Monitor */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
              <Terminal className="w-4 h-4 text-sky-400" />
              <span>Scan Orchestration Stream & Logs</span>
            </h2>

            <div className="space-y-4">
              {scans.length === 0 ? (
                <div className="py-12 text-center text-slate-500 text-xs font-mono">
                  No scan jobs currently queued or completed.
                </div>
              ) : (
                scans.map((scan) => (
                  <div key={scan.id} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white">{scan.assetName}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            {scan.profile}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                          ID: <code>{scan.id}</code> &bull; Target: <code>{scan.assetIdentifier}</code>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                            scan.status === 'COMPLETED'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                              : scan.status === 'RUNNING'
                              ? 'bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse'
                              : 'bg-red-500/10 text-red-400 border-red-500/20'
                          }`}
                        >
                          {scan.status}
                        </span>

                        {scan.status === 'RUNNING' && (
                          <button
                            onClick={() => onCancelScan(scan.id)}
                            className="text-[10px] font-mono text-red-400 hover:underline"
                          >
                            Cancel
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Jobs Terminal Output */}
                    <div className="space-y-2">
                      {scan.jobs.map((job) => (
                        <div key={job.id} className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                          <div className="flex items-center justify-between text-xs font-mono font-semibold text-slate-300">
                            <span className="flex items-center gap-1.5">
                              <Cpu className="w-3.5 h-3.5 text-sky-400" />
                              <span>{job.scannerName}</span>
                            </span>
                            <span className="text-[10px] text-emerald-400 font-normal">
                              Findings: {job.findingsCount}
                            </span>
                          </div>

                          {/* Terminal Window */}
                          <div className="bg-black/80 rounded p-2.5 font-mono text-[11px] text-sky-300/90 leading-relaxed max-h-32 overflow-y-auto space-y-1">
                            {job.logs.map((log, idx) => (
                              <div key={idx}>&gt; {log}</div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
