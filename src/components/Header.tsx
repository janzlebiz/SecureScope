import React from 'react';
import { Shield, ShieldAlert, Zap, Lock, RefreshCw, Plus, UserCheck } from 'lucide-react';
import { Project } from '../types/securescope';

interface HeaderProps {
  projects: Project[];
  selectedProject: Project | null;
  onSelectProject: (p: Project) => void;
  onOpenNewScan: () => void;
  onOpenNewProject: () => void;
  activeRole: 'owner' | 'admin' | 'analyst' | 'viewer';
  onSelectRole: (role: 'owner' | 'admin' | 'analyst' | 'viewer') => void;
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  selectedProject,
  onSelectProject,
  onOpenNewScan,
  onOpenNewProject,
  activeRole,
  onSelectRole
}) => {
  return (
    <header className="h-16 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Zone 1: Brand Wordmark */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="text-lg font-bold tracking-tight text-white font-sans">
              SecureScope
            </span>
            <span className="hidden sm:inline-block ml-2 text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              AAA ENFORCED
            </span>
          </div>
        </div>

        {/* Project Selector */}
        <div className="hidden md:flex items-center gap-2 border-l border-slate-800 pl-4 ml-2">
          <span className="text-xs text-slate-400 uppercase tracking-wider font-mono font-bold">Scope:</span>
          <select
            value={selectedProject?.id || ''}
            onChange={(e) => {
              const proj = projects.find((p) => p.id === e.target.value);
              if (proj) onSelectProject(proj);
            }}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-md px-3 py-1.5 focus:outline-none focus:border-sky-500 font-medium"
          >
            {projects.length > 0 ? (
              projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))
            ) : (
              <option value="">No authorized projects</option>
            )}
          </select>
        </div>
      </div>

      {/* Zone 2: Identity Simulator Switcher & Actions */}
      <div className="flex items-center gap-3">
        {/* Real-time RBAC Switcher (SS-01) */}
        <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg p-1">
          <div className="flex items-center gap-1 text-[11px] text-slate-400 font-mono pl-2 pr-1 font-bold uppercase tracking-wider">
            <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden lg:inline">Simulated User:</span>
          </div>
          <select
            value={activeRole}
            onChange={(e) => onSelectRole(e.target.value as any)}
            className="bg-slate-900 border border-slate-800 text-slate-200 text-[11px] rounded px-2.5 py-1 focus:outline-none focus:border-sky-500 font-bold uppercase font-mono"
          >
            <option value="owner">Alex Mercer (OWNER)</option>
            <option value="admin">Sarah Chen (ADMIN)</option>
            <option value="analyst">Frank Castle (ANALYST)</option>
            <option value="viewer">Jane Doe (VIEWER)</option>
          </select>
        </div>

        <button
          onClick={onOpenNewProject}
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors font-sans"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Project</span>
        </button>

        <button
          onClick={onOpenNewScan}
          className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg shadow-sm shadow-sky-950/50 transition-colors whitespace-nowrap font-sans"
        >
          <Zap className="w-3.5 h-3.5 fill-current" />
          <span>Run Assessment</span>
        </button>
      </div>
    </header>
  );
};
