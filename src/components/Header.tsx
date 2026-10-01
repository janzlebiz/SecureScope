import React from 'react';
import { Shield, ShieldAlert, Zap, Lock, RefreshCw, Plus } from 'lucide-react';
import { Project } from '../types/securescope';

interface HeaderProps {
  projects: Project[];
  selectedProject: Project | null;
  onSelectProject: (p: Project) => void;
  onOpenNewScan: () => void;
  onOpenNewProject: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  selectedProject,
  onSelectProject,
  onOpenNewScan,
  onOpenNewProject
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
              SCOPE ENFORCED
            </span>
          </div>
        </div>

        {/* Project Selector */}
        <div className="hidden md:flex items-center gap-2 border-l border-slate-800 pl-4 ml-2">
          <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">Workspace:</span>
          <select
            value={selectedProject?.id || ''}
            onChange={(e) => {
              const proj = projects.find((p) => p.id === e.target.value);
              if (proj) onSelectProject(proj);
            }}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-md px-3 py-1.5 focus:outline-none focus:border-sky-500 font-medium"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Zone 2: Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenNewProject}
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Project</span>
        </button>

        <button
          onClick={onOpenNewScan}
          className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg shadow-sm shadow-sky-950/50 transition-colors whitespace-nowrap"
        >
          <Zap className="w-3.5 h-3.5 fill-current" />
          <span>Run Assessment</span>
        </button>
      </div>
    </header>
  );
};
