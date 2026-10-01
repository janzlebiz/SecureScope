import React from 'react';
import {
  LayoutDashboard,
  FolderGit2,
  Zap,
  AlertTriangle,
  BookOpen,
  Sparkles,
  FileText,
  History,
  Cpu
} from 'lucide-react';

export type ViewTab =
  | 'dashboard'
  | 'projects'
  | 'orchestrator'
  | 'findings'
  | 'standards'
  | 'ai-advisor'
  | 'reports'
  | 'audit'
  | 'registry';

interface SidebarProps {
  activeTab: ViewTab;
  onSelectTab: (tab: ViewTab) => void;
  openScansCount: number;
  openFindingsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  openScansCount,
  openFindingsCount
}) => {
  const navItems = [
    { id: 'dashboard' as ViewTab, label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'projects' as ViewTab, label: 'Projects & Assets', icon: FolderGit2 },
    {
      id: 'orchestrator' as ViewTab,
      label: 'Scan Orchestrator',
      icon: Zap,
      badge: openScansCount > 0 ? openScansCount : undefined,
      badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    },
    {
      id: 'findings' as ViewTab,
      label: 'Correlated Findings',
      icon: AlertTriangle,
      badge: openFindingsCount > 0 ? openFindingsCount : undefined,
      badgeColor: 'bg-red-500/20 text-red-400 border-red-500/30'
    },
    { id: 'standards' as ViewTab, label: 'Standards & Compliance', icon: BookOpen },
    { id: 'ai-advisor' as ViewTab, label: 'AI Security Analyst', icon: Sparkles },
    { id: 'reports' as ViewTab, label: 'Reports & Export', icon: FileText },
    { id: 'audit' as ViewTab, label: 'Audit Trail', icon: History },
    { id: 'registry' as ViewTab, label: 'Scanner Registry', icon: Cpu }
  ];

  return (
    <aside className="w-64 bg-slate-900/95 border-r border-slate-800 flex flex-col justify-between shrink-0 hidden md:flex">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono font-semibold text-slate-500 uppercase tracking-wider">
          Security Platform
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3 truncate">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.5 text-[10px] font-mono font-bold rounded border ${
                    item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Scope Enforcer Footer Panel */}
      <div className="p-4 m-3 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] text-slate-400 space-y-1.5">
        <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Scope Policy Engine</span>
        </div>
        <p className="text-slate-500 leading-relaxed text-[10px]">
          Target safety rules & SSRF blocking active. Private IPs require explicit scope policy override.
        </p>
      </div>
    </aside>
  );
};
