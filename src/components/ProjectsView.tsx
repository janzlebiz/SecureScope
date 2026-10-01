import React, { useState } from 'react';
import {
  FolderGit2,
  Plus,
  Globe,
  Server,
  Smartphone,
  Code2,
  ShieldCheck,
  Lock,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { Project, Asset, AssetType, Environment } from '../types/securescope';

interface ProjectsViewProps {
  projects: Project[];
  assets: Asset[];
  selectedProject: Project | null;
  onSelectProject: (p: Project) => void;
  onCreateProject: (name: string, description: string) => void;
  onAddAsset: (asset: {
    projectId: string;
    name: string;
    type: AssetType;
    identifier: string;
    environment: Environment;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }) => void;
  onOpenScanForAsset: (asset: Asset) => void;
}

export const ProjectsView: React.FC<ProjectsViewProps> = ({
  projects,
  assets,
  selectedProject,
  onSelectProject,
  onCreateProject,
  onAddAsset,
  onOpenScanForAsset
}) => {
  const [showNewProjectModal, setShowNewProjectModal] = useState(false);
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);

  // New Project State
  const [projectName, setProjectName] = useState('');
  const [projectDesc, setProjectDesc] = useState('');

  // New Asset State
  const [assetName, setAssetName] = useState('');
  const [assetType, setAssetType] = useState<AssetType>('WEB_URL');
  const [assetIdentifier, setAssetIdentifier] = useState('');
  const [assetEnv, setAssetEnv] = useState<Environment>('STAGING');
  const [assetCrit, setAssetCrit] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');

  const currentProjectAssets = assets.filter((a) => a.projectId === selectedProject?.id);

  const handleCreateProject = (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) return;
    onCreateProject(projectName, projectDesc);
    setProjectName('');
    setProjectDesc('');
    setShowNewProjectModal(false);
  };

  const handleAddAsset = (e: React.FormEvent) => {
    e.preventDefault();
    if (!assetName.trim() || !assetIdentifier.trim() || !selectedProject) return;
    onAddAsset({
      projectId: selectedProject.id,
      name: assetName,
      type: assetType,
      identifier: assetIdentifier,
      environment: assetEnv,
      criticality: assetCrit
    });
    setAssetName('');
    setAssetIdentifier('');
    setShowAddAssetModal(false);
  };

  const getAssetIcon = (type: AssetType) => {
    switch (type) {
      case 'WEB_URL':
        return <Globe className="w-4 h-4 text-sky-400" />;
      case 'API_ENDPOINT':
        return <Server className="w-4 h-4 text-emerald-400" />;
      case 'MOBILE_PACKAGE':
        return <Smartphone className="w-4 h-4 text-purple-400" />;
      case 'SOURCE_REPO':
        return <Code2 className="w-4 h-4 text-amber-400" />;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <FolderGit2 className="w-5 h-5 text-sky-400" />
            <span>Projects & Authorized Target Asset Inventory</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage target domains, API bases, mobile binaries, and code repos with associated Scope Policies.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowNewProjectModal(true)}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Project</span>
          </button>

          <button
            onClick={() => setShowAddAssetModal(true)}
            className="px-3.5 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 shadow-sm shadow-sky-950/50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Target Asset</span>
          </button>
        </div>
      </div>

      {/* Workspace Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Left Column: Project List */}
        <div className="md:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider px-2">
            Workspaces ({projects.length})
          </div>

          <div className="space-y-1.5">
            {projects.map((p) => {
              const isSelected = p.id === selectedProject?.id;
              const assetCount = assets.filter((a) => a.projectId === p.id).length;
              return (
                <button
                  key={p.id}
                  onClick={() => onSelectProject(p)}
                  className={`w-full text-left p-3 rounded-lg border transition-colors flex items-center justify-between group ${
                    isSelected
                      ? 'bg-sky-500/10 border-sky-500/30 text-white'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  }`}
                >
                  <div className="truncate pr-2">
                    <div className="text-xs font-semibold truncate group-hover:text-sky-400 transition-colors">
                      {p.name}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">
                      {assetCount} Asset{assetCount !== 1 ? 's' : ''}
                    </div>
                  </div>
                  <ChevronRight className={`w-4 h-4 shrink-0 ${isSelected ? 'text-sky-400' : 'text-slate-600'}`} />
                </button>
              );
            })}
          </div>
        </div>

        {/* Right 3 Cols: Active Project Details & Target Assets */}
        <div className="md:col-span-3 space-y-6">
          {/* Active Project Scope Policy Card */}
          {selectedProject && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-bold text-white">{selectedProject.name}</h2>
                  <p className="text-xs text-slate-400 mt-0.5">{selectedProject.description}</p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Lead: {selectedProject.ownerName}
                  </span>
                </div>
              </div>

              {/* Scope Rules Summary */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase">Allowed Domains</div>
                  <div className="text-slate-200 font-semibold mt-1 truncate">
                    {selectedProject.scopePolicy.allowedDomains.join(', ') || 'Any authorized domain'}
                  </div>
                </div>

                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase">Excluded Paths</div>
                  <div className="text-slate-200 font-semibold mt-1 truncate">
                    {selectedProject.scopePolicy.excludedPaths.join(', ') || 'None'}
                  </div>
                </div>

                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase">SSRF Private IP Access</div>
                  <div className={`font-semibold mt-1 ${selectedProject.scopePolicy.allowPrivateIPs ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {selectedProject.scopePolicy.allowPrivateIPs ? 'ENABLED (Staging Override)' : 'BLOCKED (Default Strict)'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Assets Inventory Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-sky-400" />
                <span>Target Assets ({currentProjectAssets.length})</span>
              </h3>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-sans">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase">
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Asset Name</th>
                    <th className="py-2.5 px-3">Target Identifier</th>
                    <th className="py-2.5 px-3">Environment</th>
                    <th className="py-2.5 px-3">Criticality</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {currentProjectAssets.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500 text-xs">
                        No target assets registered in this project yet.
                      </td>
                    </tr>
                  ) : (
                    currentProjectAssets.map((asset) => (
                      <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-3">
                          <div className="p-1.5 rounded bg-slate-800/80 inline-block">
                            {getAssetIcon(asset.type)}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-semibold text-white">{asset.name}</td>
                        <td className="py-3 px-3 font-mono text-slate-300">
                          <code>{asset.identifier}</code>
                        </td>
                        <td className="py-3 px-3">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {asset.environment}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              asset.criticality === 'CRITICAL'
                                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                                : asset.criticality === 'HIGH'
                                ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                          >
                            {asset.criticality}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => onOpenScanForAsset(asset)}
                            className="px-2.5 py-1 text-[11px] font-mono font-medium text-sky-400 bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 rounded transition-colors"
                          >
                            Scan
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Create Project Modal */}
      {showNewProjectModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full space-y-4">
            <h2 className="text-base font-bold text-white">Create New Project</h2>
            <form onSubmit={handleCreateProject} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Project Name *</label>
                <input
                  type="text"
                  required
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  placeholder="e.g. Mobile Banking App"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={projectDesc}
                  onChange={(e) => setProjectDesc(e.target.value)}
                  placeholder="Target scope summary and ownership details..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewProjectModal(false)}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-lg"
                >
                  Create Project
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Asset Modal */}
      {showAddAssetModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full space-y-4">
            <h2 className="text-base font-bold text-white">Register Target Asset</h2>
            <form onSubmit={handleAddAsset} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Asset Name *</label>
                <input
                  type="text"
                  required
                  value={assetName}
                  onChange={(e) => setAssetName(e.target.value)}
                  placeholder="e.g. Staging Auth Portal"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value as AssetType)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500"
                  >
                    <option value="WEB_URL">Web App URL</option>
                    <option value="API_ENDPOINT">REST / GraphQL API Base</option>
                    <option value="MOBILE_PACKAGE">Android APK / iOS IPA</option>
                    <option value="SOURCE_REPO">Git Repository / ZIP Archive</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Environment</label>
                  <select
                    value={assetEnv}
                    onChange={(e) => setAssetEnv(e.target.value as Environment)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-sky-500"
                  >
                    <option value="DEVELOPMENT">Development</option>
                    <option value="STAGING">Staging</option>
                    <option value="PRODUCTION">Production</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Target Identifier *</label>
                <input
                  type="text"
                  required
                  value={assetIdentifier}
                  onChange={(e) => setAssetIdentifier(e.target.value)}
                  placeholder={
                    assetType === 'WEB_URL' || assetType === 'API_ENDPOINT'
                      ? 'https://app.example.com'
                      : assetType === 'MOBILE_PACKAGE'
                      ? 'com.example.app.apk'
                      : 'https://github.com/example/repo.git'
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddAssetModal(false)}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-lg"
                >
                  Add Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
