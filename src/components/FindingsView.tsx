import { useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  AlertOctagon,
  Eye,
  ExternalLink,
  Sparkles,
  Layers
} from 'lucide-react';
import { Finding, FindingSeverity, FindingStatus } from '../types/securescope';

interface FindingsViewProps {
  findings: Finding[];
  onSelectFinding: (f: Finding) => void;
  onUpdateStatus: (id: string, status: FindingStatus) => void;
}

export const FindingsView = ({
  findings,
  onSelectFinding,
  onUpdateStatus
}: FindingsViewProps) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.affectedLocation.toLowerCase().includes(search.toLowerCase()) ||
      (f.cwe || '').toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Correlated Security Findings ({filteredFindings.length})</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deduplicated vulnerability results compiled from OWASP ZAP, Nuclei, MobSF, Semgrep, and Trivy.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        {/* Search Input */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, CWE, or location..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 w-full md:w-auto overflow-x-auto">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap ${
                severityFilter === sev
                  ? 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-sky-500 font-mono"
        >
          <option value="ALL">All Statuses</option>
          <option value="OPEN">OPEN</option>
          <option value="CONFIRMED">CONFIRMED</option>
          <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          <option value="REMEDIATED">REMEDIATED</option>
        </select>
      </div>

      {/* Findings Data Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono text-slate-400 uppercase">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title & Description</th>
                <th className="py-3 px-4">Category / CWE</th>
                <th className="py-3 px-4">Standards</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 text-xs font-mono">
                    No findings match current search and filter constraints.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectFinding(finding)}
                  >
                    <td className="py-3.5 px-4">
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
                    </td>

                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-semibold text-white group-hover:text-sky-400 transition-colors truncate">
                        {finding.title}
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {finding.description}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      <div>{finding.category}</div>
                      <div className="text-[10px] text-slate-500">{finding.cwe || 'N/A'}</div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {finding.owaspTop10 || finding.owaspMasvs || 'OWASP Standard'}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-300 max-w-xs truncate">
                      <code>{finding.affectedLocation}</code>
                    </td>

                    <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                      <select
                        value={finding.status}
                        onChange={(e) => onUpdateStatus(finding.id, e.target.value as FindingStatus)}
                        className="bg-slate-950 border border-slate-800 text-slate-300 text-[11px] font-mono rounded px-2 py-1 focus:outline-none focus:border-sky-500"
                      >
                        <option value="OPEN">OPEN</option>
                        <option value="CONFIRMED">CONFIRMED</option>
                        <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                        <option value="REMEDIATED">REMEDIATED</option>
                      </select>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding);
                        }}
                        className="px-2.5 py-1 text-[11px] font-mono text-sky-400 hover:bg-sky-500/10 rounded transition-colors"
                      >
                        Evidence
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
  );
};
