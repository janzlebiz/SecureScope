import React, { useState } from 'react';
import { FileText, Download, Printer, FileSpreadsheet, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { Scan, Project, Finding } from '../types/securescope';

interface ReportsViewProps {
  scans: Scan[];
  projects: Project[];
  findings: Finding[];
  activeToken: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ scans, projects, findings, activeToken }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');
  const [reportFormat, setReportFormat] = useState<'HTML' | 'JSON' | 'CSV'>('HTML');

  const selectedScan = scans.find((s) => s.id === selectedScanId);
  const scanFindings = findings.filter((f) => f.scanId === selectedScanId);

  const handleExport = () => {
    if (!selectedScanId) return;

    const url = `/api/reports/generate?scanId=${selectedScanId}&format=${reportFormat}&token=${activeToken}`;
    if (reportFormat === 'HTML') {
      window.open(url, '_blank');
    } else {
      window.location.href = url;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-400" />
            <span>Reports & Security Artifact Exporter</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Generate executive reports, auditor proof documents, and machine-readable JSON/CSV artifacts.
          </p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-2xl mx-auto space-y-5">
        <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
          <ShieldCheck className="w-4 h-4 text-sky-400" />
          <span>Export Assessment Artifact</span>
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Select Completed Scan Run</label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg p-2.5 focus:outline-none focus:border-sky-500 font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.assetName} ({s.profile}) &bull; {new Date(s.startedAt).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">Export Format</label>
            <div className="grid grid-cols-3 gap-3 font-mono text-xs">
              <button
                type="button"
                onClick={() => setReportFormat('HTML')}
                className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 transition-colors ${
                  reportFormat === 'HTML'
                    ? 'bg-sky-500/10 border-sky-500/30 text-white font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <Printer className="w-4 h-4 text-sky-400" />
                <span>HTML / PDF Print</span>
              </button>

              <button
                type="button"
                onClick={() => setReportFormat('CSV')}
                className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 transition-colors ${
                  reportFormat === 'CSV'
                    ? 'bg-sky-500/10 border-sky-500/30 text-white font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                <span>CSV Spreadsheet</span>
              </button>

              <button
                type="button"
                onClick={() => setReportFormat('JSON')}
                className={`p-3 rounded-lg border flex flex-col items-center gap-1.5 transition-colors ${
                  reportFormat === 'JSON'
                    ? 'bg-sky-500/10 border-sky-500/30 text-white font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <Download className="w-4 h-4 text-purple-400" />
                <span>JSON Artifact</span>
              </button>
            </div>
          </div>

          {selectedScan && (
            <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1 font-mono">
              <div className="text-slate-400">Target: <code>{selectedScan.assetIdentifier}</code></div>
              <div className="text-slate-400">Authorized By: {selectedScan.initiatedByName}</div>
              <div className="text-sky-400">Correlated Findings Included: {scanFindings.length}</div>
            </div>
          )}

          <button
            onClick={handleExport}
            disabled={!selectedScanId}
            className="w-full py-2.5 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-lg transition-colors font-mono flex items-center justify-center gap-2 shadow-sm shadow-sky-950/50"
          >
            <Download className="w-4 h-4" />
            <span>EXPORT {reportFormat} REPORT</span>
          </button>
        </div>
      </div>
    </div>
  );
};
