import React, { useState } from 'react';
import {
  X,
  AlertTriangle,
  Code2,
  Sparkles,
  ShieldCheck,
  Check,
  Copy,
  ExternalLink,
  Layers
} from 'lucide-react';
import { Finding, FindingStatus } from '../types/securescope';

interface FindingDetailModalProps {
  finding: Finding;
  onClose: () => void;
  onUpdateStatus: (id: string, status: FindingStatus) => void;
  onAnalyzeWithAi: (findingId: string) => Promise<any>;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onUpdateStatus,
  onAnalyzeWithAi
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const handleRunAi = async () => {
    setIsAnalyzing(true);
    await onAnalyzeWithAi(finding.id);
    setIsAnalyzing(false);
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const firstOccurrence = finding.occurrences[0];
  const evidence = firstOccurrence?.evidence;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-3xl w-full my-8 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${
                  finding.severity === 'CRITICAL'
                    ? 'bg-red-500/10 text-red-400 border-red-500/30'
                    : finding.severity === 'HIGH'
                    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">Fingerprint: {finding.fingerprint}</span>
            </div>
            <h2 className="text-base font-bold text-white">{finding.title}</h2>
          </div>

          <button onClick={onClose} className="text-slate-400 hover:text-white p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[10px]">CWE / CVE</div>
            <div className="text-slate-200 font-semibold mt-0.5">{finding.cwe || finding.cve || 'N/A'}</div>
          </div>

          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[10px]">OWASP Mapping</div>
            <div className="text-slate-200 font-semibold mt-0.5 truncate">{finding.owaspTop10 || finding.owaspMasvs || 'OWASP Top 10'}</div>
          </div>

          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[10px]">CVSS 3.1</div>
            <div className="text-slate-200 font-semibold mt-0.5">{finding.cvssScore ? `${finding.cvssScore} / 10` : 'N/A'}</div>
          </div>

          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
            <div className="text-slate-500 text-[10px]">Scanners Correlated</div>
            <div className="text-sky-400 font-semibold mt-0.5">{finding.occurrences.length} Engine{finding.occurrences.length > 1 ? 's' : ''}</div>
          </div>
        </div>

        {/* Description & Location */}
        <div className="space-y-2">
          <div className="text-xs font-mono font-bold text-slate-300">Description</div>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
            {finding.description}
          </p>
          <div className="text-xs font-mono text-slate-400">
            Affected Location: <code>{finding.affectedLocation}</code>
          </div>
        </div>

        {/* Evidence Viewer */}
        {evidence && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono font-bold text-slate-300">
              <span className="flex items-center gap-1.5">
                <Code2 className="w-4 h-4 text-sky-400" />
                <span>Scanner Evidence Output ({firstOccurrence?.scannerName})</span>
              </span>
            </div>

            <div className="bg-black/90 p-3.5 rounded-lg border border-slate-800 font-mono text-xs text-sky-300 overflow-x-auto max-h-48 whitespace-pre-wrap">
              {evidence.type === 'source' ? (
                <div>
                  <div className="text-slate-500 text-[10px] mb-1">// {evidence.filePath}:{evidence.startLine}</div>
                  <div>{evidence.codeSnippet}</div>
                </div>
              ) : evidence.type === 'http' ? (
                <div>
                  <div className="text-slate-400">{evidence.method} {evidence.location}</div>
                  {evidence.responseHeaders && (
                    <div className="text-slate-500 text-[11px] my-1">
                      {Object.entries(evidence.responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}
                    </div>
                  )}
                  {evidence.responseBodyExcerpt && (
                    <div className="text-emerald-400/90 text-[11px] border-t border-slate-800 pt-1 mt-1">
                      {evidence.responseBodyExcerpt}
                    </div>
                  )}
                </div>
              ) : (
                <div>{JSON.stringify(evidence, null, 2)}</div>
              )}
            </div>
          </div>
        )}

        {/* AI Security Analyst Advisor Box */}
        <div className="p-4 bg-sky-950/20 border border-sky-800/40 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-300">
              <Sparkles className="w-4 h-4 text-sky-400" />
              <span>Gemini AI Security Analyst Advisory</span>
            </div>

            <button
              onClick={handleRunAi}
              disabled={isAnalyzing}
              className="px-3 py-1 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isAnalyzing ? 'Analyzing...' : finding.aiAnalysis ? 'Re-Analyze' : 'Generate AI Advisory'}</span>
            </button>
          </div>

          {finding.aiAnalysis ? (
            <div className="space-y-3 text-xs">
              <div>
                <div className="font-mono text-[10px] text-sky-400 uppercase">Executive Analysis</div>
                <p className="text-slate-200 mt-0.5 leading-relaxed">{finding.aiAnalysis.summary}</p>
              </div>

              <div>
                <div className="font-mono text-[10px] text-sky-400 uppercase">Business Risk & Impact</div>
                <p className="text-slate-300 mt-0.5 leading-relaxed">{finding.aiAnalysis.businessImpact}</p>
              </div>

              {finding.aiAnalysis.remediationCodeSnippet && (
                <div>
                  <div className="flex items-center justify-between font-mono text-[10px] text-sky-400 uppercase mb-1">
                    <span>Developer Remediation Code Patch</span>
                    <button
                      onClick={() => handleCopyCode(finding.aiAnalysis!.remediationCodeSnippet!)}
                      className="text-slate-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedCode ? 'Copied' : 'Copy Patch'}</span>
                    </button>
                  </div>
                  <pre className="bg-black/90 p-3 rounded border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                    {finding.aiAnalysis.remediationCodeSnippet}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-sky-400/80 leading-relaxed">
              Click "Generate AI Advisory" to receive plain-language explanations, business risk evaluations, and developer code patches from Gemini AI.
            </p>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-slate-800 pt-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-mono text-slate-400">Status:</span>
            <select
              value={finding.status}
              onChange={(e) => onUpdateStatus(finding.id, e.target.value as FindingStatus)}
              className="bg-slate-950 border border-slate-800 text-slate-200 font-mono rounded px-3 py-1.5 focus:outline-none focus:border-sky-500"
            >
              <option value="OPEN">OPEN</option>
              <option value="CONFIRMED">CONFIRMED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
              <option value="REMEDIATED">REMEDIATED</option>
            </select>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
