import React, { useState } from 'react';
import { Sparkles, Send, ShieldCheck, AlertTriangle, FileText, CheckCircle2 } from 'lucide-react';
import { Finding, Scan } from '../types/securescope';

interface AiAdvisorViewProps {
  findings: Finding[];
  scans: Scan[];
  onAnalyzeFinding: (findingId: string) => Promise<any>;
  onGenerateExecutiveSummary: (scanId: string) => Promise<string>;
}

export const AiAdvisorView: React.FC<AiAdvisorViewProps> = ({
  findings,
  scans,
  onAnalyzeFinding,
  onGenerateExecutiveSummary
}) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');
  const [executiveSummary, setExecutiveSummary] = useState<string>('');
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false);

  const [selectedFindingId, setSelectedFindingId] = useState<string>(findings[0]?.id || '');
  const [isAnalyzingFinding, setIsAnalyzingFinding] = useState(false);
  const [findingAnalysisResult, setFindingAnalysisResult] = useState<any>(null);

  const handleGenerateSummary = async () => {
    if (!selectedScanId) return;
    setIsGeneratingSummary(true);
    const result = await onGenerateExecutiveSummary(selectedScanId);
    setExecutiveSummary(result);
    setIsGeneratingSummary(false);
  };

  const handleAnalyzeFinding = async () => {
    if (!selectedFindingId) return;
    setIsAnalyzingFinding(true);
    const result = await onAnalyzeFinding(selectedFindingId);
    setFindingAnalysisResult(result);
    setIsAnalyzingFinding(false);
  };

  const activeFinding = findings.find((f) => f.id === selectedFindingId);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-sky-400" />
            <span>AI Security Analyst Studio</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Server-side Gemini AI risk interpretation, developer patch generation, and executive report synthesis.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Col: CISO Executive Summary Generator */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <FileText className="w-4 h-4 text-sky-400" />
            <span>Executive Assessment Briefing Generator</span>
          </h2>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Select Completed Assessment Run</label>
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

            <button
              onClick={handleGenerateSummary}
              disabled={isGeneratingSummary || !selectedScanId}
              className="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isGeneratingSummary ? 'Synthesizing Briefing...' : 'Generate Executive Briefing'}</span>
            </button>

            {executiveSummary && (
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 space-y-2 leading-relaxed whitespace-pre-wrap">
                <div className="font-mono text-[10px] text-sky-400 font-bold uppercase">Executive Summary</div>
                <div>{executiveSummary}</div>
              </div>
            )}
          </div>
        </div>

        {/* Right Col: Deep Technical Patch & Finding Analyzer */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            <span>Developer Code Patch & Remediation Guidance</span>
          </h2>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Select Vulnerability Finding</label>
              <select
                value={selectedFindingId}
                onChange={(e) => setSelectedFindingId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg p-2.5 focus:outline-none focus:border-sky-500 font-mono"
              >
                {findings.map((f) => (
                  <option key={f.id} value={f.id}>
                    [{f.severity}] {f.title} ({f.cwe || f.category})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleAnalyzeFinding}
              disabled={isAnalyzingFinding || !selectedFindingId}
              className="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isAnalyzingFinding ? 'Analyzing Finding...' : 'Generate Code Patch & Fix Steps'}</span>
            </button>

            {findingAnalysisResult && (
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-3">
                <div>
                  <div className="font-mono text-[10px] text-sky-400 uppercase font-bold">Analysis</div>
                  <p className="text-slate-200 mt-0.5 leading-relaxed">{findingAnalysisResult.summary}</p>
                </div>

                <div>
                  <div className="font-mono text-[10px] text-sky-400 uppercase font-bold">Business Risk</div>
                  <p className="text-slate-300 mt-0.5 leading-relaxed">{findingAnalysisResult.businessImpact}</p>
                </div>

                {findingAnalysisResult.remediationCodeSnippet && (
                  <div>
                    <div className="font-mono text-[10px] text-sky-400 uppercase font-bold mb-1">Code Patch</div>
                    <pre className="bg-black/90 p-3 rounded border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                      {findingAnalysisResult.remediationCodeSnippet}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
