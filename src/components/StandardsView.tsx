import React from 'react';
import { BookOpen, CheckCircle2, ShieldCheck, ExternalLink } from 'lucide-react';
import { Finding } from '../types/securescope';

interface StandardsViewProps {
  findings: Finding[];
}

export const StandardsView: React.FC<StandardsViewProps> = ({ findings }) => {
  const owaspCategories = [
    {
      code: 'A01:2021',
      title: 'Broken Access Control',
      count: findings.filter((f) => (f.owaspTop10 || '').includes('A01') || (f.category || '').includes('Access')).length
    },
    {
      code: 'A02:2021',
      title: 'Cryptographic Failures',
      count: findings.filter((f) => (f.owaspTop10 || '').includes('A02') || (f.category || '').includes('Crypto') || (f.category || '').includes('Secrets')).length
    },
    {
      code: 'A03:2021',
      title: 'Injection (SQL, XSS, Command)',
      count: findings.filter((f) => (f.owaspTop10 || '').includes('A03') || (f.category || '').includes('Injection')).length
    },
    {
      code: 'A05:2021',
      title: 'Security Misconfiguration',
      count: findings.filter((f) => (f.owaspTop10 || '').includes('A05') || (f.category || '').includes('Headers') || (f.category || '').includes('Misconfig')).length
    },
    {
      code: 'A06:2021',
      title: 'Vulnerable & Outdated Components',
      count: findings.filter((f) => (f.owaspTop10 || '').includes('A06') || (f.category || '').includes('SCA') || (f.category || '').includes('Dependency')).length
    },
    {
      code: 'MASVS-STORAGE',
      title: 'OWASP MASVS Mobile Storage Security',
      count: findings.filter((f) => (f.owaspMasvs || '').includes('STORAGE') || (f.category || '').includes('Mobile Storage')).length
    },
    {
      code: 'MASVS-NETWORK',
      title: 'OWASP MASVS Mobile Network Security',
      count: findings.filter((f) => (f.owaspMasvs || '').includes('NETWORK') || (f.category || '').includes('Mobile Network')).length
    }
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-sky-400" />
            <span>Standards & Compliance Framework Mapping</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated alignment of findings to OWASP Top 10 (2021), OWASP WSTG, OWASP MASVS (Mobile), and CWE IDs.
          </p>
        </div>
      </div>

      {/* Standards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {owaspCategories.map((std) => (
          <div
            key={std.code}
            className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-2 py-0.5 rounded">
                  {std.code}
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {std.count} Finding{std.count !== 1 ? 's' : ''}
                </span>
              </div>
              <h3 className="text-sm font-bold text-white mt-2.5">{std.title}</h3>
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-400">Compliance Status:</span>
              <span className={std.count > 0 ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                {std.count > 0 ? `${std.count} Issues Detected` : 'Nominal / Passed'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
