import React from 'react';
import { History, Cpu, Shield, Lock, CheckCircle2 } from 'lucide-react';
import { AuditEvent, ScannerRegistryEntry } from '../types/securescope';

interface AuditViewProps {
  auditLogs: AuditEvent[];
  scanners: ScannerRegistryEntry[];
}

export const AuditView: React.FC<AuditViewProps> = ({ auditLogs, scanners }) => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <History className="w-5 h-5 text-sky-400" />
            <span>Immutable Audit Trail & System Event Stream</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Timestamped history recording target scope declarations, authorization gate acknowledgments, scan launches, and finding status updates.
          </p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
          <Lock className="w-4 h-4 text-emerald-400" />
          <span>Audit Log History ({auditLogs.length})</span>
        </h2>

        <div className="space-y-2 font-mono text-xs">
          {auditLogs.length === 0 ? (
            <div className="py-8 text-center text-slate-500">No audit events recorded yet.</div>
          ) : (
            auditLogs.map((log) => (
              <div
                key={log.id}
                className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sky-400 font-bold">{log.action}</span>
                    <span className="text-slate-500">&bull;</span>
                    <span className="text-slate-200">{log.actorName} ({log.actorEmail})</span>
                  </div>
                  <div className="text-slate-400 text-[11px]">{log.details}</div>
                </div>

                <div className="text-[10px] text-slate-500 shrink-0">
                  {new Date(log.timestamp).toLocaleString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
