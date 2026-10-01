import { ReportModel, Scan, Project, Finding } from '../../types/securescope';

export class ReportGenerator {
  public static generateReportModel(
    scan: Scan,
    project: Project,
    findings: Finding[]
  ): ReportModel {
    const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
    const high = findings.filter((f) => f.severity === 'HIGH').length;
    const medium = findings.filter((f) => f.severity === 'MEDIUM').length;

    let executiveSummary = `SecureScope conducted an authorized automated security assessment of asset '${scan.assetName}' (${scan.assetIdentifier}) on ${new Date(scan.startedAt).toLocaleDateString()} using the '${scan.profile}' scan profile. `;
    
    if (critical > 0 || high > 0) {
      executiveSummary += `The assessment identified ${critical} CRITICAL and ${high} HIGH severity findings that require immediate technical remediation to prevent potential unauthorized access or data exposure. `;
    } else if (medium > 0) {
      executiveSummary += `The assessment identified ${medium} MEDIUM severity findings related to security misconfigurations and best practices. No critical vulnerabilities were detected during this run. `;
    } else {
      executiveSummary += `No critical or high severity vulnerabilities were identified during this assessment. Continued monitoring and regular standard scans are recommended.`;
    }

    return {
      title: `Security Assessment Report — ${scan.assetName}`,
      generatedAt: new Date().toISOString(),
      projectId: project.id,
      projectName: project.name,
      scanId: scan.id,
      scanProfile: scan.profile,
      assetName: scan.assetName,
      assetIdentifier: scan.assetIdentifier,
      executiveSummary,
      findings,
      scannersUsed: scan.jobs.map((j) => ({ name: j.scannerName, version: '1.0' })),
      limitations: 'Automated security testing provides point-in-time assessment based on configured scanner rule sets and scope constraints. It should be complemented with periodic manual penetration testing and code reviews.',
      scopeConfirmedBy: scan.initiatedByName
    };
  }

  public static exportHtmlReport(model: ReportModel): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${model.title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.6; margin: 0; padding: 40px; background: #f8fafc; }
    .container { max-width: 1000px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 40px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .header { border-b: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }
    .brand { font-size: 24px; font-weight: 800; color: #0f172a; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: #64748b; font-weight: 500; }
    .summary-box { background: #f1f5f9; border-left: 4px solid #0ea5e9; padding: 20px; border-radius: 4px; margin-bottom: 30px; }
    .section-title { font-size: 18px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 30px; margin-bottom: 15px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    th { background: #0f172a; color: #ffffff; text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    td { padding: 12px 14px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-family: monospace; }
    .CRITICAL { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .HIGH { background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }
    .MEDIUM { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
    .LOW { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .INFO { background: #f0f9ff; color: #0284c7; border: 1px solid #bae6fd; }
    .evidence { background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; }
    .footer { margin-top: 50px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="brand">SecureScope Assessment Report</div>
        <div class="subtitle">Project: ${model.projectName} | Generated: ${new Date(model.generatedAt).toLocaleString()}</div>
      </div>
      <div style="text-align: right;">
        <span class="badge INFO">${model.scanProfile}</span>
      </div>
    </div>

    <div class="section-title">Executive Summary</div>
    <div class="summary-box">
      ${model.executiveSummary}
    </div>

    <div class="section-title">Assessment Target & Scope</div>
    <table>
      <tr><th>Asset Name</th><td>${model.assetName}</td></tr>
      <tr><th>Target Identifier</th><td><code>${model.assetIdentifier}</code></td></tr>
      <tr><th>Scan ID</th><td><code>${model.scanId}</code></td></tr>
      <tr><th>Scope Authorized By</th><td>${model.scopeConfirmedBy}</td></tr>
    </table>

    <div class="section-title">Findings Inventory (${model.findings.length})</div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Title</th>
          <th>Category</th>
          <th>CWE / Standards</th>
          <th>Location</th>
        </tr>
      </thead>
      <tbody>
        ${model.findings.map(f => `
          <tr>
            <td><span class="badge ${f.severity}">${f.severity}</span></td>
            <td><strong>${f.title}</strong></td>
            <td>${f.category}</td>
            <td>${f.cwe || 'N/A'} ${f.owaspTop10 ? `<br><small>${f.owaspTop10}</small>` : ''}</td>
            <td><code>${f.affectedLocation}</code></td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <div class="section-title">Detailed Vulnerability Findings</div>
    ${model.findings.map((f, i) => `
      <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 6px; margin-bottom: 20px; background: #ffffff;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <h3 style="margin: 0; font-size: 16px;">${i + 1}. ${f.title}</h3>
          <span class="badge ${f.severity}">${f.severity}</span>
        </div>
        <p style="font-size: 13px; color: #475569; margin-bottom: 15px;">${f.description}</p>
        
        <div style="margin-bottom: 10px; font-size: 13px;"><strong>Remediation:</strong> ${f.remediation}</div>
        
        ${f.occurrences && f.occurrences[0] && f.occurrences[0].evidence ? `
          <div style="font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 5px;">Source Evidence (${f.occurrences[0].scannerName}):</div>
          <div class="evidence">${typeof f.occurrences[0].evidence === 'string' ? f.occurrences[0].evidence : JSON.stringify(f.occurrences[0].evidence, null, 2)}</div>
        ` : ''}
      </div>
    `).join('')}

    <div class="section-title">Limitations & Assessment Disclaimer</div>
    <p style="font-size: 12px; color: #64748b;">${model.limitations}</p>

    <div class="footer">
      Generated automatically by SecureScope Authorized Security Assessment Platform &bull; Confidential &bull; Target: ${model.assetIdentifier}
    </div>
  </div>
</body>
</html>`;
  }

  public static exportCsvReport(findings: Finding[]): string {
    const headers = ['ID', 'Severity', 'Title', 'Category', 'CWE', 'OWASP', 'Location', 'Status', 'Remediation'];
    const rows = findings.map((f) => [
      f.id,
      f.severity,
      `"${f.title.replace(/"/g, '""')}"`,
      `"${f.category.replace(/"/g, '""')}"`,
      f.cwe || '',
      f.owaspTop10 || '',
      `"${f.affectedLocation.replace(/"/g, '""')}"`,
      f.status,
      `"${f.remediation.replace(/"/g, '""')}"`
    ]);

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }
}
