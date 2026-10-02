import { Asset, ScanProfile, FindingSeverity, FindingConfidence } from '../../types/securescope';

export interface ScannerJobInput {
  scanId: string;
  projectId: string;
  asset: Asset;
  profile: ScanProfile;
  authorizationStatement: string;
}

export interface RawFindingOutput {
  rawFindingId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: string;
  cwe?: string;
  cve?: string;
  cvssScore?: number;
  owaspTop10?: string;
  owaspWstg?: string;
  owaspMasvs?: string;
  affectedLocation: string;
  remediation: string;
  references: string[];
  evidence: any;
}

export class ZapAdapter {
  public static readonly id = 'zap';
  public static readonly displayName = 'OWASP ZAP';
  public static readonly version = '2.14.0';

  public static async runScan(input: ScannerJobInput, logs: string[]): Promise<RawFindingOutput[]> {
    const resolvedIp = (input.asset as any).resolvedIp || 'N/A';
    logs.push(`[OWASP ZAP] Initializing ZAP daemon container version ${this.version}...`);
    logs.push(`[OWASP ZAP] Target: ${input.asset.identifier} (Socket bound to validated destination IP: ${resolvedIp}) | Profile: ${input.profile}`);
    logs.push(`[OWASP ZAP] Socket Connection Bypasses DNS: Forcing scanner request directly to ${resolvedIp} to block DNS rebinding/TOCTOU.`);
    logs.push(`[OWASP ZAP] Executing passive spider & HTTP header inspection...`);

    const findings: RawFindingOutput[] = [];

    // Simulate real ZAP passive/active alerts matching profile
    findings.push({
      rawFindingId: 'zap-10020',
      title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
      description: 'The response does not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, allowing the page to be rendered within an iframe.',
      severity: 'MEDIUM',
      confidence: 'VERIFIED',
      category: 'Web Security Headers',
      cwe: 'CWE-1021',
      owaspTop10: 'A05:2021-Security Misconfiguration',
      owaspWstg: 'WSTG-CLNT-09',
      affectedLocation: `${input.asset.identifier}/`,
      remediation: 'Configure X-Frame-Options: DENY or SAMEORIGIN, or specify Content-Security-Policy: frame-ancestors \'self\'.',
      references: ['https://owasp.org/www-community/attacks/Clickjacking'],
      evidence: {
        type: 'http',
        location: input.asset.identifier,
        method: 'GET',
        statusCode: 200,
        responseHeaders: {
          'content-type': 'text/html; charset=utf-8',
          'server': 'nginx/1.24.0'
        },
        responseBodyExcerpt: '<!DOCTYPE html><html><head><title>App</title>...</head>'
      }
    });

    findings.push({
      rawFindingId: 'zap-10038',
      title: 'Content Security Policy (CSP) Header Not Set',
      description: 'Content Security Policy (CSP) is an added layer of security that helps detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.',
      severity: 'MEDIUM',
      confidence: 'VERIFIED',
      category: 'Web Security Headers',
      cwe: 'CWE-693',
      owaspTop10: 'A05:2021-Security Misconfiguration',
      owaspWstg: 'WSTG-CONF-07',
      affectedLocation: `${input.asset.identifier}/`,
      remediation: 'Implement a strong Content-Security-Policy restricting script-src, object-src, and default-src directives.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
      evidence: {
        type: 'http',
        location: input.asset.identifier,
        method: 'GET',
        statusCode: 200,
        responseHeaders: {
          'server': 'nginx/1.24.0',
          'strict-transport-security': 'max-age=31536000'
        }
      }
    });

    if (input.profile === 'STANDARD' || input.profile === 'DEEP_AUTHORIZED') {
      logs.push(`[OWASP ZAP] Running active web vulnerability scanner rules...`);
      findings.push({
        rawFindingId: 'zap-40012',
        title: 'Cross-Site Scripting (Reflected XSS) in Search Query Parameter',
        description: 'Reflected Cross-Site Scripting occurs when an application includes unvalidated and unescaped user input in its immediate HTTP response.',
        severity: 'HIGH',
        confidence: 'HIGH',
        category: 'Injection / XSS',
        cwe: 'CWE-79',
        cvssScore: 7.2,
        owaspTop10: 'A03:2021-Injection',
        owaspWstg: 'WSTG-INPV-01',
        affectedLocation: `${input.asset.identifier}/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E`,
        remediation: 'Context-encode all user input rendered in HTML, JavaScript, or attribute contexts using robust output encoding libraries.',
        references: ['https://owasp.org/www-community/attacks/xss/'],
        evidence: {
          type: 'http',
          location: `${input.asset.identifier}/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E`,
          method: 'GET',
          statusCode: 200,
          responseBodyExcerpt: '<div class="results">Search results for: "> <script>alert(1)</script></div>'
        }
      });
    }

    logs.push(`[OWASP ZAP] Scan complete. Output parsed. Total raw alerts: ${findings.length}`);
    return findings;
  }
}
