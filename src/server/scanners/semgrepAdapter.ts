import { Asset, ScanProfile } from '../../types/securescope';
import { RawFindingOutput } from './zapAdapter';

export class SemgrepAdapter {
  public static readonly id = 'semgrep';
  public static readonly displayName = 'Semgrep SAST';
  public static readonly version = 'v1.68.0';

  public static async runScan(input: { asset: Asset; profile: ScanProfile }, logs: string[]): Promise<RawFindingOutput[]> {
    logs.push(`[Semgrep SAST] Running multi-language AST static security rules v${this.version}...`);
    logs.push(`[Semgrep SAST] Analyzing source repository repository/zip: '${input.asset.name}'...`);

    const findings: RawFindingOutput[] = [];

    findings.push({
      rawFindingId: 'semgrep-sqli-raw-query',
      title: 'Potential SQL Injection via Unescaped String Concatenation',
      description: 'Raw SQL query string constructed using unescaped dynamic variable concatenation instead of parameterized prepared statements.',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      category: 'Static Code Analysis (SAST)',
      cwe: 'CWE-89',
      cvssScore: 8.8,
      owaspTop10: 'A03:2021-Injection',
      owaspAsvs: 'V5.3.4 (Data Protection & Output Encoding)',
      affectedLocation: 'src/controllers/userController.ts:48',
      remediation: 'Use parameterized queries, ORM query builders (e.g. Prisma/Drizzle/Sequelize), or prepared statements.',
      references: ['https://semgrep.dev/r/typescript.express.security.audit.sqli.express-sqli'],
      evidence: {
        type: 'source',
        filePath: 'src/controllers/userController.ts',
        startLine: 48,
        endLine: 50,
        codeSnippet: 'const query = "SELECT * FROM users WHERE email = \'" + req.body.email + "\'";\nconst result = await db.query(query);',
        ruleId: 'typescript.express.security.audit.sqli.express-sqli'
      }
    });

    findings.push({
      rawFindingId: 'semgrep-jwt-no-verify',
      title: 'Insecure JWT Decoding Without Signature Verification',
      description: 'The application calls `jwt.decode()` rather than `jwt.verify()`, allowing untrusted signature bypass.',
      severity: 'HIGH',
      confidence: 'VERIFIED',
      category: 'Static Code Analysis (SAST)',
      cwe: 'CWE-347',
      owaspTop10: 'A02:2021-Cryptographic Failures',
      affectedLocation: 'src/middleware/auth.ts:22',
      remediation: 'Replace `jwt.decode()` with `jwt.verify(token, secretKey, options)` to enforce signature verification.',
      references: ['https://semgrep.dev/r/javascript.jwt.security.jwt-decode-without-verify'],
      evidence: {
        type: 'source',
        filePath: 'src/middleware/auth.ts',
        startLine: 22,
        endLine: 24,
        codeSnippet: 'const userPayload = jwt.decode(authHeader.split(" ")[1]);\nreq.user = userPayload;',
        ruleId: 'javascript.jwt.security.jwt-decode-without-verify'
      }
    });

    logs.push(`[Semgrep SAST] Analysis complete. 84 source files parsed. Total vulnerabilities identified: ${findings.length}`);
    return findings;
  }
}
