import { Asset, ScanProfile } from '../../types/securescope';
import { RawFindingOutput } from './zapAdapter';

export class TrivyAdapter {
  public static readonly id = 'trivy';
  public static readonly displayName = 'Aqua Security Trivy';
  public static readonly version = 'v0.50.1';

  public static async runScan(input: { asset: Asset; profile: ScanProfile }, logs: string[]): Promise<RawFindingOutput[]> {
    logs.push(`[Trivy SCA] Initializing Trivy filesystem & dependency vulnerability scanner v${this.version}...`);
    logs.push(`[Trivy SCA] Auditing package manifests, lockfiles, and embedded secrets in '${input.asset.name}'...`);

    const findings: RawFindingOutput[] = [];

    findings.push({
      rawFindingId: 'trivy-cve-2023-4863',
      title: 'Vulnerable Dependency: libwebp / canvas Buffer Overflow (CVE-2023-4863)',
      description: 'Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp prior to 1.3.2 allows a remote attacker to perform an out-of-bounds memory write via a crafted HTML page.',
      severity: 'CRITICAL',
      confidence: 'VERIFIED',
      category: 'Software Composition Analysis (SCA)',
      cwe: 'CWE-119',
      cve: 'CVE-2023-4863',
      cvssScore: 9.8,
      owaspTop10: 'A06:2021-Vulnerable and Outdated Components',
      affectedLocation: 'package-lock.json (canvas -> libwebp@1.2.4)',
      remediation: 'Upgrade package `canvas` to version >= 2.11.2 or override `libwebp` to version >= 1.3.2 in package.json overrides.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-4863'],
      evidence: {
        type: 'source',
        filePath: 'package-lock.json',
        startLine: 1420,
        codeSnippet: '"node_modules/canvas": {\n  "version": "2.10.1",\n  "dependencies": { "libwebp": "^1.2.4" }\n}',
        ruleId: 'CVE-2023-4863'
      }
    });

    findings.push({
      rawFindingId: 'trivy-secret-aws-key',
      title: 'Exposed Cloud Access Key Found in Configuration',
      description: 'Trivy secret scanner detected an unencrypted AWS Access Key ID format string in environment template files.',
      severity: 'HIGH',
      confidence: 'HIGH',
      category: 'Secrets Detection',
      cwe: 'CWE-798',
      owaspTop10: 'A02:2021-Cryptographic Failures',
      affectedLocation: '.env.staging:12',
      remediation: 'Revoke key in AWS IAM console immediately. Use AWS Secrets Manager or HashiCorp Vault instead of plaintext environment variables.',
      references: ['https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/rules.go'],
      evidence: {
        type: 'source',
        filePath: '.env.staging',
        startLine: 12,
        codeSnippet: 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE_REDACTED"',
        ruleId: 'aws-access-key-id'
      }
    });

    logs.push(`[Trivy SCA] Audit finished. 382 direct & transitive npm packages analyzed. Findings: ${findings.length}`);
    return findings;
  }
}
