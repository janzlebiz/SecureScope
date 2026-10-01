import { ScannerRegistryEntry } from '../../types/securescope';
import { ZapAdapter } from './zapAdapter';
import { NucleiAdapter } from './nucleiAdapter';
import { MobSFAdapter } from './mobsfAdapter';
import { SemgrepAdapter } from './semgrepAdapter';
import { TrivyAdapter } from './trivyAdapter';

export const SCANNER_REGISTRY: ScannerRegistryEntry[] = [
  {
    id: ZapAdapter.id,
    name: ZapAdapter.name,
    category: 'Web & API DAST',
    version: ZapAdapter.version,
    license: 'Apache-2.0',
    capabilities: ['WEB_DAST', 'API_DAST', 'CRAWLING', 'PASSIVE_AUDIT', 'ACTIVE_ATTACK'],
    containerImage: 'ghcr.io/zaproxy/zaproxy:stable',
    isolationMode: 'Non-root container / Read-only rootfs',
    status: 'ACTIVE',
    enabledByDefault: true,
    notes: 'Primary open-source web application dynamic scanner.'
  },
  {
    id: NucleiAdapter.id,
    name: NucleiAdapter.name,
    category: 'Template Vulnerability Scanner',
    version: NucleiAdapter.version,
    license: 'MIT',
    capabilities: ['WEB_DAST', 'CVE_DETECTION', 'MISCONFIG_DETECTION', 'API_TESTING'],
    containerImage: 'projectdiscovery/nuclei:v3.2.1',
    isolationMode: 'Non-root container / Restricted Egress',
    status: 'ACTIVE',
    enabledByDefault: true,
    notes: 'Fast YAML template vulnerability scanner with version-pinned rule sets.'
  },
  {
    id: MobSFAdapter.id,
    name: MobSFAdapter.name,
    category: 'Mobile Security (Android & iOS)',
    version: MobSFAdapter.version,
    license: 'GPL-3.0',
    capabilities: ['MOBILE_STATIC', 'APK_DECOMPILE', 'MANIFEST_AUDIT', 'MASVS_MAPPING'],
    containerImage: 'opensecurity/mobsf:v3.8.0',
    isolationMode: 'Non-root container / Sandboxed Storage',
    status: 'ACTIVE',
    enabledByDefault: true,
    notes: 'Mobile Security Framework for Android APKs, iOS IPAs, and mobile source packages.'
  },
  {
    id: SemgrepAdapter.id,
    name: SemgrepAdapter.name,
    category: 'Static Application Security Testing (SAST)',
    version: SemgrepAdapter.version,
    license: 'LGPL-2.1',
    capabilities: ['SAST', 'SOURCE_AUDIT', 'AST_MATCHING', 'SECRET_SCANNING'],
    containerImage: 'returntocorp/semgrep:1.68.0',
    isolationMode: 'Ephemeral sandbox container',
    status: 'ACTIVE',
    enabledByDefault: true,
    notes: 'Polyglot static analysis engine matching AST security rules.'
  },
  {
    id: TrivyAdapter.id,
    name: TrivyAdapter.name,
    category: 'Software Composition & Secrets (SCA)',
    version: TrivyAdapter.version,
    license: 'Apache-2.0',
    capabilities: ['SCA', 'DEPENDENCY_AUDIT', 'SECRET_DETECTION', 'LICENSE_CHECK'],
    containerImage: 'aquasec/trivy:0.50.1',
    isolationMode: 'Ephemeral sandbox container',
    status: 'ACTIVE',
    enabledByDefault: true,
    notes: 'Open-source dependency vulnerability scanner and embedded secret detector.'
  },
  {
    id: 'nmap',
    name: 'Nmap Security Scanner',
    category: 'Network Discovery',
    version: '7.94',
    license: 'NPSL / Custom Review',
    capabilities: ['PORT_SCAN', 'SERVICE_DETECTION', 'NETWORK_DISCOVERY'],
    containerImage: 'secure-scope/worker-nmap:v1.0',
    isolationMode: 'Restricted egress worker pool',
    status: 'OPTIONAL',
    enabledByDefault: false,
    notes: 'Optional network discovery adapter. Requires explicit scope authorization.'
  },
  {
    id: 'sqlmap',
    name: 'sqlmap Verification Engine',
    category: 'Controlled SQL Injection Verification',
    version: '1.8',
    license: 'GPL-3.0',
    capabilities: ['SQLI_VERIFICATION'],
    containerImage: 'secure-scope/worker-sqlmap:v1.0',
    isolationMode: 'Isolated sandbox container',
    status: 'OPTIONAL',
    enabledByDefault: false,
    notes: 'Controlled active SQL injection verification. Disabled by default; explicit Deep profile opt-in required.'
  }
];
