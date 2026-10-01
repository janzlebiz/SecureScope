import crypto from 'crypto';
import { Finding, FindingSeverity, FindingConfidence, FindingOccurrence } from '../../types/securescope';

export class NormalizerAndCorrelator {
  /**
   * Generates a deterministic cryptographic fingerprint (SHA-256) for deduplication across scanners
   */
  public static generateFingerprint(
    assetIdentifier: string,
    cwe: string | undefined,
    category: string,
    affectedLocation: string,
    title: string
  ): string {
    const rawKey = [
      assetIdentifier.toLowerCase().trim(),
      (cwe || '').toUpperCase().trim(),
      category.toLowerCase().trim(),
      affectedLocation.toLowerCase().trim(),
      title.toLowerCase().trim()
    ].join('||');

    const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
    return `fp-${hash.slice(0, 16)}`;
  }

  /**
   * Correlates raw findings from multiple scanner instances into normalized findings
   */
  public static correlateFindings(
    scanId: string,
    projectId: string,
    assetId: string,
    assetIdentifier: string,
    rawList: Array<{
      scannerId: string;
      scannerName: string;
      scannerVersion: string;
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
    }>
  ): Finding[] {
    const findingMap = new Map<string, Finding>();
    const now = new Date().toISOString();

    for (const raw of rawList) {
      // SS-05: Validation on raw findings to prevent pipeline crashes
      if (!raw || typeof raw !== 'object') {
        console.warn('[Normalizer] Skipped invalid null or malformed finding object.');
        continue;
      }

      const missingFields = [];
      if (!raw.title || typeof raw.title !== 'string') missingFields.push('title');
      if (!raw.affectedLocation || typeof raw.affectedLocation !== 'string') missingFields.push('affectedLocation');
      if (!raw.severity || typeof raw.severity !== 'string') missingFields.push('severity');
      if (!raw.category || typeof raw.category !== 'string') missingFields.push('category');

      if (missingFields.length > 0) {
        console.warn(`[Normalizer] Skipped malformed raw finding due to missing/invalid fields: ${missingFields.join(', ')}`);
        continue;
      }

      // Safe bounds checks
      const title = raw.title.slice(0, 200);
      const affectedLocation = raw.affectedLocation.slice(0, 500);
      const severity = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(raw.severity)
        ? raw.severity
        : 'INFO') as FindingSeverity;

      const fp = this.generateFingerprint(
        assetIdentifier,
        raw.cwe,
        raw.category,
        affectedLocation,
        title
      );

      const occurrence: FindingOccurrence = {
        scannerId: raw.scannerId,
        scannerName: raw.scannerName,
        scannerVersion: raw.scannerVersion,
        rawFindingId: raw.rawFindingId || 'raw-unk',
        detectedAt: now,
        evidence: raw.evidence || {}
      };

      if (findingMap.has(fp)) {
        const existing = findingMap.get(fp)!;
        existing.occurrences.push(occurrence);
        existing.lastSeen = now;

        // Upgrade severity if this scanner reports higher severity
        const severityRank: Record<FindingSeverity, number> = {
          CRITICAL: 5,
          HIGH: 4,
          MEDIUM: 3,
          LOW: 2,
          INFO: 1
        };
        if (severityRank[severity] > severityRank[existing.severity]) {
          existing.severity = severity;
        }

        // Upgrade confidence if verified
        if (raw.confidence === 'VERIFIED') {
          existing.confidence = 'VERIFIED';
        }

        // Merge references
        if (Array.isArray(raw.references)) {
          existing.references = Array.from(new Set([...existing.references, ...raw.references]));
        }

        // Augment standards mapping if missing
        if (!existing.cwe && raw.cwe) existing.cwe = raw.cwe;
        if (!existing.cve && raw.cve) existing.cve = raw.cve;
        if (!existing.cvssScore && raw.cvssScore) existing.cvssScore = raw.cvssScore;
        if (!existing.owaspTop10 && raw.owaspTop10) existing.owaspTop10 = raw.owaspTop10;
        if (!existing.owaspWstg && raw.owaspWstg) existing.owaspWstg = raw.owaspWstg;
        if (!existing.owaspMasvs && raw.owaspMasvs) existing.owaspMasvs = raw.owaspMasvs;

      } else {
        const newFinding: Finding = {
          id: `fnd-${crypto.randomBytes(4).toString('hex')}`,
          fingerprint: fp,
          scanId,
          projectId,
          assetId,
          assetIdentifier,
          title,
          description: raw.description || 'No description provided.',
          severity,
          confidence: (['VERIFIED', 'HIGH', 'MEDIUM', 'LOW'].includes(raw.confidence) ? raw.confidence : 'LOW') as FindingConfidence,
          category: raw.category,
          status: 'OPEN',
          cwe: raw.cwe,
          cve: raw.cve,
          cvssScore: raw.cvssScore,
          owaspTop10: raw.owaspTop10,
          owaspWstg: raw.owaspWstg,
          owaspMasvs: raw.owaspMasvs,
          affectedLocation,
          remediation: raw.remediation || 'Remediation details not provided.',
          references: Array.isArray(raw.references) ? raw.references : [],
          occurrences: [occurrence],
          firstSeen: now,
          lastSeen: now
        };
        findingMap.set(fp, newFinding);
      }
    }

    return Array.from(findingMap.values());
  }
}
