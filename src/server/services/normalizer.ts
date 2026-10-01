import { Finding, FindingSeverity, FindingConfidence, FindingOccurrence } from '../../types/securescope';

export class NormalizerAndCorrelator {
  /**
   * Generates a deterministic fingerprint for deduplication across scanners
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

    // Simple deterministic numeric hash string
    let hash = 0;
    for (let i = 0; i < rawKey.length; i++) {
      const char = rawKey.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return `fp-${Math.abs(hash).toString(16)}`;
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
      const fp = this.generateFingerprint(
        assetIdentifier,
        raw.cwe,
        raw.category,
        raw.affectedLocation,
        raw.title
      );

      const occurrence: FindingOccurrence = {
        scannerId: raw.scannerId,
        scannerName: raw.scannerName,
        scannerVersion: raw.scannerVersion,
        rawFindingId: raw.rawFindingId,
        detectedAt: now,
        evidence: raw.evidence
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
        if (severityRank[raw.severity] > severityRank[existing.severity]) {
          existing.severity = raw.severity;
        }

        // Upgrade confidence if verified
        if (raw.confidence === 'VERIFIED') {
          existing.confidence = 'VERIFIED';
        }

        // Merge references
        existing.references = Array.from(new Set([...existing.references, ...raw.references]));

        // Augment standards mapping if missing
        if (!existing.cwe && raw.cwe) existing.cwe = raw.cwe;
        if (!existing.cve && raw.cve) existing.cve = raw.cve;
        if (!existing.cvssScore && raw.cvssScore) existing.cvssScore = raw.cvssScore;
        if (!existing.owaspTop10 && raw.owaspTop10) existing.owaspTop10 = raw.owaspTop10;
        if (!existing.owaspWstg && raw.owaspWstg) existing.owaspWstg = raw.owaspWstg;
        if (!existing.owaspMasvs && raw.owaspMasvs) existing.owaspMasvs = raw.owaspMasvs;

      } else {
        const newFinding: Finding = {
          id: `fnd-${Math.random().toString(36).substring(2, 9)}`,
          fingerprint: fp,
          scanId,
          projectId,
          assetId,
          assetIdentifier,
          title: raw.title,
          description: raw.description,
          severity: raw.severity,
          confidence: raw.confidence,
          category: raw.category,
          status: 'OPEN',
          cwe: raw.cwe,
          cve: raw.cve,
          cvssScore: raw.cvssScore,
          owaspTop10: raw.owaspTop10,
          owaspWstg: raw.owaspWstg,
          owaspMasvs: raw.owaspMasvs,
          affectedLocation: raw.affectedLocation,
          remediation: raw.remediation,
          references: raw.references,
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
