import { ScopePolicy, PolicyDecision, AssetType, ScanProfile } from '../../types/securescope';

export class PolicyEngine {
  /**
   * Normalizes a target string and validates it against scope policy, SSRF rules, and authorization guidelines.
   */
  public static evaluateTarget(
    targetInput: string,
    assetType: AssetType,
    profile: ScanProfile,
    policy: ScopePolicy,
    authorizationConfirmed: boolean
  ): PolicyDecision {
    const reasons: string[] = [];
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'PROHIBITED' = 'LOW';
    let targetNormalized = targetInput.trim();
    let isPrivateOrLoopback = false;
    let resolvedIps: string[] = [];

    // 1. Authorization check
    if (!authorizationConfirmed) {
      reasons.push('Scan blocked: User authorization has not been confirmed for this target.');
      return {
        allowed: false,
        reasons,
        riskLevel: 'PROHIBITED',
        targetNormalized,
        isPrivateOrLoopback: false
      };
    }

    // 2. Profile policy check
    if (!policy.allowedProfiles.includes(profile)) {
      reasons.push(`Scan profile '${profile}' is not permitted by this project's Scope Policy.`);
    }

    if (profile === 'DEEP_AUTHORIZED') {
      riskLevel = 'HIGH';
    } else if (profile === 'STANDARD') {
      riskLevel = 'MEDIUM';
    }

    // 3. Asset Type validation & SSRF check
    if (assetType === 'WEB_URL' || assetType === 'API_ENDPOINT') {
      try {
        // Ensure protocol prefix
        if (!targetNormalized.startsWith('http://') && !targetNormalized.startsWith('https://')) {
          targetNormalized = `https://${targetNormalized}`;
        }

        const parsedUrl = new URL(targetNormalized);
        const hostname = parsedUrl.hostname.toLowerCase();

        // Check for loopback & private IP ranges (SSRF Protection)
        const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
        const isMetadataIp = hostname === '169.254.169.254' || hostname === 'metadata.google.internal';
        
        // Match standard private IP ranges
        const isPrivateIp = 
          /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
          /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
          /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname);

        if (isLoopback || isMetadataIp || isPrivateIp) {
          isPrivateOrLoopback = true;
          resolvedIps = [hostname];

          if (isMetadataIp) {
            reasons.push('SSRF Violation: Target hostname is a cloud metadata address.');
            riskLevel = 'PROHIBITED';
          } else if ((isLoopback || isPrivateIp) && !policy.allowPrivateIPs) {
            reasons.push('SSRF Violation: Target resolves to a loopback or private IP address, and private IP scanning is disabled in project policy.');
            riskLevel = 'PROHIBITED';
          }
        }

        // Domain Scope matching
        if (policy.allowedDomains.length > 0) {
          const domainMatched = policy.allowedDomains.some((domain) => {
            const cleanDomain = domain.toLowerCase().replace(/^\*?\./, '');
            return hostname === cleanDomain || hostname.endsWith(`.${cleanDomain}`);
          });

          if (!domainMatched) {
            reasons.push(`Target domain '${hostname}' is not listed in project allowed domains [${policy.allowedDomains.join(', ')}].`);
          }
        }

        // Excluded Paths matching
        if (policy.excludedPaths.length > 0) {
          const pathMatched = policy.excludedPaths.some((exPath) => parsedUrl.pathname.startsWith(exPath));
          if (pathMatched) {
            reasons.push(`Target path '${parsedUrl.pathname}' matches an explicitly excluded path rule.`);
          }
        }

      } catch (err) {
        reasons.push(`Invalid target URL format: '${targetInput}'.`);
        riskLevel = 'PROHIBITED';
      }
    } else if (assetType === 'MOBILE_PACKAGE') {
      // Validate mobile package name or uploaded package filename
      if (!targetNormalized.includes('.') && !targetNormalized.endsWith('.apk') && !targetNormalized.endsWith('.ipa')) {
        reasons.push('Mobile asset target must be a valid Android package identifier (e.g. com.example.app) or an uploaded APK/IPA file.');
      }
    } else if (assetType === 'SOURCE_REPO') {
      // Validate git URL or archive name
      if (!targetNormalized.startsWith('http') && !targetNormalized.startsWith('git@') && !targetNormalized.endsWith('.zip')) {
        reasons.push('Source repository target must be a valid Git URL or ZIP archive file.');
      }
    }

    const allowed = reasons.length === 0;

    return {
      allowed,
      reasons,
      riskLevel: allowed ? riskLevel : 'PROHIBITED',
      targetNormalized,
      ipAddressesResolved: resolvedIps,
      isPrivateOrLoopback
    };
  }
}
