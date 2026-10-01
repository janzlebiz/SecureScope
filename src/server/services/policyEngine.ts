import dns from 'dns';
import net from 'net';
import { ScopePolicy, PolicyDecision, AssetType, ScanProfile } from '../../types/securescope';

export class PolicyEngine {
  /**
   * Helper to check if an IP address is blacklisted (SSRF Prevention)
   */
  public static isIpUnsafe(ip: string): boolean {
    if (!net.isIP(ip)) return true; // Malformed/invalid IP

    if (net.isIPv4(ip)) {
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4 || parts.some(isNaN)) return true;

      // 127.0.0.0/8
      if (parts[0] === 127) return true;
      // 10.0.0.0/8
      if (parts[0] === 10) return true;
      // 172.16.0.0/12
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      // 192.168.0.0/16
      if (parts[0] === 192 && parts[1] === 168) return true;
      // 169.254.0.0/16
      if (parts[0] === 169 && parts[1] === 254) return true;
      // Unspecified / Broadcast / Multicast
      if (parts[0] === 0 || parts[0] >= 224) return true;

      return false;
    }

    if (net.isIPv6(ip)) {
      const canonicalIp = ip.toLowerCase();
      
      // Loopback / Unspecified
      if (canonicalIp === '::1' || canonicalIp === '0:0:0:0:0:0:0:1') return true;
      if (canonicalIp === '::' || canonicalIp === '0:0:0:0:0:0:0:0') return true;

      // Unique Local (fc00::/7)
      if (canonicalIp.startsWith('fc') || canonicalIp.startsWith('fd')) return true;

      // Link-local (fe80::/10)
      if (
        canonicalIp.startsWith('fe8') ||
        canonicalIp.startsWith('fe9') ||
        canonicalIp.startsWith('fea') ||
        canonicalIp.startsWith('feb')
      ) {
        return true;
      }

      // Multicast (ff00::/8)
      if (canonicalIp.startsWith('ff')) return true;

      // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
      if (canonicalIp.startsWith('::ffff:')) {
        const ipv4Part = ip.substring(7);
        return this.isIpUnsafe(ipv4Part);
      }

      return false;
    }

    return true;
  }

  /**
   * Secure, canonical label-boundary domain check (SS-03 Target Scope / Domain Bypass)
   */
  public static isDomainAllowed(targetHost: string, allowedDomains: string[]): boolean {
    if (!allowedDomains || allowedDomains.length === 0) {
      return false; // Fail closed if empty
    }

    const targetLower = targetHost.toLowerCase().trim();
    // Support trailing dot matching properly by canonicalizing
    const canonicalTarget = targetLower.endsWith('.') ? targetLower.slice(0, -1) : targetLower;
    const targetLabels = canonicalTarget.split('.');

    return allowedDomains.some((pattern) => {
      const cleanPattern = pattern.toLowerCase().trim();
      const canonicalPattern = cleanPattern.endsWith('.') ? cleanPattern.slice(0, -1) : cleanPattern;
      if (!canonicalPattern) return false;

      // Wildcard check (e.g., *.example.com)
      if (canonicalPattern.startsWith('*.')) {
        const baseDomain = canonicalPattern.slice(2);
        const baseLabels = baseDomain.split('.');
        // Target must be a strict subdomain
        if (targetLabels.length <= baseLabels.length) {
          return false;
        }
        const suffixLabels = targetLabels.slice(-baseLabels.length);
        return suffixLabels.join('.') === baseDomain;
      }

      // Exact label matching
      const baseLabels = canonicalPattern.split('.');
      if (targetLabels.length !== baseLabels.length) {
        return false;
      }
      return targetLabels.join('.') === canonicalPattern;
    });
  }

  /**
   * Normalizes a target string and validates it against scope policy, SSRF rules, and authorization guidelines.
   */
  public static async evaluateTarget(
    targetInput: string,
    assetType: AssetType,
    profile: ScanProfile,
    policy: ScopePolicy,
    authorizationConfirmed: boolean
  ): Promise<PolicyDecision> {
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

        // Reject embedded credentials in URLs (SS-02 Scheme Scheme checks)
        if (parsedUrl.username || parsedUrl.password) {
          reasons.push('SSRF Violation: Target URL must not contain embedded user credentials.');
          riskLevel = 'PROHIBITED';
        }

        // Validate scheme (http/https only)
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          reasons.push('SSRF Violation: Only HTTP and HTTPS protocols are allowed.');
          riskLevel = 'PROHIBITED';
        }

        // Perform active asynchronous DNS resolution for both A and AAAA records (SS-02 DNS Resolution Gate)
        let addresses: string[] = [];
        try {
          // Resolve using standard OS-configured DNS resolver (supports local hostnames, rebinding checks)
          const dnsLookupResults = await dns.promises.lookup(hostname, { all: true });
          addresses = dnsLookupResults.map((addr) => addr.address);
          resolvedIps = addresses;
        } catch (err) {
          reasons.push(`SSRF DNS Error: Failed to resolve hostname '${hostname}'.`);
          riskLevel = 'PROHIBITED';
        }

        // Validate every resolved IP address against IP blacklist rules
        let containsUnsafeIp = false;
        for (const ip of addresses) {
          if (this.isIpUnsafe(ip)) {
            containsUnsafeIp = true;
            isPrivateOrLoopback = true;
            break;
          }
        }

        if (containsUnsafeIp) {
          if (hostname === 'metadata.google.internal' || addresses.includes('169.254.169.254')) {
            reasons.push('SSRF Violation: Target resolves to a cloud metadata IP address.');
            riskLevel = 'PROHIBITED';
          } else if (!policy.allowPrivateIPs) {
            reasons.push('SSRF Violation: Target resolves to an internal private or loopback IP address, and private scanning is disabled.');
            riskLevel = 'PROHIBITED';
          }
        }

        // Strict Domain Scope validation with canonical boundaries (SS-03 Target Scope Bypass)
        if (policy.allowedDomains && policy.allowedDomains.length > 0) {
          const domainMatched = this.isDomainAllowed(hostname, policy.allowedDomains);
          if (!domainMatched) {
            reasons.push(`Target domain '${hostname}' is not listed in project allowed domains [${policy.allowedDomains.join(', ')}].`);
          }
        } else {
          // Empty allowedDomains means fail-closed (SS-03 empty allowlist requirement)
          reasons.push('Scope policy violation: No allowed domains are configured for this project. Scan blocked.');
          riskLevel = 'PROHIBITED';
        }

        // Excluded Paths matching
        if (policy.excludedPaths && policy.excludedPaths.length > 0) {
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
