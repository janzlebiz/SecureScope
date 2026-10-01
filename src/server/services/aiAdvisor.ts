import { GoogleGenAI } from '@google/genai';
import { Finding } from '../../types/securescope';

export class AiAdvisor {
  private static getClient(): GoogleGenAI | null {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return null;
    return new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }

  /**
   * Analyzes a specific security finding to generate plain-language explanation, impact, developer code patch, and verification steps.
   */
  public static async analyzeFinding(finding: Finding): Promise<{
    summary: string;
    businessImpact: string;
    remediationCodeSnippet: string;
    verificationSteps: string[];
  }> {
    const ai = this.getClient();

    if (!ai) {
      return {
        summary: `${finding.title} was identified at ${finding.affectedLocation}. Immediate remediation is recommended based on ${finding.cwe || 'industry standards'}.`,
        businessImpact: `Unmitigated ${finding.severity.toLowerCase()} severity vulnerabilities can lead to unauthorized data exposure, session hijacking, or system degradation.`,
        remediationCodeSnippet: `// Remediation guidance for ${finding.title}:\n${finding.remediation}`,
        verificationSteps: [
          `Apply code fix in ${finding.affectedLocation}`,
          'Re-run SecureScope standard scan to confirm resolution',
          'Verify HTTP response headers or code diffs'
        ]
      };
    }

    try {
      const prompt = `You are a Senior Cybersecurity Engineer and Application Security Specialist.
Analyze the following security finding from an automated scanner and generate a structured developer remediation guide.

Finding Details:
- Title: ${finding.title}
- Severity: ${finding.severity}
- CWE: ${finding.cwe || 'N/A'}
- OWASP Category: ${finding.owaspTop10 || finding.category}
- Affected Location: ${finding.affectedLocation}
- Description: ${finding.description}
- Scanner Remediation Note: ${finding.remediation}

Respond ONLY with a valid JSON object matching this exact schema:
{
  "summary": "A concise 2-sentence plain-language technical explanation of the vulnerability.",
  "businessImpact": "A 2-sentence breakdown of potential business and security risks if exploited.",
  "remediationCodeSnippet": "A clean, copy-pasteable code patch or server configuration snippet (in Express/Node/Nginx/React or relevant framework) that fixes this issue.",
  "verificationSteps": ["Step 1...", "Step 2...", "Step 3..."]
}`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.2
        }
      });

      const text = response.text || '';
      const parsed = JSON.parse(text);

      return {
        summary: parsed.summary || finding.description,
        businessImpact: parsed.businessImpact || 'Risk of security control bypass.',
        remediationCodeSnippet: parsed.remediationCodeSnippet || finding.remediation,
        verificationSteps: parsed.verificationSteps || ['Re-scan asset to verify fix']
      };
    } catch (err) {
      console.error('Error calling Gemini AI Advisor:', err);
      return {
        summary: finding.description,
        businessImpact: 'High potential impact if exploited by unauthorized actors.',
        remediationCodeSnippet: finding.remediation,
        verificationSteps: ['Re-test asset with SecureScope scan']
      };
    }
  }

  /**
   * Generates an AI-powered Executive Risk Assessment for a completed scan
   */
  public static async generateExecutiveSummary(scanTitle: string, findings: Finding[]): Promise<string> {
    const ai = this.getClient();
    if (!ai) {
      return `Automated security assessment of ${scanTitle} identified ${findings.length} findings across ${findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length} high-severity areas. Immediate remediation of critical findings is advised.`;
    }

    try {
      const summaryData = findings.map(f => `- [${f.severity}] ${f.title} (${f.cwe || f.category})`).join('\n');
      const prompt = `You are a Chief Information Security Officer (CISO).
Write a 3-paragraph executive summary for an executive security assessment report.

Asset: ${scanTitle}
Total Findings: ${findings.length}
Key Findings List:
${summaryData.slice(0, 2000)}

Paragraph 1: High-level executive posture overview.
Paragraph 2: Strategic risk implications and primary threat vectors.
Paragraph 3: Immediate 30-day recommended action roadmap.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          temperature: 0.3
        }
      });

      return response.text || 'Executive summary generated successfully.';
    } catch (err) {
      return `Security assessment completed for ${scanTitle}. Remediation of identified issues is in progress.`;
    }
  }
}
