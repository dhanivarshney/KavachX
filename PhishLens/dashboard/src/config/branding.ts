/**
 * KavachX - Central Configuration and Branding
 * Easily modify product name, positioning, thresholds, and metadata from here.
 */

export interface TestSample {
  label: string;
  url: string;
  type: "phishing" | "legitimate" | "suspicious";
  tag: string;
  description: string;
}

export const BRANDING = {
  // Product Identity
  productName: "KavachX",
  shortName: "KavachX",
  companyName: "KavachX Security Labs",
  version: "v2.5.0 Enterprise",
  tagline: "Understand website risk before you trust a link.",
  descriptor: "Website Threat Intelligence",
  category: "AI-assisted phishing detection and website security analysis",
  description:
    "Next-generation proactive security intelligence to analyze links, messages, and digital touchpoints before credentials or trust are compromised.",
  
  // Status Labels
  statusWorkspace: "Security Workspace",
  statusOperational: "Systems Operational",
  statusDegraded: "Systems Degraded",
  statusOffline: "Service Unavailable",

  // Risk Classification Thresholds & Badges
  thresholds: {
    safeMax: 34,        // 0 - 34: Low Risk
    suspiciousMax: 69,  // 35 - 69: Suspicious
    // 70 - 100: High Risk
  },

  labels: {
    safe: {
      title: "Low Risk",
      short: "Safe",
      badgeText: "Verified Low Risk",
      badgeClass: "bg-emerald-50 text-emerald-700 border-emerald-200 ring-emerald-500/10",
      description: "No overt phishing, spoofing, or credential-harvesting indicators detected.",
      advice: "Exercise standard web safety. Always ensure you are on the intended domain before submitting sensitive credentials.",
    },
    suspicious: {
      title: "Suspicious",
      short: "Caution",
      badgeText: "Anomalous Indicators",
      badgeClass: "bg-amber-50 text-amber-700 border-amber-200 ring-amber-500/10",
      description: "Anomalous structural patterns, unusual naming, or unverified certificates detected.",
      advice: "Caution advised. Double-check the exact address using a bookmark or search engine before typing passwords.",
    },
    dangerous: {
      title: "High Risk",
      short: "Danger",
      badgeText: "Critical Threat Flagged",
      badgeClass: "bg-rose-50 text-rose-700 border-rose-200 ring-rose-500/10",
      description: "Confirmed or high-confidence phishing infrastructure designed to intercept credentials or financial data.",
      advice: "Do not interact. Do not enter passwords, OTPs, or payment details. Close this website immediately.",
    },
  },

  // Disclaimer
  disclaimer:
    "Automated security scans analyze multi-vector signals and heuristics at the time of inspection. While highly accurate, automated detection cannot guarantee 100% safety against novel zero-day threats. Always exercise caution when sharing sensitive personal or banking information.",

  // Curated Test Examples for Demo & User Testing
  testSamples: [
    {
      label: "PayPal Clone (Typosquat)",
      url: "https://paypa1-security-verification.com",
      type: "phishing",
      tag: "Brand Spoof",
      description: "Look-alike domain attempting to impersonate PayPal with credential harvest keywords.",
    },
    {
      label: "Chase Banking Phishing",
      url: "http://secure-login-chase-update.info/auth/login",
      type: "phishing",
      tag: "Unencrypted Lure",
      description: "Insecure HTTP connection attempting to intercept account credentials.",
    },
    {
      label: "Google (Legitimate Domain)",
      url: "https://www.google.com",
      type: "legitimate",
      tag: "Verified Authority",
      description: "Established authority domain with valid certificates and clean threat logs.",
    },
    {
      label: "Scrambled Random Link",
      url: "https://x7k9q2m1p0z-banking-auth.top",
      type: "suspicious",
      tag: "High Entropy TLD",
      description: "Scrambled domain name on a high-risk TLD with deceptive banking keywords.",
    },
  ] as TestSample[],

  // Navigation Items
  navigation: [
    { name: "Web Scanner", path: "/" },
    { name: "SMS Guard", path: "/smishing" },
    { name: "Trust Report", path: "/trust-report" },
    { name: "Analytics", path: "/analytics" },
  ],
};
