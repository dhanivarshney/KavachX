const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export interface DOMFeatures {
  has_password_field: boolean;
  num_forms: number;
  external_form_action: boolean;
  num_iframes: number;
  external_links_ratio: number;
  has_hidden_inputs: boolean;
  brand_text_mismatch: boolean;
  favicon_hotlinked_brand: boolean;
}

export interface RiskBreakdownItem {
  category: string;
  score: number;
  min_score?: number;
  max_score: number;
  reasons: string[];
  source: string;
}

export interface AnalysisSources {
  heuristics: boolean;
  ml: boolean;
  phishtank: boolean;
  tls: boolean;
  domain_age: boolean;
  demo: boolean;
}

export interface AnalysisResponse {
  risk_score: number;
  label: "safe" | "suspicious" | "dangerous";
  confidence: number;
  reasons: string[];
  sources: AnalysisSources;
  risk_breakdown: RiskBreakdownItem[];
}

export interface ScanRecord {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  label: "safe" | "suspicious" | "dangerous";
  confidence: number;
  reasons: string[];
  sources: Record<string, boolean>;
  risk_breakdown: RiskBreakdownItem[];
  source_origin: "extension" | "dashboard";
  timestamp: string;
}

export interface DiagnosticsResponse {
  status: string;
  service: string;
  capabilities: Record<string, boolean>;
  counters: Record<string, number>;
  labels: Record<string, number>;
  sources: Record<string, number>;
}

export interface StatsResponse {
  total_reports: number;
  false_positives: number;
  false_negatives: number;
  top_reported_domains: { host: string; count: number }[];
  daily_reports_last_30_days: { day: string; count: number }[];
}

const EMPTY_DOM: DOMFeatures = {
  has_password_field: false,
  num_forms: 0,
  external_form_action: false,
  num_iframes: 0,
  external_links_ratio: 0.0,
  has_hidden_inputs: false,
  brand_text_mismatch: false,
  favicon_hotlinked_brand: false,
};

export async function analyzeUrl(url: string): Promise<AnalysisResponse> {
  const res = await fetch(`${BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, dom_features: EMPTY_DOM }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    throw new Error(errData?.detail?.[0]?.msg || errData?.detail || `Analysis failed (${res.status})`);
  }
  return res.json();
}

export async function getRecentScans(limit: number = 25): Promise<ScanRecord[]> {
  try {
    const res = await fetch(`${BASE}/recent-scans?limit=${limit}`);
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export async function getLatestScan(): Promise<ScanRecord | null> {
  try {
    const res = await fetch(`${BASE}/recent-scans/latest`);
    if (!res.ok) return null;
    const data = await res.json();
    return data && data.url ? data : null;
  } catch {
    return null;
  }
}

export interface HealthResponse {
  status: "ok" | "degraded";
  service: string;
  checks: {
    feedback_store: boolean;
    ml_model: boolean;
  };
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
  return res.json();
}

export async function getDiagnostics(): Promise<DiagnosticsResponse> {
  const res = await fetch(`${BASE}/diagnostics`);
  if (!res.ok) throw new Error(`Diagnostics failed: ${res.status}`);
  return res.json();
}

export async function getStats(): Promise<StatsResponse> {
  const res = await fetch(`${BASE}/stats`);
  if (!res.ok) throw new Error(`Stats failed: ${res.status}`);
  return res.json();
}

export async function getExplanation(
  label: string,
  risk_score: number,
  reasons: string[],
  risk_breakdown: RiskBreakdownItem[]
): Promise<string> {
  try {
    const res = await fetch(`${BASE}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, risk_score, reasons, risk_breakdown }),
    });
    if (!res.ok) return "";
    const data = await res.json();
    return data.explanation ?? "";
  } catch {
    return "";
  }
}

export async function submitFeedback(url: string, observed: string, expected: string): Promise<void> {
  await fetch(`${BASE}/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, observed_label: observed, expected_label: expected }),
  });
}

export interface StarBreakdownItem {
  star: number;
  percentage: number;
}

export interface TrustpilotResponse {
  domain: string;
  status: string;
  trust_score: number;
  star_rating: number;
  total_reviews: string;
  rating_label: string;
  is_unverified_scam_indicator: boolean;
  star_distribution: StarBreakdownItem[];
  top_complaints: string[];
  community_verdict: string;
  trustpilot_url: string;
}

export async function getTrustpilotReputation(domain: string): Promise<TrustpilotResponse> {
  const res = await fetch(`${BASE}/reputation/trustpilot?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error(`Trustpilot fetch failed: ${res.status}`);
  return res.json();
}

export interface ExtractedLinkResult {
  url: string;
  risk_score: number;
  label: "safe" | "suspicious" | "dangerous";
  reasons: string[];
}

export interface SmishingResponse {
  threat_score: number;
  risk_label: "safe" | "suspicious" | "dangerous";
  confidence: number;
  impersonated_brand: string | null;
  detected_traps: string[];
  extracted_links: ExtractedLinkResult[];
  ai_advice: string;
  safety_summary: string;
}

export async function analyzeSmishing(message: string, sender_id?: string): Promise<SmishingResponse> {
  const res = await fetch(`${BASE}/analyze/smishing`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, sender_id }),
  });
  if (!res.ok) throw new Error(`Smishing analysis failed: ${res.status}`);
  return res.json();
}



// ── Damage Control Mode ──────────────────────────────────────────

export interface DamageControlAction {
  id: string;
  priority: number;
  title: string;
  detail: string;
  completed: boolean;
  completed_at: string | null;
}

export interface DamageControlHelpline {
  name: string;
  contact: string;
  url: string;
  note: string;
}

export interface DamageControlIncident {
  incident_id: string;
  incident_type: string;
  incident_label: string;
  severity?: "CRITICAL" | "HIGH" | "MODERATE" | string;
  golden_hour?: boolean;
  risk_summary?: string;
  status: string;
  created_at: string;
  closed_at: string | null;
  details?: Record<string, any>;
  progress?: { total: number; completed: number; percentage: number };
  actions: DamageControlAction[];
  donts: string[];
  helplines: DamageControlHelpline[];
  disclaimer: string;
}

export interface IncidentTypeInfo {
  key: string;
  label: string;
}

export async function getIncidentTypes(): Promise<{ types: IncidentTypeInfo[] }> {
  const res = await fetch(`${BASE}/api/damage-control/incident-types`);
  if (!res.ok) throw new Error(`Failed to fetch incident types: ${res.status}`);
  return res.json();
}

export async function createIncident(incident_type: string, channel?: string, details?: Record<string, any>): Promise<DamageControlIncident> {
  const res = await fetch(`${BASE}/api/damage-control/incidents`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident_type, channel, details }),
  });
  if (!res.ok) throw new Error(`Failed to create incident: ${res.status}`);
  return res.json();
}

export async function getIncident(incident_id: string): Promise<DamageControlIncident> {
  const res = await fetch(`${BASE}/api/damage-control/incidents/${incident_id}`);
  if (!res.ok) throw new Error(`Failed to fetch incident: ${res.status}`);
  return res.json();
}

export async function toggleAction(incident_id: string, action_id: string): Promise<DamageControlIncident> {
  const res = await fetch(`${BASE}/api/damage-control/incidents/${incident_id}/actions/${action_id}`, {
    method: "PATCH",
  });
  if (!res.ok) throw new Error(`Failed to toggle action: ${res.status}`);
  return res.json();
}

export async function closeIncident(incident_id: string): Promise<DamageControlIncident> {
  const res = await fetch(`${BASE}/api/damage-control/incidents/${incident_id}/close`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`Failed to close incident: ${res.status}`);
  return res.json();
}

export function getIncidentDossierUrl(incident_id: string): string {
  return `${BASE}/api/damage-control/incidents/${incident_id}/dossier`;
}
