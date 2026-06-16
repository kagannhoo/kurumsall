const API = "/api/v1";
const TOKEN_KEY = "asm_token";

export interface User {
  id: string | null;
  email: string;
  role: "admin" | "viewer";
  is_active: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  root_domains: string[];
  is_active: boolean;
  created_at: string;
}

export interface DomainVerification {
  domain: string;
  verified: boolean;
  verified_at: string | null;
  txt_record_name: string;
  txt_record_value: string;
}

export interface ChangeEvent {
  id: string;
  change_type: "added" | "removed" | "modified";
  asset_type: string;
  identifier: string;
  risk_level: "low" | "medium" | "high" | "critical";
  risk_score: number;
  summary: string;
  detected_at: string;
}

export interface AttackScenario {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  attack_chain: string[];
  business_impact: string;
  related_findings: string[];
  mitre_tactics?: string[];
}

export interface ActionItem {
  priority: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  owner: string;
  timeframe: string;
  related_scenario_id?: string | null;
}

export interface AIInsight {
  summary: string;
  risk_commentary: string;
  recommendations: string[];
  attack_scenarios: AttackScenario[];
  action_items: ActionItem[];
  ollama_connected: boolean;
  model_name: string;
  generated_at: string;
}

export interface AssetInventoryItem {
  asset_type: string;
  label: string;
  count: number;
  description: string;
}

export interface PerimeterInfo {
  root_domains: string[];
  cloud_providers: string[];
  monitored_surface: string[];
}

export interface DashboardSummary {
  organization_id: string;
  organization_name: string;
  total_assets: number;
  previous_total_assets: number | null;
  risk_score: number;
  previous_risk_score: number | null;
  risk_delta_percent: number | null;
  recent_changes: ChangeEvent[];
  ai_insight: AIInsight | null;
  latest_scan: {
    id: string;
    status: string;
    completed_at: string | null;
    asset_count: number;
  } | null;
  asset_inventory: AssetInventoryItem[];
  risk_breakdown: {
    by_type?: Record<string, number>;
    by_level?: Record<string, number>;
    critical_findings?: string[];
  } | null;
  critical_findings: string[];
  perimeter: PerimeterInfo | null;
  scan_coverage: string[];
  executive_summary: string | null;
  ollama_status: {
    connected: boolean;
    model_ready?: boolean;
    configured_model?: string;
    models?: string[];
    error?: string;
  } | null;
}

export interface TimelinePoint {
  date: string;
  asset_count: number;
  risk_score: number;
}

export interface ScanRun {
  id: string;
  status: "pending" | "running" | "completed" | "failed";
  asset_count: number;
  error_message: string | null;
}

function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, { headers, ...init });
  if (res.status === 401) {
    setToken(null);
    throw new Error("Oturum süresi doldu — tekrar giriş yapın");
  }
  if (!res.ok) {
    let message = await res.text();
    try {
      const body = JSON.parse(message) as { detail?: string };
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      // ham metin
    }
    throw new Error(message || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

async function download(path: string, filename: string) {
  const token = getToken();
  const res = await fetch(`${API}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error("Export başarısız");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function waitForScanComplete(orgId: string, scanId: string): Promise<ScanRun> {
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const scan = await request<ScanRun>(`/organizations/${orgId}/scans/${scanId}`);
        if (scan.status === "completed" || scan.status === "failed") {
          resolve(scan);
          return;
        }
        setTimeout(poll, 2000);
      } catch (e) {
        reject(e);
      }
    };
    poll();
  });
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string; user: User }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User>("/auth/me"),
  listOrganizations: () => request<Organization[]>("/organizations"),
  createOrganization: (body: {
    name: string;
    slug: string;
    root_domains: string[];
    cloud_accounts?: Record<string, unknown>;
  }) => request<Organization>("/organizations", { method: "POST", body: JSON.stringify(body) }),
  getDomainVerifications: (orgId: string) =>
    request<DomainVerification[]>(`/organizations/${orgId}/domains/verification`),
  markDomainVerified: (orgId: string, domain: string) =>
    request<DomainVerification>(`/organizations/${orgId}/domains/${domain}/mark-verified`, {
      method: "POST",
    }),
  verifyDomainDns: (orgId: string, domain: string) =>
    request<DomainVerification>(`/organizations/${orgId}/domains/${domain}/verify`, {
      method: "POST",
    }),
  getDashboard: (orgId: string) => request<DashboardSummary>(`/organizations/${orgId}/dashboard`),
  getTimeline: (orgId: string) =>
    request<{ points: TimelinePoint[] }>(`/organizations/${orgId}/timeline`),
  triggerScan: async (orgId: string): Promise<ScanRun> => {
    const queued = await request<{ scan_run_id: string }>(`/organizations/${orgId}/scans`, {
      method: "POST",
    });
    return waitForScanComplete(orgId, queued.scan_run_id);
  },
  getScan: (orgId: string, scanId: string) =>
    request<ScanRun>(`/organizations/${orgId}/scans/${scanId}`),
  exportCsv: (orgId: string, slug: string) => download(`/organizations/${orgId}/export/csv`, `asm-${slug}.csv`),
  exportPdf: (orgId: string, slug: string) => download(`/organizations/${orgId}/export/pdf`, `asm-${slug}.pdf`),
  getSystemStatus: () =>
    request<{ ollama: Record<string, unknown>; ai_enabled: boolean }>("/system/status"),
};
