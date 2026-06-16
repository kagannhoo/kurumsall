import { useCallback, useEffect, useState } from "react";
import {
  api,
  ActionItem,
  AssetInventoryItem,
  AttackScenario,
  ChangeEvent,
  DashboardSummary,
  Organization,
  PerimeterInfo,
  TimelinePoint,
  isLoggedIn,
  setToken,
} from "./api";

const CHANGE_LABELS: Record<string, string> = {
  added: "Yeni",
  removed: "Kaldırıldı",
  modified: "Değişti",
};

const RISK_LABELS: Record<string, string> = {
  low: "Düşük",
  medium: "Orta",
  high: "Yüksek",
  critical: "Kritik",
};

const ASSET_TYPE_LABELS: Record<string, string> = {
  domain: "Domain",
  subdomain: "Alt domain",
  port: "Port",
  ssl_cert: "SSL",
  cloud_resource: "Cloud",
  vulnerability: "Zafiyet",
};

function riskClass(level: string): string {
  return `risk-${level}`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("tr-TR", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function StatCard({ label, value, sub, hint }: {
  label: string;
  value: string;
  sub?: string;
  hint?: string;
}) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

function ChangeRow({ change }: { change: ChangeEvent }) {
  return (
    <div className="change-row">
      <span className={`change-badge ${change.change_type}`}>
        {CHANGE_LABELS[change.change_type] ?? change.change_type}
      </span>
      <span className="change-type-tag">{ASSET_TYPE_LABELS[change.asset_type] ?? change.asset_type}</span>
      <span className="change-summary">{change.summary}</span>
      <span className={`risk-pill ${riskClass(change.risk_level)}`}>
        {RISK_LABELS[change.risk_level] ?? change.risk_level}
      </span>
    </div>
  );
}

function RiskDistribution({ byLevel }: { byLevel: Record<string, number> }) {
  const total = Object.values(byLevel).reduce((a, b) => a + b, 0) || 1;
  const levels = [
    { key: "critical", label: "Kritik", className: "bar-critical" },
    { key: "high", label: "Yüksek", className: "bar-high" },
    { key: "medium", label: "Orta", className: "bar-medium" },
    { key: "low", label: "Düşük", className: "bar-low" },
  ];

  return (
    <div className="risk-bars">
      {levels.map(({ key, label, className }) => {
        const count = byLevel[key] ?? 0;
        const pct = Math.round((count / total) * 100);
        return (
          <div key={key} className="risk-bar-row">
            <span className="risk-bar-label">{label}</span>
            <div className="risk-bar-track">
              <div className={"risk-bar-fill " + className} style={{ width: pct + "%" }} />
            </div>
            <span className="risk-bar-count">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function AssetInventoryGrid({ items }: { items: AssetInventoryItem[] }) {
  if (items.length === 0) {
    return <p className="muted">Tarama sonrası envanter burada listelenir.</p>;
  }
  return (
    <div className="inventory-grid">
      {items.map((item) => (
        <div key={item.asset_type} className="inventory-card">
          <div className="inventory-count">{item.count}</div>
          <div className="inventory-label">{item.label}</div>
          <div className="inventory-desc">{item.description}</div>
        </div>
      ))}
    </div>
  );
}

function PerimeterPanel({ perimeter }: { perimeter: PerimeterInfo }) {
  return (
    <div className="perimeter">
      <div className="perimeter-block">
        <h3>İzlenen domainler</h3>
        <div className="tag-list">
          {perimeter.root_domains.map((d) => (
            <span key={d} className="tag">{d}</span>
          ))}
        </div>
      </div>
      {perimeter.cloud_providers.length > 0 && (
        <div className="perimeter-block">
          <h3>Cloud hesapları</h3>
          <div className="tag-list">
            {perimeter.cloud_providers.map((p) => (
              <span key={p} className="tag tag-cloud">{p}</span>
            ))}
          </div>
        </div>
      )}
      <div className="perimeter-block">
        <h3>Tarama kapsamı</h3>
        <ul className="surface-list">
          {perimeter.monitored_surface.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function OllamaStatus({ status }: { status: DashboardSummary["ollama_status"] }) {
  if (!status) return null;
  const online = status.connected && status.model_ready;
  return (
    <div className={`ollama-status ${online ? "online" : "offline"}`}>
      <span className="ollama-dot" />
      <div>
        <strong>AI Motor: {online ? "Ollama aktif" : "Ollama kapalı — kural tabanlı analiz"}</strong>
        <p className="muted">
          {online
            ? `Model: ${status.configured_model}`
            : `Başlatmak için terminalde: ollama serve — ardından ollama pull ${status.configured_model || "llama3.1"}`}
        </p>
      </div>
    </div>
  );
}

function AttackScenarioCard({ scenario }: { scenario: AttackScenario }) {
  return (
    <article className={"scenario-card severity-" + scenario.severity}>
      <div className="scenario-header">
        <h3>{scenario.title}</h3>
        <span className={"risk-pill " + riskClass(scenario.severity)}>
          {RISK_LABELS[scenario.severity] ?? scenario.severity}
        </span>
      </div>
      <p className="scenario-impact"><strong>İş etkisi:</strong> {scenario.business_impact}</p>
      <h4 className="subheading">Saldırı zinciri</h4>
      <ol className="attack-chain">
        {scenario.attack_chain.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
      {scenario.mitre_tactics && scenario.mitre_tactics.length > 0 && (
        <div className="mitre-tags">
          {scenario.mitre_tactics.map((t) => (
            <span key={t} className="tag tag-mitre">{t}</span>
          ))}
        </div>
      )}
      <p className="scenario-findings muted">
        Bulgular: {scenario.related_findings.join(" · ")}
      </p>
    </article>
  );
}

function ActionPlan({ items }: { items: ActionItem[] }) {
  if (items.length === 0) return <p className="muted">Aksiyon önerisi üretilmedi.</p>;
  return (
    <div className="action-list">
      {items.map((item, i) => (
        <div key={item.title + "-" + i} className={"action-item priority-" + item.priority}>
          <div className="action-header">
            <span className={"risk-pill " + riskClass(item.priority)}>{RISK_LABELS[item.priority]}</span>
            <strong>{item.title}</strong>
          </div>
          <p className="action-desc">{item.description}</p>
          <div className="action-meta">
            <span>Sorumlu: {item.owner}</span>
            <span>Süre: {item.timeframe}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function TimelineChart({ points }: { points: TimelinePoint[] }) {
  if (points.length === 0) return null;
  const maxAssets = Math.max(...points.map((p) => p.asset_count), 1);

  return (
    <div className="timeline-wrap">
      <p className="chart-caption">Kaynak: günlük snapshot · Metrik: keşfedilen asset sayısı</p>
      <div className="timeline">
        {points.map((p) => {
          const barHeight = Math.round((p.asset_count / maxAssets) * 120);
          const tip = `${formatDate(p.date)}: ${p.asset_count} asset, risk ${p.risk_score.toFixed(1)}`;
          return (
          <div key={p.date} className="timeline-bar-group">
            <div
              className="timeline-bar"
              style={{ height: barHeight + "px" }}
              title={tip}
            />
            <span className="timeline-label">{formatDate(p.date).split(" ")[0]}</span>
            <span className="timeline-count">{p.asset_count}</span>
            <span className="timeline-risk">{p.risk_score.toFixed(1)}</span>
          </div>
          );
        })}
      </div>
    </div>
  );
}

function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState("admin@local");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(email, password);
      setToken(res.access_token);
      onLogin();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>KurSal</h1>
        <p className="muted">Saldırı yüzeyi izleme platformu</p>
        {error && <div className="error-banner">{error}</div>}
        <label>
          E-posta
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Şifre
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <button className="btn primary full" type="submit" disabled={loading}>
          {loading ? "Giriş yapılıyor…" : "Giriş Yap"}
        </button>
        <p className="login-hint muted">Varsayılan: admin@local / admin123</p>
      </form>
    </div>
  );
}

function DomainVerificationPanel({
  orgId,
  onVerified,
}: {
  orgId: string;
  onVerified: () => void;
}) {
  const [domains, setDomains] = useState<import("./api").DomainVerification[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getDomainVerifications(orgId).then(setDomains).catch((e) => setError(String(e)));
  }, [orgId]);

  const unverified = domains.filter((d) => !d.verified);
  if (domains.length === 0) return null;
  if (unverified.length === 0) return null;

  const markDemo = async (domain: string) => {
    try {
      await api.markDomainVerified(orgId, domain);
      onVerified();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section className="panel domain-panel">
      <h2>Domain Doğrulama Gerekli</h2>
      <p className="panel-intro muted">
        Tarama başlatmadan önce domain sahipliğini doğrulayın. DNS TXT kaydı ekleyin veya demo için manuel onaylayın.
      </p>
      {error && <div className="error-banner">{error}</div>}
      {unverified.map((d) => (
        <div key={d.domain} className="domain-verify-row">
          <strong>{d.domain}</strong>
          <code className="dns-record">{d.txt_record_name} → {d.txt_record_value}</code>
          <button className="btn secondary" onClick={() => markDemo(d.domain)}>
            Demo: Doğrula
          </button>
        </div>
      ))}
    </section>
  );
}

function DashboardView({
  dashboard,
  timeline,
  onScan,
  scanning,
  scanStatus,
  orgSlug,
  orgId,
}: {
  dashboard: DashboardSummary;
  timeline: TimelinePoint[];
  onScan: () => void;
  scanning: boolean;
  scanStatus: string | null;
  orgSlug: string;
  orgId: string;
}) {
  const assetDelta =
    dashboard.previous_total_assets != null
      ? dashboard.total_assets - dashboard.previous_total_assets
      : null;

  const byLevel = dashboard.risk_breakdown?.by_level ?? {};

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <p className="eyebrow">Attack Surface Management</p>
          <h1>{dashboard.organization_name}</h1>
          <p className="muted">
            Dışa açık port, domain, SSL sertifikası ve cloud kaynaklarının günlük envanteri ve diff analizi
          </p>
        </div>
        <div className="header-actions">
          <button className="btn secondary" onClick={() => api.exportCsv(orgId, orgSlug)}>
            CSV İndir
          </button>
          <button className="btn secondary" onClick={() => api.exportPdf(orgId, orgSlug)}>
            PDF Rapor
          </button>
          <button className="btn primary" onClick={onScan} disabled={scanning}>
            {scanning ? "Tarama çalışıyor…" : "Yüzey Taraması Başlat"}
          </button>
        </div>
      </header>

      {scanStatus && <div className="scan-status-banner">{scanStatus}</div>}

      <OllamaStatus status={dashboard.ollama_status} />

      {dashboard.executive_summary && (
        <section className="panel executive-panel">
          <h2>Yönetici Özeti</h2>
          <p className="executive-text">{dashboard.executive_summary}</p>
        </section>
      )}

      <div className="stats-grid">
        <StatCard
          label="Envanter (Asset)"
          value={String(dashboard.total_assets)}
          sub={assetDelta != null ? `${assetDelta >= 0 ? "+" : ""}${assetDelta} önceki taramaya göre` : undefined}
          hint="Domain, port, SSL ve cloud kayıtları"
        />
        <StatCard
          label="Risk Skoru"
          value={`${dashboard.risk_score.toFixed(1)} / 10`}
          sub={
            dashboard.risk_delta_percent != null
              ? `${dashboard.risk_delta_percent >= 0 ? "+" : ""}${dashboard.risk_delta_percent}% haftalık değişim`
              : undefined
          }
          hint="CVSS + exposure ağırlıklı"
        />
        <StatCard
          label="Son Tarama"
          value={
            dashboard.latest_scan?.completed_at
              ? formatDate(dashboard.latest_scan.completed_at).split(",")[0]
              : "Bekliyor"
          }
          sub={dashboard.latest_scan?.asset_count ? `${dashboard.latest_scan.asset_count} kayıt tarandı` : undefined}
          hint="Günlük otomatik + manuel"
        />
        <StatCard
          label="Yapısal Değişiklik"
          value={String(dashboard.recent_changes.length)}
          sub={`${dashboard.critical_findings.length} kritik bulgu`}
          hint="Eklenen / kaldırılan / değişen"
        />
      </div>

      <div className="three-col">
        {dashboard.perimeter && (
          <section className="panel">
            <h2>İzleme Perimetresi</h2>
            <PerimeterPanel perimeter={dashboard.perimeter} />
          </section>
        )}

        <section className="panel">
          <h2>Envanter Dağılımı</h2>
          <AssetInventoryGrid items={dashboard.asset_inventory} />
        </section>

        <section className="panel">
          <h2>Risk Dağılımı</h2>
          {Object.keys(byLevel).length > 0 ? (
            <RiskDistribution byLevel={byLevel} />
          ) : (
            <p className="muted">Risk skorları tarama sonrası hesaplanır.</p>
          )}
        </section>
      </div>

      <section className="panel">
        <h2>Aktif Tarama Modülleri</h2>
        <p className="panel-intro muted">
          Her taramada aşağıdaki collector&apos;lar sırayla çalışır; sonuçlar snapshot olarak saklanır ve bir önceki günle karşılaştırılır.
        </p>
        <ul className="coverage-list">
          {dashboard.scan_coverage.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      {dashboard.critical_findings.length > 0 && (
        <section className="panel critical-panel">
          <h2>Öncelikli Bulgular</h2>
          <ul className="critical-list">
            {dashboard.critical_findings.map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        </section>
      )}

      {dashboard.ai_insight && dashboard.ai_insight.attack_scenarios?.length > 0 && (
        <section className="panel">
          <h2>Olası Saldırı Senaryoları</h2>
          <p className="panel-intro muted">
            Keşfedilen bulgulara dayalı gerçekçi saldırı yolları — red team perspektifi, yönetici dili.
          </p>
          <div className="scenario-grid">
            {dashboard.ai_insight.attack_scenarios.map((s) => (
              <AttackScenarioCard key={s.id} scenario={s} />
            ))}
          </div>
        </section>
      )}

      {dashboard.ai_insight && dashboard.ai_insight.action_items?.length > 0 && (
        <section className="panel action-panel">
          <h2>Önerilen Aksiyon Planı</h2>
          <p className="panel-intro muted">
            Öncelik sırasına göre yapılması gerekenler — sorumlu ekip ve tahmini süre ile.
          </p>
          <ActionPlan items={dashboard.ai_insight.action_items} />
        </section>
      )}

      {timeline.length > 0 && (
        <section className="panel">
          <h2>Envanter Trendi</h2>
          <TimelineChart points={timeline} />
        </section>
      )}

      <div className="two-col">
        <section className="panel">
          <h2>Diff Raporu — Son Değişiklikler</h2>
          <p className="panel-intro muted">
            Önceki snapshot ile karşılaştırma. Yeni subdomain, açılan port veya SSL süresi gibi değişiklikler burada listelenir.
          </p>
          {dashboard.recent_changes.length === 0 ? (
            <p className="muted">Henüz diff yok. İkinci taramadan itibaren değişiklikler görünür.</p>
          ) : (
            <div className="changes-list">
              {dashboard.recent_changes.map((c) => (
                <ChangeRow key={c.id} change={c} />
              ))}
            </div>
          )}
        </section>

        <section className="panel ai-panel">
          <h2>AI Tehdit Değerlendirmesi</h2>
          <p className="panel-intro muted">
            {dashboard.ai_insight?.ollama_connected
              ? "Ollama ile zenginleştirilmiş analiz + kural tabanlı tehdit motoru."
              : "Kural tabanlı tehdit motoru aktif. Ollama açıldığında bir sonraki tarama LLM ile zenginleşir."}
          </p>
          {dashboard.ai_insight ? (
            <>
              <p className="ai-summary">{dashboard.ai_insight.summary}</p>
              <p className="ai-commentary">{dashboard.ai_insight.risk_commentary}</p>
              {dashboard.ai_insight.recommendations.length > 0 && (
                <>
                  <h3 className="subheading">Hızlı özet</h3>
                  <ul className="recommendations">
                    {dashboard.ai_insight.recommendations.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </>
              )}
              <p className="muted model-tag">
                Motor: {dashboard.ai_insight.model_name}
                {dashboard.ai_insight.ollama_connected ? " · Ollama bağlı" : " · Ollama bekleniyor"}
              </p>
            </>
          ) : (
            <p className="muted">Tarama tamamlandığında tehdit analizi oluşturulur.</p>
          )}
        </section>
      </div>
    </div>
  );
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(isLoggedIn());
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedSlug, setSelectedSlug] = useState<string>("");
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [domainKey, setDomainKey] = useState(0);

  const loadOrgs = useCallback(async () => {
    const list = await api.listOrganizations();
    setOrgs(list);
    if (list.length > 0 && !selectedId) {
      setSelectedId(list[0].id);
      setSelectedSlug(list[0].slug);
    }
  }, [selectedId]);

  const loadDashboard = useCallback(async (orgId: string) => {
    const [dash, tl] = await Promise.all([
      api.getDashboard(orgId),
      api.getTimeline(orgId),
    ]);
    setDashboard(dash);
    setTimeline(tl.points);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    loadOrgs()
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [loadOrgs, authenticated]);

  useEffect(() => {
    if (!selectedId || !authenticated) return;
    setLoading(true);
    loadDashboard(selectedId)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [selectedId, loadDashboard, authenticated]);

  const handleScan = async () => {
    if (!selectedId) return;
    setScanning(true);
    setScanStatus("Tarama kuyruğa alındı — arka planda çalışıyor…");
    setError(null);
    try {
      const result = await api.triggerScan(selectedId);
      if (result.status === "failed") {
        setError(result.error_message || "Tarama başarısız");
      } else {
        setScanStatus(`Tarama tamamlandı — ${result.asset_count} asset`);
      }
      await loadDashboard(selectedId);
    } catch (e) {
      setError(String(e));
      setScanStatus(null);
    } finally {
      setScanning(false);
    }
  };

  const handleSeed = async () => {
    setError(null);
    try {
      const org = await api.createOrganization({
        name: "Demo Şirket A.Ş.",
        slug: "demo-company",
        root_domains: ["example.com"],
        cloud_accounts: {
          aws: {
            resources: [
              {
                type: "s3_bucket",
                id: "demo-public-bucket",
                name: "demo-public-bucket",
                region: "eu-west-1",
                public: true,
              },
            ],
          },
        },
      });
      for (const domain of org.root_domains) {
        await api.markDomainVerified(org.id, domain);
      }
      await loadOrgs();
      setSelectedId(org.id);
      setSelectedSlug(org.slug);
      setDomainKey((k) => k + 1);
    } catch (e) {
      const msg = String(e);
      if (msg.toLowerCase().includes("already exists")) {
        const list = await api.listOrganizations();
        const demo = list.find((o) => o.slug === "demo-company");
        if (demo) {
          for (const domain of demo.root_domains) {
            try {
              await api.markDomainVerified(demo.id, domain);
            } catch {
              // zaten doğrulanmış olabilir
            }
          }
          setSelectedId(demo.id);
          setSelectedSlug(demo.slug);
        }
        await loadOrgs();
        return;
      }
      setError(msg);
    }
  };

  const handleLogout = () => {
    setToken(null);
    setAuthenticated(false);
    setOrgs([]);
    setDashboard(null);
    setSelectedId(null);
  };

  if (!authenticated) {
    return <LoginPage onLogin={() => setAuthenticated(true)} />;
  }

  if (loading && orgs.length === 0) {
    return <div className="app loading">Yükleniyor…</div>;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">KurSal</div>
        <p className="sidebar-desc">Saldırı yüzeyi izleme</p>
        <nav>
          {orgs.map((org) => (
            <button
              key={org.id}
              className={"nav-item" + (selectedId === org.id ? " active" : "")}
              onClick={() => {
                setSelectedId(org.id);
                setSelectedSlug(org.slug);
              }}
            >
              {org.name}
            </button>
          ))}
        </nav>
        <button className="btn secondary full logout-btn" onClick={handleLogout}>
          Çıkış
        </button>
        {orgs.length === 0 && (
          <button className="btn secondary full" onClick={handleSeed}>
            Demo Organizasyon Oluştur
          </button>
        )}
      </aside>

      <main className="main">
        {error && <div className="error-banner">{error}</div>}
        {dashboard && selectedId ? (
          <>
            <DomainVerificationPanel
              key={domainKey}
              orgId={selectedId}
              onVerified={() => {
                setDomainKey((k) => k + 1);
                loadDashboard(selectedId);
              }}
            />
            <DashboardView
              dashboard={dashboard}
              timeline={timeline}
              onScan={handleScan}
              scanning={scanning}
              scanStatus={scanStatus}
              orgSlug={selectedSlug}
              orgId={selectedId}
            />
          </>
        ) : (
          <div className="empty-state">
            <h2>Organizasyon seçin veya demo oluşturun</h2>
            <p className="muted">Port, domain, SSL ve cloud envanter takibi burada başlar.</p>
            <button className="btn primary" onClick={handleSeed}>
              Demo Organizasyon Oluştur
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
