import { ScannerModule } from "../api";

const MODE_LABELS: Record<string, string> = {
  builtin: "Yerleşik",
  external: "Harici araç",
  configured_inventory: "Yapılandırılmış envanter",
  pending: "Bekliyor",
};

const STATUS_LABELS: Record<string, string> = {
  ok: "Tamamlandı",
  failed: "Başarısız",
  pending: "Bekliyor",
  unknown: "Henüz tarama yok",
};

export function ScannerModulesPanel({ modules }: { modules: ScannerModule[] }) {
  if (modules.length === 0) return null;

  return (
    <section className="panel">
      <h2>Tarama Modül Durumu</h2>
      <p className="panel-intro muted">
        Son taramada her modülün durumu. Cloud modülü şu an envanter config&apos;inden okur — canlı API yol haritasında.
      </p>
      <div className="scanner-modules">
        {modules.map((mod) => (
          <div key={mod.module} className={"scanner-module status-" + mod.status}>
            <div className="scanner-module-header">
              <strong>{mod.label}</strong>
              <span className={"module-status-pill status-" + mod.status}>
                {STATUS_LABELS[mod.status] ?? mod.status}
              </span>
            </div>
            <div className="scanner-module-meta">
              <span>Mod: {MODE_LABELS[mod.mode] ?? mod.mode}</span>
              <span>Asset: {mod.asset_count}</span>
            </div>
            {mod.note && <p className="module-note muted">{mod.note}</p>}
            {mod.error && <p className="module-error">{mod.error}</p>}
          </div>
        ))}
      </div>
    </section>
  );
}
