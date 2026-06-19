import { DashboardSummary } from "../api";

export function DemoBanner({ dashboard }: { dashboard: DashboardSummary }) {
  if (!dashboard.is_demo_organization && !dashboard.demo_notice) return null;

  return (
    <div className="demo-banner">
      <strong>Demo modu</strong>
      <p>
        {dashboard.demo_notice ??
          "Bu organizasyon eğitim amaçlıdır. Cloud kaynakları yapılandırılmış envanterden gelir; gerçek AWS/Azure API taraması değildir."}
      </p>
      <p className="muted">
        Production kullanım için kendi domain'inizi ekleyin, DNS TXT ile doğrulayın ve gerçek cloud API anahtarlarını yapılandırın.
      </p>
    </div>
  );
}
