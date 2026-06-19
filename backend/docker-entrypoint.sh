#!/bin/sh
set -e

# İlk çalıştırmada Nuclei şablonları yoksa indir (build sırasında da kurulur)
if command -v nuclei >/dev/null 2>&1; then
  if [ ! -d /root/nuclei-templates ] || [ -z "$(ls -A /root/nuclei-templates 2>/dev/null)" ]; then
    echo "[KurSal] Nuclei CVE şablonları indiriliyor..."
    nuclei -update-templates -silent || true
  fi
fi

exec "$@"
