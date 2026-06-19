import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.scanners.base import ScanContext
from app.services.scanners.collectors import NucleiScanner


@pytest.fixture
def scanner():
    return NucleiScanner()


@pytest.fixture
def context():
    return ScanContext(organization_id="org-1", root_domains=["example.com"])


class TestNucleiScanner:
    @pytest.mark.asyncio
    async def test_skips_when_external_tools_disabled(self, scanner, context, monkeypatch):
        from app.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "scanner_use_external_tools", False)
        result = await scanner.scan(context)
        assert result == []

    @pytest.mark.asyncio
    async def test_skips_when_nuclei_not_in_path(self, scanner, context, monkeypatch):
        from app.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "scanner_use_external_tools", True)
        with patch("app.services.scanners.collectors.shutil.which", return_value=None):
            result = await scanner.scan(context)
        assert result == []

    @pytest.mark.asyncio
    async def test_parses_nuclei_jsonl(self, scanner, context, monkeypatch):
        from app.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "scanner_use_external_tools", True)

        nuclei_line = json.dumps(
            {
                "template-id": "CVE-2024-1234",
                "info": {
                    "name": "Test RCE",
                    "severity": "critical",
                    "tags": ["cve", "cve2024"],
                },
                "matched-at": "https://example.com/admin",
                "host": "example.com",
                "type": "http",
            }
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(nuclei_line.encode(), b""))
        mock_proc.returncode = 0

        with (
            patch("app.services.scanners.collectors.shutil.which", return_value="/usr/bin/nuclei"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await scanner.scan(context)

        assert len(result) == 1
        assert result[0].asset_type.value == "vulnerability"
        assert result[0].payload["template_id"] == "CVE-2024-1234"
        assert result[0].payload["severity"] == "critical"
        assert result[0].risk_score == 10.0

    def test_parse_output_deduplicates(self, scanner):
        line = json.dumps(
            {
                "template-id": "test-dup",
                "info": {"name": "Dup", "severity": "high"},
                "matched-at": "https://a.example.com",
                "host": "a.example.com",
            }
        )
        raw = f"{line}\n{line}\n"
        assets = scanner._parse_output(raw)
        assert len(assets) == 1
