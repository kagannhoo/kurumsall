"""Quick diff engine smoke test — run: python -m scripts.test_diff"""

from app.models.entities import AssetType
from app.services.diff.engine import DiffEngine, SnapshotRecord


def main() -> None:
    engine = DiffEngine()
    previous = [
        SnapshotRecord(AssetType.DOMAIN, "company.com", "fp1", {}, 1.0),
        SnapshotRecord(AssetType.SUBDOMAIN, "www.company.com", "fp2", {}, 2.0),
    ]
    current = previous + [
        SnapshotRecord(AssetType.SUBDOMAIN, "api.company.com", "fp3", {"source": "discovery"}, 4.0),
        SnapshotRecord(AssetType.PORT, "api.company.com:8443/tcp", "fp4", {"port": 8443}, 7.0),
    ]
    diffs = engine.compare(previous, current)
    assert len(diffs) == 2
    assert any("api.company.com" in d.summary for d in diffs)
    print(f"PASS: {len(diffs)} changes detected")
    for d in diffs:
        print(f"  {d.summary} [{d.risk_level.value}]")


if __name__ == "__main__":
    main()
