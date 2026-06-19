import asyncio
import json
import shutil
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.models.entities import AssetType
from app.services.scanners.base import BaseScanner, DiscoveredAsset, ScanContext, ScannerKind

logger = structlog.get_logger(__name__)
settings = get_settings()

COMMON_SUBDOMAINS = [
    "www", "api", "mail", "vpn", "dev", "staging", "admin", "portal",
    "app", "cdn", "static", "blog", "shop", "secure", "remote",
]

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200]


class DNSScanner(BaseScanner):
    kind = ScannerKind.DNS

    async def scan(self, context: ScanContext) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        for domain in context.root_domains:
            assets.append(
                DiscoveredAsset(
                    asset_type=AssetType.DOMAIN,
                    identifier=domain.lower(),
                    display_name=domain,
                    payload={"source": "root_domain"},
                )
            )
            subdomains = await self._discover_subdomains(domain)
            for sub in subdomains:
                assets.append(
                    DiscoveredAsset(
                        asset_type=AssetType.SUBDOMAIN,
                        identifier=sub.lower(),
                        display_name=sub,
                        payload={"parent_domain": domain, "source": "discovery"},
                    )
                )
        return assets

    async def _discover_subdomains(self, domain: str) -> set[str]:
        found: set[str] = set()
        if settings.scanner_use_external_tools and shutil.which(settings.scanner_subfinder_path):
            found.update(await self._run_subfinder(domain))
        found.update(await self._brute_common_subdomains(domain))
        return found

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _run_subfinder(self, domain: str) -> set[str]:
        proc = await asyncio.create_subprocess_exec(
            settings.scanner_subfinder_path,
            "-d", domain,
            "-silent",
            "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        results: set[str] = set()
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host") or data.get("domain")
                if host:
                    results.add(host.lower())
            except json.JSONDecodeError:
                results.add(line.lower())
        return results

    async def _brute_common_subdomains(self, domain: str) -> set[str]:
        found: set[str] = set()

        async def check(sub: str) -> None:
            fqdn = f"{sub}.{domain}".lower()
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 3
                answers = resolver.resolve(fqdn, "A")
                ips = [str(r) for r in answers]
                if ips:
                    found.add(fqdn)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
                pass

        await asyncio.gather(*[check(sub) for sub in COMMON_SUBDOMAINS])
        return found


class PortScanner(BaseScanner):
    kind = ScannerKind.PORT

    async def scan(self, context: ScanContext) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        hosts = set(context.root_domains)
        for domain in context.root_domains:
            hosts.update({f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS[:8]})

        resolved = await self._resolve_hosts(hosts)
        for host, ip in resolved.items():
            open_ports = await self._scan_host(host, ip)
            for port_info in open_ports:
                identifier = f"{host}:{port_info['port']}/{port_info['protocol']}"
                risk = self._port_risk(port_info["port"])
                assets.append(
                    DiscoveredAsset(
                        asset_type=AssetType.PORT,
                        identifier=identifier,
                        display_name=identifier,
                        payload={"host": host, "ip": ip, **port_info},
                        risk_score=risk,
                    )
                )
        return assets

    async def _resolve_hosts(self, hosts: set[str]) -> dict[str, str]:
        resolved: dict[str, str] = {}

        async def resolve(host: str) -> None:
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                resolved[host] = ip
            except OSError:
                pass

        await asyncio.gather(*[resolve(h) for h in hosts])
        return resolved

    async def _scan_host(self, host: str, ip: str) -> list[dict]:
        if settings.scanner_use_external_tools and shutil.which(settings.scanner_naabu_path):
            external = await self._run_naabu(host)
            if external:
                return external
        return await self._connect_scan(ip)

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _run_naabu(self, host: str) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            settings.scanner_naabu_path,
            "-host", host,
            "-top-ports", "100",
            "-json",
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        ports: list[dict] = []
        for line in stdout.decode().splitlines():
            try:
                data = json.loads(line)
                port = int(data.get("port", 0))
                if port:
                    ports.append({"port": port, "protocol": "tcp", "source": "naabu"})
            except (json.JSONDecodeError, ValueError):
                continue
        return ports

    async def _connect_scan(self, ip: str) -> list[dict]:
        open_ports: list[dict] = []

        async def probe(port: int) -> None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2.0,
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append({"port": port, "protocol": "tcp", "source": "connect"})
            except (OSError, asyncio.TimeoutError):
                pass

        await asyncio.gather(*[probe(p) for p in COMMON_PORTS])
        return open_ports

    @staticmethod
    def _port_risk(port: int) -> float:
        critical = {3306: 9.5, 5432: 9.0, 6379: 9.0, 27017: 9.0, 3389: 8.5, 445: 8.0, 8443: 7.0}
        high = {22: 6.0, 21: 6.5, 23: 7.5, 9200: 7.0}
        if port in critical:
            return critical[port]
        if port in high:
            return high[port]
        if port in (80, 443, 8080):
            return 2.0
        return 4.0


class SSLScanner(BaseScanner):
    kind = ScannerKind.SSL

    async def scan(self, context: ScanContext) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        hosts: set[str] = set()
        for domain in context.root_domains:
            hosts.add(domain)
            for sub in COMMON_SUBDOMAINS[:6]:
                hosts.add(f"{sub}.{domain}")

        async def check(host: str) -> None:
            cert_asset = await self._inspect_cert(host)
            if cert_asset:
                assets.append(cert_asset)

        await asyncio.gather(*[check(h) for h in hosts])
        return assets

    async def _inspect_cert(self, host: str) -> DiscoveredAsset | None:
        try:
            loop = asyncio.get_running_loop()
            cert_info = await loop.run_in_executor(None, self._fetch_cert, host)
            if not cert_info:
                return None
            days_left = cert_info["days_until_expiry"]
            risk = self._expiry_risk(days_left)
            return DiscoveredAsset(
                asset_type=AssetType.SSL_CERT,
                identifier=f"ssl:{host}",
                display_name=f"SSL — {host}",
                payload=cert_info,
                risk_score=risk,
            )
        except Exception as exc:
            logger.debug("ssl_scan_failed", host=host, error=str(exc))
            return None

    @staticmethod
    def _fetch_cert(host: str) -> dict | None:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                not_after = cert.get("notAfter")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "host": host,
                    "issuer": issuer.get("organizationName", "unknown"),
                    "not_after": expiry.isoformat(),
                    "days_until_expiry": days_left,
                    "san_domains": sans,
                    "grade": SSLScanner._grade(days_left),
                }

    @staticmethod
    def _grade(days_left: int) -> str:
        if days_left < 0:
            return "F"
        if days_left <= 7:
            return "D"
        if days_left <= 30:
            return "C"
        if days_left <= 90:
            return "B"
        return "A"

    @staticmethod
    def _expiry_risk(days_left: int) -> float:
        if days_left < 0:
            return 10.0
        if days_left <= 7:
            return 9.5
        if days_left <= 14:
            return 8.0
        if days_left <= 30:
            return 6.0
        if days_left <= 90:
            return 3.0
        return 1.0


class CloudScanner(BaseScanner):
    kind = ScannerKind.CLOUD

    async def scan(self, context: ScanContext) -> list[DiscoveredAsset]:
        if not context.cloud_accounts:
            return []
        assets: list[DiscoveredAsset] = []
        for provider, config in context.cloud_accounts.items():
            for resource in config.get("resources", []):
                identifier = f"{provider}:{resource.get('type')}:{resource.get('id')}"
                assets.append(
                    DiscoveredAsset(
                        asset_type=AssetType.CLOUD_RESOURCE,
                        identifier=identifier,
                        display_name=resource.get("name", identifier),
                        payload={
                            "provider": provider,
                            "resource_type": resource.get("type"),
                            "region": resource.get("region"),
                            "public": resource.get("public", False),
                            "metadata": resource.get("metadata", {}),
                            "source": "configured_inventory",
                        },
                        risk_score=self._cloud_risk(resource),
                    )
                )
        return assets

    @staticmethod
    def _cloud_risk(resource: dict) -> float:
        score = 2.0
        if resource.get("public"):
            score += 5.0
        rtype = resource.get("type", "")
        if rtype in ("s3_bucket", "storage_account", "gcs_bucket") and resource.get("public"):
            return 9.5
        if rtype in ("rds_instance", "cloud_sql") and resource.get("public"):
            return 9.0
        return score
