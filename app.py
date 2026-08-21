import base64
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Dict, Iterable, List

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from prometheus_client import Gauge, Info, start_http_server


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vault-cert-exporter")


CERT_FIELD_RE = re.compile(
    os.getenv("CERT_FIELD_REGEX", r"(cert|certificate|ca|crt|pem|tls|ssl|mtls)"),
    re.IGNORECASE,
)
CRL_FIELD_RE = re.compile(
    os.getenv("CRL_FIELD_REGEX", r"(crl|revocation)"),
    re.IGNORECASE,
)
KEY_FIELD_RE = re.compile(
    os.getenv("KEY_FIELD_REGEX", r"(^|[./_-])(cert|tls|mtls|ssl|private)?[._-]?key([._-]?path)?$|private[_-]?key"),
    re.IGNORECASE,
)
KEYSTORE_FIELD_RE = re.compile(
    os.getenv("KEYSTORE_FIELD_REGEX", r"(jks|keystore|truststore|p12|pfx)"),
    re.IGNORECASE,
)
PATH_RE = re.compile(
    os.getenv("CERT_PATH_REGEX", r"(cert|certificate|ca|crt|pem|tls|ssl|mtls|pki|crl|jks|keystore|truststore)"),
    re.IGNORECASE,
)
PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
PEM_CRL_RE = re.compile(
    rb"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----",
    re.DOTALL,
)


CERT_NOT_AFTER = Gauge(
    "vault_certificate_not_after_timestamp_seconds",
    "Certificate expiration time as Unix timestamp.",
    ["mount", "path", "field", "subject", "issuer", "serial_number"],
)
CERT_DAYS_LEFT = Gauge(
    "vault_certificate_days_until_expiry",
    "Days until certificate expiration.",
    ["mount", "path", "field", "subject", "issuer", "serial_number"],
)
CERT_VALID = Gauge(
    "vault_certificate_valid",
    "Whether the discovered certificate was parsed successfully.",
    ["mount", "path", "field"],
)
CRL_NEXT_UPDATE = Gauge(
    "vault_crl_next_update_timestamp_seconds",
    "CRL nextUpdate time as Unix timestamp.",
    ["mount", "path", "field", "issuer"],
)
CRL_DAYS_LEFT = Gauge(
    "vault_crl_days_until_next_update",
    "Days until CRL nextUpdate.",
    ["mount", "path", "field", "issuer"],
)
CRL_LAST_UPDATE = Gauge(
    "vault_crl_last_update_timestamp_seconds",
    "CRL lastUpdate time as Unix timestamp.",
    ["mount", "path", "field", "issuer"],
)
CRL_REVOKED_CERTS = Gauge(
    "vault_crl_revoked_certificates",
    "Number of revoked certificates listed in the CRL.",
    ["mount", "path", "field", "issuer"],
)
CRL_VALID = Gauge(
    "vault_crl_valid",
    "Whether the discovered CRL was parsed successfully.",
    ["mount", "path", "field"],
)
INVENTORY_PRESENT = Gauge(
    "vault_secret_inventory_present",
    "Inventory of certificate, CRL, keystore, truststore, and key material discovered in Vault.",
    ["mount", "path", "field", "type", "owner", "service"],
)
SCRAPE_SUCCESS = Gauge(
    "vault_certificate_exporter_scrape_success",
    "Whether the latest Vault scrape succeeded.",
)
SCRAPE_DURATION = Gauge(
    "vault_certificate_exporter_scrape_duration_seconds",
    "Duration of the latest Vault scrape.",
)
SCRAPE_ERRORS = Gauge(
    "vault_certificate_exporter_scrape_errors_total",
    "Number of errors seen during the latest Vault scrape.",
)
DISCOVERED_CERTS = Gauge(
    "vault_certificate_exporter_discovered_certificates",
    "Number of certificates parsed during the latest Vault scrape.",
)
DISCOVERED_CRLS = Gauge(
    "vault_certificate_exporter_discovered_crls",
    "Number of CRLs parsed during the latest Vault scrape.",
)
EXPORTER_INFO = Info(
    "vault_certificate_exporter",
    "Vault certificate exporter configuration.",
)


@dataclass(frozen=True)
class Settings:
    vault_addr: str
    mounts: List[str]
    listen_addr: str
    listen_port: int
    scrape_interval: int
    request_timeout: int
    verify_tls: bool
    max_depth: int
    path_prefixes: List[str]
    scan_all_paths: bool

    @staticmethod
    def from_env() -> "Settings":
        vault_addr = env_required("VAULT_ADDR").rstrip("/")
        mounts = split_csv(os.getenv("VAULT_KV_MOUNTS", "app,secret,test"))
        prefixes = split_csv(os.getenv("VAULT_PATH_PREFIXES", ""))
        return Settings(
            vault_addr=vault_addr,
            mounts=mounts,
            listen_addr=os.getenv("LISTEN_ADDR", "0.0.0.0"),
            listen_port=int(os.getenv("LISTEN_PORT", "9108")),
            scrape_interval=int(os.getenv("SCRAPE_INTERVAL_SECONDS", "300")),
            request_timeout=int(os.getenv("VAULT_REQUEST_TIMEOUT_SECONDS", "15")),
            verify_tls=parse_bool(os.getenv("VAULT_VERIFY_TLS", "true")),
            max_depth=int(os.getenv("VAULT_MAX_DEPTH", "10")),
            path_prefixes=prefixes,
            scan_all_paths=parse_bool(os.getenv("VAULT_SCAN_ALL_PATHS", "true")),
        )


def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


def split_csv(value: str) -> List[str]:
    return [item.strip().strip("/") for item in value.split(",") if item.strip()]


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}


def owner_map() -> Dict[str, str]:
    entries = split_csv(os.getenv("VAULT_OWNER_MAP", ""))
    result: Dict[str, str] = {}
    for entry in entries:
        if "=" not in entry:
            continue
        service, owner = entry.split("=", 1)
        result[service.strip()] = owner.strip()
    return result


class VaultClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()
        self.session.verify = settings.verify_tls
        self.token = self._login()
        self.session.headers.update({"X-Vault-Token": self.token})

    def _login(self) -> str:
        token = os.getenv("VAULT_TOKEN")
        if token:
            logger.info("Using Vault token authentication")
            return token

        role_id = os.getenv("VAULT_ROLE_ID")
        secret_id = os.getenv("VAULT_SECRET_ID")
        if role_id and secret_id:
            logger.info("Using Vault AppRole authentication")
            payload = {"role_id": role_id, "secret_id": secret_id}
            data = self._post_unauthenticated("/v1/auth/approle/login", payload)
            return data["auth"]["client_token"]

        kubernetes_role = os.getenv("VAULT_KUBERNETES_ROLE")
        if kubernetes_role:
            logger.info("Using Vault Kubernetes authentication")
            jwt_path = os.getenv(
                "VAULT_KUBERNETES_JWT_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            )
            with open(jwt_path, "r", encoding="utf-8") as token_file:
                jwt = token_file.read().strip()
            mount = os.getenv("VAULT_KUBERNETES_AUTH_MOUNT", "kubernetes").strip("/")
            payload = {"role": kubernetes_role, "jwt": jwt}
            data = self._post_unauthenticated(f"/v1/auth/{mount}/login", payload)
            return data["auth"]["client_token"]

        raise RuntimeError(
            "No Vault auth configured. Set VAULT_TOKEN, AppRole variables, or VAULT_KUBERNETES_ROLE."
        )

    def _post_unauthenticated(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.settings.vault_addr}{path}",
            json=payload,
            timeout=self.settings.request_timeout,
        )
        response.raise_for_status()
        return response.json()

    def list_metadata(self, mount: str, path: str = "") -> List[str]:
        vault_path = f"/v1/{mount}/metadata"
        if path:
            vault_path = f"{vault_path}/{path.strip('/')}"
        response = self.session.get(
            f"{self.settings.vault_addr}{vault_path}",
            params={"list": "true"},
            timeout=self.settings.request_timeout,
        )
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json().get("data", {}).get("keys", []) or []

    def read_secret(self, mount: str, path: str) -> Dict[str, Any]:
        response = self.session.get(
            f"{self.settings.vault_addr}/v1/{mount}/data/{path.strip('/')}",
            timeout=self.settings.request_timeout,
        )
        response.raise_for_status()
        return response.json().get("data", {}).get("data", {}) or {}


def discover_paths(client: VaultClient, mount: str, settings: Settings) -> Iterable[str]:
    roots = settings.path_prefixes or [""]
    for root in roots:
        yield from walk_metadata(client, mount, root, settings.max_depth)


def walk_metadata(client: VaultClient, mount: str, path: str, depth: int) -> Iterable[str]:
    if depth < 0:
        logger.warning("Max depth reached at %s/%s", mount, path)
        return

    try:
        keys = client.list_metadata(mount, path)
    except requests.HTTPError as exc:
        logger.warning("Cannot list %s/%s: %s", mount, path, exc)
        return

    for key in keys:
        child = f"{path.rstrip('/')}/{key}".strip("/")
        if key.endswith("/"):
            yield from walk_metadata(client, mount, child.rstrip("/"), depth - 1)
        elif should_scan_path(mount, child, settings):
            yield child


def should_scan_path(mount: str, path: str, settings: Settings) -> bool:
    return settings.scan_all_paths or bool(PATH_RE.search(path))


def interesting_values(secret: Dict[str, Any]) -> Iterable[tuple[str, str, str]]:
    for key, value in flatten_secret(secret):
        item_type = classify_field(key)
        if not item_type:
            continue
        if isinstance(value, str):
            yield key, value, item_type


def classify_field(field: str) -> str:
    if KEY_FIELD_RE.search(field):
        return "private_key"
    if KEYSTORE_FIELD_RE.search(field):
        return "keystore"
    if CRL_FIELD_RE.search(field):
        return "crl"
    if CERT_FIELD_RE.search(field):
        return "certificate"
    return ""


def inventory_labels(mount: str, path: str, field: str, item_type: str) -> Dict[str, str]:
    service = path.split("/", 1)[0] if path else ""
    owner = owner_map().get(service, os.getenv("VAULT_DEFAULT_OWNER", "unknown"))
    return {
        "mount": mount,
        "path": path,
        "field": field,
        "type": item_type,
        "owner": owner,
        "service": service,
    }


def flatten_secret(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            nested_key = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten_secret(nested_value, nested_key)
    else:
        yield prefix, value


def parse_certificates(value: str) -> List[x509.Certificate]:
    candidates: List[bytes] = []
    raw = value.strip().encode("utf-8")

    if b"-----BEGIN CERTIFICATE-----" in raw:
        candidates.extend(PEM_CERT_RE.findall(raw))
    else:
        try:
            decoded = base64.b64decode(value, validate=True)
            if b"-----BEGIN CERTIFICATE-----" in decoded:
                candidates.extend(PEM_CERT_RE.findall(decoded))
            else:
                candidates.append(decoded)
        except Exception:
            return []

    certificates: List[x509.Certificate] = []
    for candidate in candidates:
        try:
            if candidate.startswith(b"-----BEGIN CERTIFICATE-----"):
                certificates.append(x509.load_pem_x509_certificate(candidate, default_backend()))
            else:
                certificates.append(x509.load_der_x509_certificate(candidate, default_backend()))
        except Exception:
            continue
    return certificates


def parse_crls(value: str) -> List[x509.CertificateRevocationList]:
    candidates: List[bytes] = []
    raw = value.strip().encode("utf-8")

    if b"-----BEGIN X509 CRL-----" in raw:
        candidates.extend(PEM_CRL_RE.findall(raw))
    else:
        try:
            decoded = base64.b64decode(value, validate=True)
            if b"-----BEGIN X509 CRL-----" in decoded:
                candidates.extend(PEM_CRL_RE.findall(decoded))
            else:
                candidates.append(decoded)
        except Exception:
            return []

    crls: List[x509.CertificateRevocationList] = []
    for candidate in candidates:
        try:
            if candidate.startswith(b"-----BEGIN X509 CRL-----"):
                crls.append(x509.load_pem_x509_crl(candidate, default_backend()))
            else:
                crls.append(x509.load_der_x509_crl(candidate, default_backend()))
        except Exception:
            continue
    return crls


def cert_name(name: x509.Name) -> str:
    return name.rfc4514_string()


def cert_serial(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def collect_once(settings: Settings) -> None:
    start = time.time()
    errors = 0
    cert_count = 0
    crl_count = 0

    CERT_NOT_AFTER.clear()
    CERT_DAYS_LEFT.clear()
    CERT_VALID.clear()
    CRL_NEXT_UPDATE.clear()
    CRL_DAYS_LEFT.clear()
    CRL_LAST_UPDATE.clear()
    CRL_REVOKED_CERTS.clear()
    CRL_VALID.clear()
    INVENTORY_PRESENT.clear()

    try:
        client = VaultClient(settings)
        now = time.time()

        for mount in settings.mounts:
            logger.info("Scanning mount %s/", mount)
            for path in discover_paths(client, mount, settings):
                try:
                    secret = client.read_secret(mount, path)
                except Exception as exc:
                    errors += 1
                    logger.warning("Cannot read %s/%s: %s", mount, path, exc)
                    continue

                for field, value, item_type in interesting_values(secret):
                    INVENTORY_PRESENT.labels(**inventory_labels(mount, path, field, item_type)).set(1)

                    if item_type == "certificate":
                        certificates = parse_certificates(value)
                        CERT_VALID.labels(mount=mount, path=path, field=field).set(1 if certificates else 0)
                        if not certificates:
                            continue

                        for index, cert in enumerate(certificates):
                            field_label = field if len(certificates) == 1 else f"{field}[{index}]"
                            expires_at = cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp()
                            labels = {
                                "mount": mount,
                                "path": path,
                                "field": field_label,
                                "subject": cert_name(cert.subject),
                                "issuer": cert_name(cert.issuer),
                                "serial_number": cert_serial(cert),
                            }
                            CERT_NOT_AFTER.labels(**labels).set(expires_at)
                            CERT_DAYS_LEFT.labels(**labels).set((expires_at - now) / 86400)
                            cert_count += 1

                    if item_type == "crl":
                        crls = parse_crls(value)
                        CRL_VALID.labels(mount=mount, path=path, field=field).set(1 if crls else 0)
                        if not crls:
                            continue

                        for index, crl in enumerate(crls):
                            field_label = field if len(crls) == 1 else f"{field}[{index}]"
                            issuer = cert_name(crl.issuer)
                            labels = {
                                "mount": mount,
                                "path": path,
                                "field": field_label,
                                "issuer": issuer,
                            }
                            next_update = crl.next_update.replace(tzinfo=timezone.utc).timestamp()
                            last_update = crl.last_update.replace(tzinfo=timezone.utc).timestamp()
                            CRL_NEXT_UPDATE.labels(**labels).set(next_update)
                            CRL_DAYS_LEFT.labels(**labels).set((next_update - now) / 86400)
                            CRL_LAST_UPDATE.labels(**labels).set(last_update)
                            CRL_REVOKED_CERTS.labels(**labels).set(len(crl))
                            crl_count += 1

        SCRAPE_SUCCESS.set(1)
    except Exception:
        errors += 1
        SCRAPE_SUCCESS.set(0)
        logger.exception("Vault scrape failed")
    finally:
        SCRAPE_ERRORS.set(errors)
        DISCOVERED_CERTS.set(cert_count)
        DISCOVERED_CRLS.set(crl_count)
        SCRAPE_DURATION.set(time.time() - start)
        logger.info("Scrape finished: certificates=%s crls=%s errors=%s", cert_count, crl_count, errors)


def collect_forever(settings: Settings) -> None:
    while True:
        collect_once(settings)
        time.sleep(settings.scrape_interval)


def main() -> None:
    settings = Settings.from_env()
    if not settings.verify_tls:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    EXPORTER_INFO.info(
        {
            "vault_addr": settings.vault_addr,
            "mounts": ",".join(settings.mounts),
            "path_prefixes": ",".join(settings.path_prefixes),
            "scan_all_paths": str(settings.scan_all_paths).lower(),
        }
    )

    logger.info("Starting HTTP server on %s:%s", settings.listen_addr, settings.listen_port)
    start_http_server(settings.listen_port, addr=settings.listen_addr)

    collector = threading.Thread(target=collect_forever, args=(settings,), daemon=True)
    collector.start()

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
