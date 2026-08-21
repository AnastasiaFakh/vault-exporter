import os
import sys
import types
import unittest


class _Gauge:
    def __init__(self, *args, **kwargs):
        pass


class _Info:
    def __init__(self, *args, **kwargs):
        pass


class _Session:
    pass


sys.modules.setdefault(
    "requests",
    types.SimpleNamespace(Session=_Session, HTTPError=Exception),
)
sys.modules.setdefault(
    "prometheus_client",
    types.SimpleNamespace(Gauge=_Gauge, Info=_Info, start_http_server=lambda *args, **kwargs: None),
)
sys.modules.setdefault("cryptography", types.ModuleType("cryptography"))
x509_module = types.ModuleType("cryptography.x509")
x509_module.Certificate = object
x509_module.CertificateRevocationList = object
x509_module.Name = object
sys.modules.setdefault("cryptography.x509", x509_module)
sys.modules.setdefault("cryptography.hazmat", types.ModuleType("cryptography.hazmat"))
sys.modules.setdefault("cryptography.hazmat.backends", types.SimpleNamespace(default_backend=lambda: None))

os.environ.setdefault("VAULT_ADDR", "http://vault.example")

import app


class PathDiscoveryTest(unittest.TestCase):
    def settings(self, scan_all_paths=True):
        return app.Settings(
            vault_addr="http://vault.example",
            mounts=["app"],
            listen_addr="0.0.0.0",
            listen_port=9108,
            scrape_interval=300,
            request_timeout=15,
            verify_tls=True,
            max_depth=10,
            path_prefixes=[],
            scan_all_paths=scan_all_paths,
        )

    def test_plain_appenv_path_is_scanned_by_default(self):
        settings = app.Settings.from_env()

        self.assertTrue(app.should_scan_path("app", "cs.partner/appenv", settings))

    def test_plain_appenv_path_is_not_scanned_when_full_scan_disabled(self):
        settings = self.settings(scan_all_paths=False)

        self.assertFalse(app.should_scan_path("app", "some-service/appenv", settings))

    def test_cert_like_path_still_matches_regex_when_full_scan_disabled(self):
        settings = self.settings(scan_all_paths=False)

        self.assertTrue(app.should_scan_path("app", "some-service/certs", settings))

    def test_mtls_key_path_is_private_key_inventory(self):
        self.assertEqual(app.classify_field("RBT_MTLS_KEY_PATH"), "private_key")

    def test_mtls_cert_path_is_certificate(self):
        self.assertEqual(app.classify_field("RBT_MTLS_CERT_PATH"), "certificate")


if __name__ == "__main__":
    unittest.main()
