import unittest

from app import should_export_certificate_expiry


class CertificateStatusFilterTests(unittest.TestCase):
    def test_exports_when_status_is_absent(self):
        self.assertTrue(should_export_certificate_expiry({"certificate": "pem"}))

    def test_exports_active_certificate(self):
        self.assertTrue(should_export_certificate_expiry({"usage_status": "active"}))

    def test_skips_explicitly_revoked_certificate(self):
        self.assertFalse(should_export_certificate_expiry({"usage_status": "revoked"}))
        self.assertFalse(should_export_certificate_expiry({"revoked": True}))
        self.assertFalse(should_export_certificate_expiry({"index_status": "R"}))

    def test_skips_explicitly_expired_certificate(self):
        self.assertFalse(should_export_certificate_expiry({"usage_status": "expired"}))
        self.assertFalse(should_export_certificate_expiry({"status": "expired"}))
        self.assertFalse(should_export_certificate_expiry({"index_status": "E"}))


if __name__ == "__main__":
    unittest.main()
