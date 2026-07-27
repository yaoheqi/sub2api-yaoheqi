import importlib.util
import pathlib
import sys
import types
import unittest


if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.SimpleNamespace(LOCK_EX=0, LOCK_NB=0, flock=lambda *_: None)

MODULE_PATH = pathlib.Path(__file__).with_name("account_healthcheck.py")
SPEC = importlib.util.spec_from_file_location("account_healthcheck", MODULE_PATH)
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


class ClassifyErrorTest(unittest.TestCase):
    def test_classifies_permanent_and_transient_states(self):
        cases = {
            'API returned 429: {"error":{"type":"usage_limit_reached"}}': "rate_limited",
            'API returned 401: {"code":"token_revoked"}': "auth_error",
            'API returned 402: {"detail":{"code":"deactivated_workspace"}}': "unavailable",
            'API returned 404: {"error":{"type":"model_not_found"}}': "unsupported_model",
            "HTTP 503: upstream unavailable": "transient_error",
            "TimeoutError: timed out": "transient_error",
            "API returned 418": "other_error",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(expected, health.classify_error(message))

    def test_health_owned_prefixes_are_distinct(self):
        self.assertNotEqual(health.AUTH_PREFIX, health.UNAVAILABLE_PREFIX)
        self.assertNotEqual(health.UNAVAILABLE_PREFIX, health.TRANSIENT_PREFIX)


if __name__ == "__main__":
    unittest.main()
