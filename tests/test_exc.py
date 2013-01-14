from unittest import TestCase

from healthvaultlib.exceptions import (HealthVaultException, HealthVaultStatus,
    _get_exception_class_for, HealthVaultTokenExpiredException,
    HealthVaultAccessDeniedException)


class TestException(TestCase):
    def test_no_code(self):
        e = HealthVaultException("Howdy")
        assert e.code is None

    def test_with_code(self):
        e = HealthVaultException("Howdy", code=2)
        assert e.code == 2

    def test_token_expiration(self):
        exc = _get_exception_class_for(HealthVaultStatus.CREDENTIAL_TOKEN_EXPIRED)
        self.assertEqual(HealthVaultTokenExpiredException, exc)

    def test_session_expiration(self):
        exc = _get_exception_class_for(HealthVaultStatus.AUTHENTICATED_SESSION_TOKEN_EXPIRED)
        self.assertEqual(HealthVaultTokenExpiredException, exc)

    def test_access_denied(self):
        exc = _get_exception_class_for(HealthVaultStatus.ACCESS_DENIED)
        self.assertEqual(HealthVaultAccessDeniedException, exc)
