"""Tests for HealthVaultConn"""

import mock
from unittest import TestCase
from healthvaultlib.healthvault import HealthVaultConn

class ConnTests(TestCase):
    def test_very_simple(self):
        # construct a conn, mocking all the real work
        with mock.patch.object(HealthVaultConn, '_get_auth_token'):
            with mock.patch.object(HealthVaultConn, '_get_record_id'):
                c = HealthVaultConn()

