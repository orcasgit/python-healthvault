from healthvaultlib.healthvault import HealthVaultException

class TestException(object):
    def test_no_code(self):
        e = HealthVaultException("Howdy")
        assert e.code is None

    def test_with_code(self):
        e = HealthVaultException("Howdy", code=2)
        assert e.code == 2
