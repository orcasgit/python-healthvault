from healthvaultlib.status_codes import HealthVaultStatus

def _get_exception_class_for(code):
    """Given a status code from healthvault, return the most appropriate exception class
    to raise for it.

    Returns a class so the exception can be constructed from the proper place
    in the code instead of here.

    :param integer code: A status code from HealthVault
    :returns: The HealthVaultException class or a subclass
    :rtype: class
    """
    if code == HealthVaultStatus.CREDENTIAL_TOKEN_EXPIRED:
        return HealthVaultTokenExpiredException
    elif code == HealthVaultStatus.ACCESS_DENIED:
        return HealthVaultAccessDeniedException
    else:
        return HealthVaultException


class HealthVaultException(Exception):
    """This exception is raised for any error in the python-healthvault library
    that doesn't have a more specific exception. The more specific exceptions
    inherit from it.

    It has a :py:attr:`code` attribute that'll be set to the
    `HealthVault status code <http://msdn.microsoft.com/en-us/library/hh567902.aspx>`_,
    if one is available. Otherwise it's None.
    """
    def __init__(self, *args, **kwargs):
        self.code = kwargs.pop('code', None)
        super(HealthVaultException, self).__init__(*args, **kwargs)


class HealthVaultTokenExpiredException(HealthVaultException):
    """Raised when the user access token (wctoken) has expired, healthvault
    error 7: CREDENTIAL_TOKEN_EXPIRED
    Credential token has expired need a new one.
    """
    pass


class HealthVaultAccessDeniedException(HealthVaultException):
    """Raised for error 11: ACCESS_DENIED.  Could mean the user went to HealthVault
    and removed the application's authorization. Ask the user for it again.
    """
    pass


class HealthVaultHTTPException(HealthVaultException):
    """Raises when the HTTP request fails for any reason.
    The :py:attr:`code` attribute is set to the HTTP response code
    and the exception message to the response message.
    """
    pass
