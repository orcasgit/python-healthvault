class HealthVaultStatus(object):
    """Status codes that HealthVault can return.

    `See also <http://msdn.microsoft.com/en-us/library/hh567902.aspx>`_

    """
    OK = 0  # The request was successful.
    FAILED = 1  # Generic failure  due to unknown causes or internal error.
    BAD_HTTP = 2  # Http protocol problem.
    INVALID_XML = 3  # Request xml cannot be parsed or nonconformant.
    BAD_SIG = 4  # Signature validation failed
    BAD_METHOD = 5  # No such method.
    INVALID_APP = 6  # App does not exist  app is invalid  app is not active  or calling IP is invalid.
    CREDENTIAL_TOKEN_EXPIRED = 7  # Credential token has expired need a new one.
    INVALID_TOKEN = 8  # Auth token malformed or otherwise busted.
    INVALID_PERSON = 9  # Person does not exist or is not active.
    INVALID_RECORD = 10  # Given record id does not exist.
    ACCESS_DENIED = 11  # Person or app does not have sufficient rights.
    NYI = 12  # The functionality being accessed is not yet implemented.
    INVALID_THING = 13  # invalid thing identifier.
    CANT_CONVERT_UNITS = 14  # Data table already exists with incompatible units.
    INVALID_FILTER = 15  # Missing or invalid GetThingsFilter.
    INVALID_FORMAT = 16  # Missing or invalid GetThings format specifier.
    MISSING_SHARED_SECRET = 17  # A credential was supplied without a shared secret.
    INVALID_APPAUTH = 18  # authorized_applications entry missing.
    INVALID_THING_TYPE = 19  # Thing type doesn't exist.
    THING_TYPE_IMMUTABLE = 20  # Can't update things of this type.
    THING_TYPE_UNCREATABLE = 21  # Can't create things of this type.
    DUPLICATE_CREDENTIAL_FOUND = 22  # Duplicate Credential found.
    INVALID_RECORD_NAME = 23  # Invalid Record name.
    DRUG_NOT_FOUND = 24  # Cannot find the drug specified.
    INVALID_PERSON_STATE = 25  # Invalid person state.
    INVALID_CODESET = 26  # Requested code set was not found.
    INVALID_VALIDATION_TOKEN = 28  # Invalid validation token for contact email validation.
    INVALID_CONTACT_EMAIL = 30  # Invalid contact email
    INVALID_LOGIN_NAME = 31  # Invalid login name.
    INVALID_PASSWORD = 32  # Invalid password.
    INVALID_OPENQUERY = 33  # Open query id not found.
    INVALID_TRANSFORM = 34  # Transform cannot be loaded.
    INVALID_RELATIONSHIP_TYPE = 35  # Invalid relationship type.
    INVALID_CREDENTIAL_TYPE = 36  # Invalid credential type.
    INVALID_RECORD_STATE = 37  # Invalid record state.
    APP_AUTH_NOT_REQUIRED = 38  # Application authorization is not required for this app.
    REQUEST_TOO_LONG = 39  # The request provided has exceeded maximum allowed request length.
    DUPLICATE_AUTHORIZED_RECORD_FOUND = 40  # Duplicate authorized record found.
    EMAIL_NOT_VALIDATED = 41  # Person email must be validated but it's not
    MAIL_ADDRESS_MALFORMED = 45  # The email address specified to SendInsecureMessage is malformed.
    PASSWORD_NOT_STRONG = 46  # The password does not meet the complexity requirements.
    CANNOT_REMOVE_LAST_CUSTODIAN = 47  # The last custodian for a record cannot be removed.
    INVALID_EMAIL_ADDRESS = 48  # The email address is invalid.
    REQUEST_TIMED_OUT = 49  # The request sent to HealthVault reached its time to live and is now too old to be processed.
    INVALID_SPONSOR_EMAIL = 50  # The sponsor email address is invalid.
    INVALID_PROMOTION_TOKEN = 51  # Promotion token is invalid.
    INVALID_RECORD_AUTHORIZATION_TOKEN = 52  # Record authorization token is invalid.
    TOO_MANY_GROUPS_IN_QUERY = 53  # GetThings Query has too many request groups.
    GRANT_AUTHZ_EXCEEDS_DEFAULT = 54  # The permissions to be granted exceed the default permissions available to be granted. e.g.attempt to grant all access when only read access is available.
    INVALID_VOCABULARY = 55  # Requested vocabulary was not found
    DUPLICATE_APPLICATION_FOUND = 56  # An application with the same ID already exists
    RECORD_AUTHORIZATION_TOKEN_EXPIRED = 57  # Record authorization token has expired.
    RECORD_AUTHORIZATION_DOES_NOT_EXIST = 58  # Record authorization does not exist.
    THING_TYPE_UNDELETABLE = 59  # Can't delete things of this type.
    VERSION_STAMP_MISSING = 60  # Version stamp is missing.
    VERSION_STAMP_MISMATCH = 61  # Version stamp mismatch.
    EXPIRED_OPENQUERY = 62  # Requested open query has expired.
    INVALID_PUBLIC_KEY = 63  # Public key is invalid.
    DOMAIN_NAME_NOT_SET = 64  # The application's domain name hasn't been set.
    AUTHENTICATED_SESSION_TOKEN_EXPIRED = 65  # Authenticated session token has expired  need a new one.
    INVALID_CREDENTIAL_KEY = 66  # The credential key was not found.
    INVALID_PERSON_ID = 67  # Pseudo id for person not valid
    RECORD_QUOTA_EXCEEDED = 68  # The size occupied by the things in the put things request will cause the record to exceed the size quota alloted to it.
    INVALID_DATETIME = 69  # The DateTime supplied is invalid (exceeds the bounds for the DateTime)
    BAD_CERT = 70  # Certificate validation failed.
    RESPONSE_TOO_LONG = 71  # The response has exceeded maximum allowed size.
    INVALID_VERIFICATION_QUESTION = 72  # Verification question for connect request invalid.
    INVALID_VERIFICATION_ANSWER = 73  # The verification answer for the connect request is invalid.
    INVALID_IDENTITY_CODE = 74  # There is no connect request corresponding to the given code.
    RETRY_LIMIT_EXCEEDED = 75  # Maximum number of retries has been exceeded.
    CULTURE_NOT_SUPPORTED = 76  # Request header culture not supported.
    INVALID_FILE_EXTENSION = 77  # The file extension is not supported.
    INVALID_VOCABULARY_ITEM = 78  # The vocabulary item does not exist.
    DUPLICATE_CONNECT_REQUEST_FOUND = 79  # Duplicate connect request found.
    INVALID_SPECIAL_ACCOUNT_TYPE = 80  # The account type specified is invalid.
    DUPLICATE_TYPE_FOUND = 81  # A type with the specified identifier already exists.
    CREDENTIAL_NOT_FOUND = 82  # Credential not found
    CANNOT_REMOVE_LAST_CREDENTIAL = 83  # Attempt to delete last credential associated with an account
    CONNECT_REQUEST_ALREADY_AUTHORIZED = 84  # The connect request has been previously authorized.
    INVALID_THING_TYPE_VERSION = 85  # The type specified to update an instance of a thing is an older version of the type than the existing instance.
    CREDENTIALS_LIMIT_EXCEEDED = 86  # The maximum number of allowed credentials has been exceeded.
    INVALID_METHOD = 87  # One or more invalid methods were specified in the method mask.
    INVALID_BLOB_REF_URL = 88  # The blob reference url supplied for the blob streaming API is invalid.
    CANNOT_GET_STREAMED_OTHER_DATA = 89  # Other data put in to Healthvault via the streaming API cannot be requested as an other data string.
    UPDATE_THING_TYPE_VERSION_NO_DATA_XML = 90  # The type version of the thing cannot be changed without a data xml supplied for validation.
    UNSUPPORTED_CONTENT_ENCODING = 91  # The content encoding specified for the blob is not supported.
    CONTENT_ENCODING_DATA_MISMATCH = 92  # The content encoding specified for the blob does not match the blob data.
    APPLICATION_LIMIT_EXCEEDED = 93  # The user exceeded the maximum number of applications allowed.
    INVALID_BINARY_CONTENT_ID = 94  # The specified binary content identifier was not found.
    CONNECT_REQUEST_INCOMPLETE = 95  # The connect request was found but does not yet have any contents.
    CONNECT_PACKAGE_EXISTS = 96  # The connect package has already been fully created and populated.
    INVALID_FILE_NAME = 97  # The file name is not supported.
    INVALID_SIGNUP_CODE = 98  # The signup code is invalid.
    BLOB_SIZE_TOO_LARGE_FOR_INLINE = 99  # The blob is too large and cannot be returned inline.
    DUPLICATE_BLOB = 100  # A blob of this name is already present in the request.
    BLOB_TOKEN_COMMITTED = 101  # The blob token corresponds to a blob that is already committed.
    BLOB_TOKEN_NOT_COMPLETED = 102  # The blob token corresponds to a blob that was not marked completed through the streaming interface.
    THING_POTENTIALLY_INCOMPLETE = 104  # The thing being updated has data items that cannot be seen in this version, e.g. signatures with new signature methods or multiple blobs.
    INVALID_SIGNATURE_ALGORITHM = 105  # The signature algorithm is not valid.
    INVALID_BLOB_HASH_ALGORITHM = 106  # The blob hash algorithm is invalid or not supported.
    UNSUPPORTED_BLOB_HASH_BLOCK_SIZE = 107  # The blob hash block size is unsupported.
    BLOB_HASH_ALGORITHM_MISMATCH = 108  # The specified blob hash algorithm does not match the blob's hash algorithm.
    BLOB_HASH_BLOCK_SIZE_MISMATCH = 109  # The specified blob hash block size does not match the blob's hash block size.
    UNSUPPORTED_SIGNATURE_METHOD = 110  # The signature method is not supported in the context it is being used.
    INVALID_BLOB_HASH = 111  # The specified blob hash is invalid.
    PACKAGE_BLOB_NOT_COMMITTED = 112  # The blob is associated with a connect package that is not yet created.
    APPLICATION_STATE_TRANSITION_NOT_SUPPORTED = 113  # Changing the application state from deleted is not supported.
    INVALID_PACKAGE_CONTENTS = 120  # The contents of the connect package are not valid xml.
    INVALID_CONTENT_TYPE = 121  # The content type is not supported.
    CONNECT_PACKAGE_VALIDATION_REQUIRED = 122  # The contents of the connect package must be validated before they are put into a health record.
    INVALID_THING_STATE = 123  # Invalid thing state.
    TOO_MANY_THINGS_SPECIFIED = 124  # The maximum number of things specified has been exceeded.
    INVALID_DIRECTORY_ITEM = 126  # The directory item passed in is invalid.
    INVALID_VOCABULARY_AUTHORIZATION = 129  # The vocbulary authorization is invalid.
    VOCABULARY_ACCESS_DENIED = 130  # Access to the requested vocabulary is denied.
    UNSUPPORTED_PERSONAL_FLAG = 131  # The personal flag is not supported with this type.
    SUBSCRIPTION_NOT_FOUND  = 132  # The requested subscription was not found.
    SUBSCRIPTION_LIMIT_EXCEEDED  = 133  # The number of subscriptions for the application was exceeded.
    SUBSCRIPTION_INVALID  = 134  # The subscription contains invalid data.

