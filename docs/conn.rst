.. _conn:

Lifecycle of a HealthVaultConn Object
=====================================

This section gives the high-level view of how we manage the lifecycle of HealthVaultConn objects.
See the :py:class:`healthvaultlib.healthvault.HealthVaultConn` API doc for details of specific
operations.

The first vs. subsequent HealthVaultConn objects
------------------------------------------------

The first time your application creates a HealthVaultConn object, it'll have your application's
ID, private and public keys, thumbprint, and the server addresses to use, but that's all. It'll
construct a HealthVaultConn object with those parameters.

When a HealthVaultConn object is constructed with only those parameters, it'll make a request
to HealthVault to get authenticated. As part of that process, it'll generate a random shared
secret, and HealthVault will pass back an authentication token.

Once the first HealthvaultConn object has been successfully created, the application can get
the `sharedsec` and `auth_token` attributes from it and save them, and use them when creating
new HealthVaultConn objects from then on. That will prevent a network round trip being required
every time a HealthVaultConn is constructed.

Protect these values like passwords, along with the application private key. Those and
the public information for the application would grant access to HealthVault as that
application.

I don't know if these auth tokens expire or can otherwise stop working. It would be good practice
for an application to allow for that. If construction of a HealthVaultConn object fails when passing
a saved shared secret and auth token, it should try again without them. If that succeeds, it should
replace the saved values with the ones from the new object.

HealthVaultConn objects for specific users
------------------------------------------

The first time your application needs to access each patient's data, it'll have to construct
a new HealthVaultConn object (using the saved sharedsec and auth_token if available),
redirect the user to HealthVault (using the `authorization_url` method), receive a subsequent request
indicating whether the user authorized access, and if so, get the `wctoken` passed in that request.
Then it passes the `wctoken` to the HealthVaultConn's `connect` method to associate that person
with that HealthVaultConn object, and look up the `record_id` of the person whose data it has
been authorized to access.

After that, the application can save the `wctoken` and the `record_id` attribute from the HealthVaultConn
object, and re-use them when constructing new HealthVaultConn objects to access the same person's
data. This will save sending the user back to HealthVault to authorize us again, as well as a
network request to look up the record_id.

Protect the `wctoken` like a password. The `wctoken` is what grants the application access
to an individual's personal data.

The `record_id` is a permanent identifier for that individual (possibly unique to the application though)
and the application can save it with that individual's local data.

The `wctoken` will expire fairly quickly (less than an hour?) and the application needs to allow
for that.  When it expires, some call to HealthVault will fail with an error 7,
"The credential token has expired.", raising the exception `HealthVaultTokenExpiredException`.
The application
should repeat the original authorization process, redirecting the user using `authorization_url`
and getting the `wctoken` on a subsequent request. However, in this case the application already
knows the `record_id`. It should pass that `record_id` to `authorization_url` to force the
user to authorize access to the same person's data, and provide it when constructing the
new HealthVaultConn to save another network round-trip.

Another possibility is that the user has gone to HealthVault directly and removed the
authorization for the application. In that case, HealthVault will return an error
11, ACCESS_DENIED, raising `HealthVaultAccessDeniedException`. The solution is the same:
repeat the original authorization process.
