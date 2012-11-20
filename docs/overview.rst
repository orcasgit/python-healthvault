.. _overview:

Overview of how a Python-HealthVault Application Works
======================================================

For each person whose HealthVault data your application will access, you'll
create a :py:class:`HealthVaultConn` object (see :ref:`api`).  You'll use
that object to access the user's HealthVault data.

To construct a :py:class:`HealthVaultConn` object, you'll need the following information:

* Your public and private keys - you create these; see :ref:`keys`.
* Your APP ID - a UUID, this is assigned when you create your app on the ACC
* Your public key's thumbprint - the ACC will display this after you upload a public certificate
* The server address - e.g. for pre-production, "platform.healthvault-ppe.com" (default) or
  "platform.healthvault-ppe.co.uk" for Europe. For production, drop the "-ppe".
* The user's auth token - this is passed when HealthVault redirects the user to your app after they have authorized it.
  If you don't have this yet, you leave it out and pass it in later.

Your application can connect to HealthVault and do some things without a user auth token,
but to access any person's data online, it will need to pass a user auth token. To get one,
your web application will start by redirecting your user to the HealthVault APPAUTH
link to authorize your app to access their data.  You can call
:py:meth:`healthvaultlib.HealthVaultConn.authorization_url`
to get the URL to send them to. If you know which person's data you want and the
HealthVault record ID for that person, you can request access to that specific
person's data.
When that's done, HealthVault will redirect the user back to a URL in your app, passing an `auth token
<http://msdn.microsoft.com/en-us/library/ff803620.aspx#APPAUTH>`_.

Pass that user auth token when creating the `HealthVaultConn` object if it's available.
Otherwise, call :py:meth:`healthvaultlib.HealthVaultConn.connect` and pass it in when
you get it.

Whose data?
-----------

This brings us to an important point - when you redirect the user to HealthVault to login
and authorize access to some person's data, you have no control over which person's data they
choose to authorize. It might not be the person you expect, or the person they
authorized the last time they used your application. So after passing the user auth
token you just got into the `HealthVaultConn` object, you should verify it gives you
access to the person you expect.

One way to tell which person's data you're accessing is to look at the :py:attr:`record_id`
and :py:attr:`person_id` attributes of the `HealthVaultConn` object after connecting. If
they're not the same ones you were expecting, you're now accessing a different person's
data.  (This assumes you saved them from a previous connection.)

Another approach is to save some identifier from your application in the person's
HealthVault data the first time you access it, then look for it again each time.
This is supported by HealthVault using the
`AssociateAlternateId <https://platform.healthvault-ppe.com/platform/XSD/method-associatealternateid.xsd>`_
method to set it, and
`GetAlternateIds <https://platform.healthvault-ppe.com/platform/XSD/response-getalternateids.xsd>`_
to retrieve it.  python-healthvault exposes those as the :py:meth:`associate_alternate_id`
and :py:meth:`get_alternate_ids` methods on :py:class:`healthvaultlib.HealthVaultConn`.

Note that storing something like a web application userid there would only be
appropriate if you were willing to require using a different web application userid
for each person whose HealthVault data your application was going to access.


