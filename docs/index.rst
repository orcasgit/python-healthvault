.. python-healthvault documentation master file, created by
   sphinx-quickstart on Tue Nov  6 12:04:14 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python-healthvault's documentation!
==============================================

Contents:

.. toctree::
   :maxdepth: 2

   keys
   api

This is a library to help Python programs access Microsoft's HealthVault.

If you're not familiar with HealthVault, start here: http://msdn.microsoft.com/en-us/healthvault/default

- Read this early and repeatedly: HealthVault platform technical overview http://msdn.microsoft.com/en-us/healthvault/jj127438
- Also: HealthVault development basics http://msdn.microsoft.com/en-us/healthvault/jj127014.aspx

I think you go to the HealthVault Application Configuration Center (ACC) http://msdn.microsoft.com/en-us/library/jj582782.aspx
to create your account and define a HealthVault application.

Create a new public/private key pair and upload the public key to the ACC http://msdn.microsoft.com/en-us/library/ff803601.aspx


If you're developing a web application, you'll start by redirecting your user to the HealthVault APPAUTH
link to authorize your app to access their data.
When that's done, MS will redirect the user back to a URL in your app, passing an auth token
(http://msdn.microsoft.com/en-us/library/ff803620.aspx#APPAUTH) which your app will save.

Next, construct a `HealthVaultConn` object.  You'll use
that object to access the user's HealthVault data.

To construct a `HealthVaultConn` object, you'll need the following information:

* Your public and private keys - you create these; see :ref:`keys`.
* Your APP ID - a UUID, this is assigned when you create your app on the ACC
* Your public key's thumbprint - the ACC will display this after you upload a public certificate
* The user's auth token - this is passed when HealthVault redirects the user to your app after they have authorized it
* The server address - e.g. for pre-production, 'platform.healthvault-ppe.com' (default) or
  'platform.healthvault-ppe.co.uk' for Europe. For production, drop the "-ppe".

* :ref:`keys`


To write:

* INSTALLATION
* REQUIREMENTS
* API DOC
* TESTS

Until that's done, it might be helpful to look at tests/simple.py as an example.
You can run it like this::

    python -m tests.simple


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

