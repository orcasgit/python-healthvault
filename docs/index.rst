.. python-healthvault documentation master file, created by
   sphinx-quickstart on Tue Nov  6 12:04:14 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python-healthvault's documentation!
==============================================

Contents:

.. toctree::
   :maxdepth: 2

This is a library to help Python programs access Microsoft's Healthvault.

If you're not familiar with Healthvault, start here: http://msdn.microsoft.com/en-us/healthvault/default

- Read this early and repeatedly: HealthVault platform technical overview http://msdn.microsoft.com/en-us/healthvault/jj127438
- Also: HealthVault development basics http://msdn.microsoft.com/en-us/healthvault/jj127014.aspx

I think you go to the HealthVault Application Configuration Center (ACC) http://msdn.microsoft.com/en-us/library/jj582782.aspx
to create your account and define a Healthvault application.

Create a new public/private key pair and upload the public key to the ACC http://msdn.microsoft.com/en-us/library/ff803601.aspx


If you're developing a web application, you'll start by redirecting your user to the Healthvault APPAUTH link to authorize your app to access their data.
When that's done, MS will redirect the user back to a URL in your app, passing an auth token
(http://msdn.microsoft.com/en-us/library/ff803620.aspx#APPAUTH).

Next, construct a `HealthVaultConn` object, passing the auth token from the previous step.  You'll use
that object to access the user's Healthvault data.

You'll need the following information:

* Your public and private keys - you create these
* Your APP ID - a UUID, this is assigned when you create your app on the ACC
* Your APP Thumbprint - I think this is the thumbprint of your public key?
* The user's auth token - this is passed to you when Healthvault redirects the user to your app after they have authorized it
* The server address - e.g. 'platform.healthvault-ppe.com'


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

