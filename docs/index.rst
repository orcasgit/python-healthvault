.. python-healthvault documentation master file, created by
   sphinx-quickstart on Tue Nov  6 12:04:14 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to python-healthvault
=============================

Contents:

.. toctree::
   :maxdepth: 2

   overview
   conn
   keys
   api
   history

This is a library to help Python programs access Microsoft's HealthVault.

If you're not familiar with HealthVault, start at
the `HealthVault Developer Center <http://msdn.microsoft.com/en-us/healthvault/default>`_.

Here's a brief map to where to find information in the HealthVault documentation.

* `General concepts <http://msdn.microsoft.com/en-us/healthvault/jj127438>`_
* `Prose documentation of methods and concepts <http://msdn.microsoft.com/en-us/library/ff803616.aspx>`_
* `List of methods and links to the schemas for their requests and responses <http://developer.healthvault.com/pages/methods/methods.aspx>`_
* `List of types with their type IDs, links to their schemas, and tools to create sample instances, examine them, and validate
  your own XML <http://developer.healthvault.com/pages/types/types.aspx>`_
* `A completely different list of methods and types with links to details of their schemas <http://developer.healthvault.com/sdk/docs/index.html>`_ -
  this one takes more clicking around but is more accessible if reading XSD isn't as familiar.
* `Status codes returned on errors <http://msdn.microsoft.com/en-us/library/hh567902.aspx>`_

And some useful online tools.

* Go to the `HealthVault Application Configuration Center (ACC) <http://msdn.microsoft.com/en-us/library/jj582782.aspx>`_
  to create your account and define a HealthVault application.
* `Create and update a personal HV account on the pre-production server <https://account.healthvault-ppe.com/>`_
* `Create sample data <http://developer.healthvault.com/pages/types/types.aspx>`_

Once you have a general idea of how HealthVault works, you can continue reading
the :ref:`overview`.

Installation
------------

Use ``pip install python-healthvault``.  This library is PyPI.

Requirements
------------

These will be installed automatically when you ``pip install`` python-healthvault,
if not already available.

* `pycrypto <https://www.dlitz.net/software/pycrypto/>`_
* `sphinx <http://sphinx.pocoo.org/>`_

Tests
-----

To run the tests, install `tox <http://tox.testrun.org/latest/>`_ (``pip install tox``)
then just type ``tox`` in the top directory.

Sample app
----------

`tests/simple.py` is provided in the source as an example. You might need to edit a few things
at the top.  Then you can run it like this::

    python -m tests.simple

It will open a page in your browser, direct you to HealthVault to log in and
authorize access to a person's data, then redirect back to the sample
app and display a page showing some of the available data for that person.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

