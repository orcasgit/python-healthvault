.. _keys:

Establishing Application Keys
=============================

In order to communicate with HealthVault, you need a signed certificate uploaded
to HealthVault for your application, and the corresponding public and private keys
configured in your application.

(The HealthVault documentation refers to uploading a public key, but in fact
what needs to be uploaded is a certificate, which contains a public key plus
a cryptographic signature.)

The certificate is uploaded as a DER-encoded certificate file. The public and
private keys are configured for `python-healthvault` as long Python integers.

The certificate can be self-signed.

These instructions assume that you have a system with `openssl` command line tools
installed. It need not be the same system you'll run your application on.

Create your own
---------------

The simplest approach is to just generate a self-signed certificate and use that.
This is just as secure as purchasing a certificate somewhere, as HealthVault will
only communicate with an application that can prove it has the private key. So
the signer of the certificate is not relevant to establishing authentication.

Doing this is a little fiddly, so a script has been provided.  Run::

    python healthvaultlib/makekey.py

This will create a file `selfsigned.cer` to be uploaded to HealthVault, and print
out the public and private keys in a format that can be copied and pasted into
your configuration.

Doing it manually
-----------------

(By manually, we mean using openssl commands yourself, not with pencil and paper...)

If you'd rather do this yourself, you can use this openssl command::

    openssl req -x509 -outform DER -out selfsigned.cer -batch -newkey rsa:2048 -keyout privatekey.pem -nodes -days 999999 -sha1

This will create two files. `selfsigned.cer` is the certificate file to upload to HealthVault.

To get the public key in a form we can use, run::

    $ openssl x509 -inform der -in selfsigned.cer -modulus
    Modulus=B81C20FC71CC63324CCB3860C8A092C464F9E54CBE6F228FB79D0A9B2... [truncated]

Copy that long hex string into your Python code, put a "0x" in front, and you have the public
key as a Python long literal.  E.g.::

    MY_PUBLIC_KEY = 0xB81C20FC71CC63324CCB3860C8A092C464F9E54CBE6F228FB79D0A9B2...

`privatekey.pem` contains the private key. Use this command to dump the information from the key file::

  openssl rsa -inform pem -in privatekey.pem -text -noout

This will dump a lot of data. This part contains the private key::

    privateExponent:
        4f:2e:79:d9:58:b0:08:b1:a7:69:77:73:d8:95:86:
        c9:c4:8b:dd:5c:66:42:b1:e0:91:9d:8e:e4:32:b7:
        38:10:4f:13:fd:ef:9d:0a:2c:29:76:f4:d2:df:f7:
        6d:7d:15:00:4b:ae:4c:b5:b7:ad:0c:9d:3a:0c:c3:
        68:9c:b7:05:b4:78:9b:a6:43:00:25:51:54:aa:97:
        a9:18:48:96:be:8d:99:bf:6d:53:09:41:50:63:ba:
        ff:3e:8c:d6:5b:0c:6c:9f:bf:4f:a1:bd:c3:7d:1b:
        44:f7:79:cd:82:3c:8d:f6:0b:b2:c5:46:b7:3a:06:
        75:87:1f:46:ec:25:8e:50:b9:23:2f:2d:4a:78:2b:
        67:f9:c7:55:90:e1:be:a4:eb:48:32:86:31:7b:72:
        cf:11:ee:1d:f5:bf:56:d8:af:ef:68:b2:50:49:91:
        cb:3f:d9:07:f5:75:b6:f8:09:f3:3e:45:be:99:25:
        98:cc:b4:75:ff:d0:a0:20:e4:6d:05:32:33:ec:cb:
        07:42:28:13:c9:e5:06:43:b6:b5:47:fc:a8:94:1a:
        91:9b:6c:2f:7e:71:71:15:11:0a:6f:b5:1b:90:12:
        f6:4f:f6:9c:78:88:fb:e3:ec:de:8c:27:7d:ec:1c:
        14:7b:11:5f:f5:40:0a:f6:14:6d:de:d2:34:19:f1:
        91

If you copy the long block of hex data, strip out the colons, newlines, and spaces, and put a "0x" in front, you'll
have the key as a Python long literal that you can use in your configuration.  E.g.::

    MY_PRIVATE_KEY = 0x4f2e79d958b008b1a7697773d89586....

This is pretty error-prone, though, so using the script is recommended.  If there's a way to get the private key
in a more useful format from the command line, I haven't found it yet.

If you have a certificate
-------------------------

A certificate only contains the public key. You can get that out using this openssl command::

    $ openssl x509 -inform der -in selfsigned.cer -modulus
    Modulus=B81C20FC71CC63324CCB3860C8A092C464F9E54CBE6F228 ... [truncated]

as above.

You also need the private key. When you requested the certificate, you generated the private key
and should have saved it.  Get it into PEM format and you can use the same command as we used
above with `privatekey.pem` to extract the key.
