import os

# First, create a self-signed cert and save the key that was generated too

cmd = "openssl req -x509 -outform DER -out selfsigned.cer -batch -newkey rsa:2048 -keyout privatekey.pem -nodes -days 999999 -sha1"
os.system(cmd)

# Now show the keys
from Crypto.PublicKey import RSA

with open("privatekey.pem", "r") as f:
    bits = f.read()
    rsa_key = RSA.importKey(bits)

print "APP_PUBLIC_KEY = 0x%x" % rsa_key.n
print "APP_PRIVATE_KEY = 0x%x" % rsa_key.d
