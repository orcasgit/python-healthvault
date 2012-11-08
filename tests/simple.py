# Very basic program to exercise the library
# This is not intended as an example of good code style, just
# as a demo of a few calls to the library with the proper arguments.

# Starting this program will start a little web server and point
# the user's browser at it. This server will redirect the user to
# HealthVault to authorize our application, catch the token when
# the user is redirected back here, and verify that we can now
# connect okay to HealthVault with our app's credentials and the
# token we received.

import BaseHTTPServer
from urllib import urlencode
from urlparse import urlparse, parse_qs
import webbrowser
import sys
from healthvaultlib.healthvault import HealthVaultConn

# This is the pre-production server for the US
SHELL_SERVER = "account.healthvault-ppe.com"

# FIXME: this is ORCAS test app
#APP_ID = "5b2be475-0110-4186-a592-ef1aeba66e4a"

# FIXME: This is my test app
APP_ID = "0ce9374d-f6d9-4314-afcc-57f3c8863ba0"
THUMBPRINT = "67E6AAB1C33781D17B82F8B0D78C0DF1BE3D8866"

WCTOKEN = None
APP_PUBLIC_KEY = 0xb81c20fc71cc63324ccb3860c8a092c464f9e54cbe6f228fb79d0a9b2e303c3b233989b4a45fa1b8595b42791beed20c005e973ee7dcb657e735f3399d259dd25d63ac3669040dbf06030e009dfa815d1957cd0e89474d0d8addbfe4354df1f72b37592aa49686d8d7d1d0246017ec8763b917508a05c880bff23cfaffd74290dfbe7d5b94e61bb8cb4df86883306e6eb4d884feb70c66b2e3925ad86ebcbaee2517d24466ead5c13488dc339723f286b800e255a32ef69f69a2f25c1e3bde49da00a6473d2b256b156fc52ffe597e56017dd49be697083c861ceb43ebf4927fe08165020df6690c34bcd8e4bacf1344b72cf42ec744407fb9f44c8c16ef9f77
APP_PRIVATE_KEY = 0x4f2e79d958b008b1a7697773d89586c9c48bdd5c6642b1e0919d8ee432b738104f13fdef9d0a2c2976f4d2dff76d7d15004bae4cb5b7ad0c9d3a0cc3689cb705b4789ba64300255154aa97a9184896be8d99bf6d5309415063baff3e8cd65b0c6c9fbf4fa1bdc37d1b44f779cd823c8df60bb2c546b73a0675871f46ec258e50b9232f2d4a782b67f9c75590e1bea4eb483286317b72cf11ee1df5bf56d8afef68b2504991cb3fd907f575b6f809f33e45be992598ccb475ffd0a020e46d053233eccb07422813c9e50643b6b547fca8941a919b6c2f7e717115110a6fb51b9012f64ff69c7888fbe3ecde8c277dec1c147b115ff5400af6146dded23419f191


# Lots of logging
import logging

handler = logging.StreamHandler()
root_logger = logging.getLogger('')
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(handler)

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # Start by redirecting user to HealthVault to authorize us
            target = "APPAUTH"
            targetqs = urlencode({'appid': APP_ID, 'redirect': 'http://localhost:8000/authtoken'})
            url = "https://%s/redirect.aspx?%s" % (SHELL_SERVER, urlencode({'target': target, 'targetqs': targetqs}))
            self.send_response(301)
            self.send_header("Location", url)
            return

        if self.path.startswith('/authtoken?'):
            # This is the redirect after the user has authed us
            # the params include the wctoken we'll be using from here on for this user's data
            o = urlparse(self.path)
            query = parse_qs(o.query)
            global WCTOKEN
            WCTOKEN = query['wctoken'][0]

            # Make sure we can connect okay
            config = {
                'WCTOKEN': WCTOKEN,
                'HV_APPID': APP_ID,
                'APP_THUMBPRINT': THUMBPRINT,
                'PUBLIC_KEY': APP_PUBLIC_KEY,
                'PRIVATE_KEY': APP_PRIVATE_KEY
            }
            conn = HealthVaultConn(config)
            setattr(self.server, 'conn', conn)

            # Alright, say hello
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("Hello!  Got your token.\n")
            self.wfile.write("<a href=\"/demo\">Get demographic info</a>\n")
            self.wfile.close()
            return
        if self.path.startswith("/demo"):
            # Get demographic data
            # But, there really isn't any
            conn = self.server.conn
            data = conn.getBasicDemographicInfo()
            self.send_response(200)
            self.end_headers()
            # There is unlikely to be any real demographic data if this is just a test application,
            # so print a few words around it so it's not just an empty page in that case.
            self.wfile.write("HERE'S the data:\n")
            self.wfile.write(data)
            self.wfile.write("THAT WAS IT\n")
            self.wfile.close()
            return

        # Tired of seeing errors for this one
        if self.path == '/favicon.ico':
            self.send_response(200)
            self.end_headers()
            self.wfile.close()

        # We get here for any URL we don't recognize
        print "UNHANDLED URL!!!!  %r" % self.path


# Start server
server_address = ('', 8000)
httpd = BaseHTTPServer.HTTPServer(server_address, Handler)

# Point user's browser at our starting URL
webbrowser.open("http://localhost:8000/")

# And handle requests forever
httpd.serve_forever()