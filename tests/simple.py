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
from ssl import wrap_socket
import os
from urllib import urlencode
from urlparse import urlparse, parse_qs
import webbrowser
from healthvaultlib.datatypes import DataType
from healthvaultlib.healthvault import HealthVaultConn, HealthVaultException

# FIXME: This is my test app
APP_ID = "0ce9374d-f6d9-4314-afcc-57f3c8863ba0"
THUMBPRINT = "67E6AAB1C33781D17B82F8B0D78C0DF1BE3D8866"
APP_PUBLIC_KEY = long("b81c20fc71cc63324ccb3860c8a092c464f9e54cbe6f228fb79d0a9b2e303c3b233989b4a45fa1b8595b42791beed"
                      "20c005e973ee7dcb657e735f3399d259dd25d63ac3669040dbf06030e009dfa815d1957cd0e89474d0d8addbfe435"
                      "4df1f72b37592aa49686d8d7d1d0246017ec8763b917508a05c880bff23cfaffd74290dfbe7d5b94e61bb8cb4df86"
                      "883306e6eb4d884feb70c66b2e3925ad86ebcbaee2517d24466ead5c13488dc339723f286b800e255a32ef69f69a2"
                      "f25c1e3bde49da00a6473d2b256b156fc52ffe597e56017dd49be697083c861ceb43ebf4927fe08165020df6690c3"
                      "4bcd8e4bacf1344b72cf42ec744407fb9f44c8c16ef9f77", 16)
APP_PRIVATE_KEY = long("4f2e79d958b008b1a7697773d89586c9c48bdd5c6642b1e0919d8ee432b738104f13fdef9d0a2c2976f4d2dff76d"
                       "7d15004bae4cb5b7ad0c9d3a0cc3689cb705b4789ba64300255154aa97a9184896be8d99bf6d5309415063baff3e"
                       "8cd65b0c6c9fbf4fa1bdc37d1b44f779cd823c8df60bb2c546b73a0675871f46ec258e50b9232f2d4a782b67f9c7"
                       "5590e1bea4eb483286317b72cf11ee1df5bf56d8afef68b2504991cb3fd907f575b6f809f33e45be992598ccb475"
                       "ffd0a020e46d053233eccb07422813c9e50643b6b547fca8941a919b6c2f7e717115110a6fb51b9012f64ff69c78"
                       "88fbe3ecde8c277dec1c147b115ff5400af6146dded23419f191", 16)


# Lots of logging
import logging

handler = logging.StreamHandler()
root_logger = logging.getLogger('')
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(handler)
logger = logging.getLogger(__name__)

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        """We need to init a lot because a new one of these gets created for every request.
        Things we need to keep around we attach to the server object via self.server
        """
        self.server = server  # the superclass __init__ does this anyway

        if not hasattr(self.server, 'conn'):
            wctoken = None
            if os.path.exists("WCTOKEN"):
                with open("WCTOKEN", "r") as f:
                    wctoken = f.read()
                    if not wctoken:
                        os.remove("WCTOKEN")

            try:
                self.server.conn = HealthVaultConn(
                    wctoken=wctoken,
                    app_id=APP_ID,
                    app_thumbprint=THUMBPRINT,
                    public_key=APP_PUBLIC_KEY,
                    private_key=APP_PRIVATE_KEY
                )
            except HealthVaultException as e:
                print e
                # Leave it un-authorized
                # set up un-authorized conn
                self.server.conn = HealthVaultConn(
                    app_id=APP_ID,
                    app_thumbprint=THUMBPRINT,
                    public_key=APP_PUBLIC_KEY,
                    private_key=APP_PRIVATE_KEY
                )

        # And this is a stupid old-style class, sigh
        # AND THE __init__ PROCESSES THE REQUEST!  ARGGG
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def show_data(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        conn = self.server.conn

        self.wfile.write("<p>Record id: %s</p>\n" % conn.record_id)
        self.wfile.write("<p>Person id: %s</p>\n" % conn.person_id)

        #conn.get_authorized_people()
        #conn.get_application_info()

        (sub_id, notification_key) = conn.subscribe_to_event("https://thalia.caktusgroup.com:9123/sub/", [DataType.height_measurements])
        self.wfile.write('<p>New subscription: %s, %s</p>\n' % (sub_id, notification_key))

        try:
            data = conn.get_event_subscriptions()
        except HealthVaultException as e:
            self.wfile.write("Exception getting subscriptions: %s<br/>\n" % e)
        else:
            self.wfile.write("SUBSCRIPTIONS:<br/>\n<ul>\n")
            for w in data:
                self.wfile.write("<li>%s</li>\n" % str(w))
                # Let's delete them as we go
                #sub_id = w['common']['id']
                #conn.unsubscribe_to_event(sub_id)
            self.wfile.write("</ul>\n")

        try:
            data = conn.getBasicDemographicInfo()
        except HealthVaultException as e:
            self.wfile.write("Exception getting basic demographic data: %s<br/>\n" % e)
        else:
            self.wfile.write("Demographic data:<br/>\n")
            self.wfile.write(data)
            self.wfile.write("<br/>\n")

        try:
            data = conn.getWeightMeasurements()
        except HealthVaultException as e:
            self.wfile.write("Exception getting weight measurements: %s<br/>\n" % e)
        else:
            self.wfile.write("WEIGHTS:<br/>\n<ul>\n")
            for w in data:
                self.wfile.write("<li>%s</li>\n" % str(w))
            self.wfile.write("</ul>\n")

        try:
            data = conn.getDevices()
        except HealthVaultException as e:
            self.wfile.write("Exception getting device data: %s<br/>\n" % e)
        else:
            self.wfile.write("DEVICES:<br/>\n<ul>\n")
            for w in data:
                self.wfile.write("<li>%s</li>\n" % str(w))
            self.wfile.write("</ul>\n")

        try:
            data = conn.getBloodPressureMeasurements()
        except HealthVaultException as e:
            self.wfile.write("Exception getting BP: %s<br/>\n" % e)
        else:
            self.wfile.write("BP: <ul>")
            self.wfile.write("".join(["<li>" + repr(d) + "</li>" for d in data]))
            self.wfile.write("</ul>\n")

        try:
            data = conn.getHeightMeasurements()
        except HealthVaultException as e:
            self.wfile.write("Exception getting heights: %s<br/>\n" % e)
        else:
            self.wfile.write("Heights: <ul>")
            self.wfile.write("".join(["<li>" + repr(d) + "</li>" for d in data]))
            self.wfile.write("</ul>\n")

        try:
            data = conn.getExercise()
        except HealthVaultException as e:
            self.wfile.write("Exception getting exercise: %s<br/>\n" % e)
        else:
            self.wfile.write("Exercise: <ul>")
            self.wfile.write("".join(["<li>" + repr(d) + "</li>" for d in data]))
            self.wfile.write("</ul>\n")

        try:
            data = conn.getSleepSessions()
        except HealthVaultException as e:
            self.wfile.write("Exception getting sleep sessions: %s<br/>\n" % e)
        else:
            self.wfile.write("Sleep sessions: <ul>")
            self.wfile.write("".join(["<li>" + repr(d) + "</li>" for d in data]))
            self.wfile.write("</ul>\n")


        self.wfile.write("END.<br/>\n")


    def set_wctoken(self, wctoken):
        # Make sure we can connect okay
        try:
            self.server.conn.connect(wctoken)
        except HealthVaultException as e:
            print "Exception making connection or something: %s" % e
            raise
        else:
            # Looks good, remember it
            with open("WCTOKEN", "w") as f:
                f.write(wctoken)

    def do_POST(self):
        logger.debug("do_POST: will call do_GET to handle, after reading the request body")
        content_length = int(self.headers['content-length'])
        body = self.rfile.read(content_length)
        logger.debug("Incoming request body=%r" % body)
        self.body = body
        return self.do_GET()

    def do_GET(self):
        logger.debug("do_GET: path=%s", self.path)
        if self.path == '/':
            if not self.server.conn.is_authorized():
                logger.debug("Not authorized yet, redir to HV")
                # Start by redirecting user to HealthVault to authorize us
                url = self.server.conn.authorization_url('http://localhost:8000/authtoken')
                self.send_response(307)
                self.send_header("Location", url)
                self.end_headers()
                return
            self.show_data()
            return

        if self.path == '/submit':
            self.send_response(200)
            self.end_headers()
            return

        if self.path.startswith('/authtoken?'):
            # This is the redirect after the user has authed us
            # the params include the wctoken we'll be using from here on for this user's data
            logger.debug("Handling /authtoken...")
            o = urlparse(self.path)
            query = parse_qs(o.query)
            target = query['target'][0]
            if target == 'AppAuthReject':
                logger.debug('reject')
                self.send_response(200)
                self.end_headers()
                self.wfile.write("Auth was rejected (by the user?)")
                return
            if target not in ('AppAuthSuccess', 'SelectedRecordChanged'):
                logger.debug('no idea')
                self.send_response(200)
                self.end_headers()
                self.wfile.write("Unexpected authtoken target=%s\n" % target)
                self.wfile.write(self.path)
                return
            if not 'wctoken' in query:
                logger.debug('no wctoken given')
                self.send_response(200)
                self.end_headers()
                self.wfile.write("No WCTOKEN in query: %s" % self.path)
                self.wfile.close()
                return
            logger.debug("looks like we got a wctoken to use")
            try:
                self.set_wctoken(query['wctoken'][0])
            except HealthVaultException:
                logger.exception("Something went wrong trying to use the token")
                if os.path.exists("WCTOKEN"):
                    os.remove("WCTOKEN")
                self.send_response(307)
                self.send_header("Location", "/")
                self.end_headers()
                return

            logger.debug("Got token okay, redir to /")
            # Now redirect to / again
            self.send_response(307)
            self.send_header("Location", "/")
            self.end_headers()
            return

        # Tired of seeing errors for this one
        if self.path == '/favicon.ico':
            self.send_response(200)
            self.end_headers()
            return

        # We get here for any URL we don't recognize
        print "UNHANDLED URL!!!!  %r" % self.path


class SSLServer(BaseHTTPServer.HTTPServer):
    def server_bind(self):
        """Called by constructor to bind the socket.

        May be overridden.

        """
        self.socket = wrap_socket(self.socket, server_side=True, certfile='cert.pem')
        BaseHTTPServer.HTTPServer.server_bind(self)

# Start server
server_address = ('', 8000)
httpd = SSLServer(server_address, Handler)

# Point user's browser at our starting URL
#webbrowser.open("https://localhost:8000/")

# And handle requests forever
httpd.serve_forever()