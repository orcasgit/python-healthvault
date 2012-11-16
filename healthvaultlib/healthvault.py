#The MIT License
#Copyright (c) 2008 Applied Informatics, Inc.

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

import base64
import hashlib
import hmac
import httplib
import logging
from random import randint
import socket
import datetime
from urllib import urlencode
import xml.etree.ElementTree as ET

from .datatypes import DataType
from .hvcrypto import HVCrypto
from .xmlutils import (when_to_datetime, int_or_none, text_or_none, boolean_or_none, parse_weight,
                       parse_device, elt_to_string, parse_exercise, parse_height, parse_sleep_session, prettyxml, parse_subscription, parse_notification)

from Crypto.Random import get_random_bytes


logger = logging.getLogger(__name__)


# The version current when we wrote this
HEALTHVAULT_VERSION = "1.11.1023.7909"

def format_datetime(dt):
    """Format a datetime for use in HealthVault requests.

    :param dt: The datetime to format
    :type dt: datetime.datetime
    :returns: A string in the format CCYY-MM-DDThh:mm:ss
    """
    # http://msdn.microsoft.com/en-us/library/ms256220.aspx
    return dt.strftime("%Y-%m-%dT%H:%m:%S")


def _msg_time():
    """Return value to use as `msg-time` in a request."""
    # dateTime format: see <http://msdn.microsoft.com/en-us/library/ms256220.aspx>
    # CCYY-MM-DDThh:mm:ss
    return format_datetime(datetime.datetime.now())


class HealthVaultException(Exception):
    """This exception is raised for any error in the python-healthvault library.

    """
    pass


class HealthVaultConn(object):
    """A HealthVaultConn object is used to access data for one person from one HealthVault record.

    When the HealthVaultConn object is created, it connects to the server to verify the credentials it was given,
    and retrieve the record ID corresponding to the WCTOKEN.

    Often you won't have the WCTOKEN yet. Leave it out and the HealthVaultConn object will get an
    authorized session to HealthVault but not yet get the record ID.

    To get a WCTOKEN, also known as the user auth token, your web application needs to redirect
    the user to HealthVault to grant your application authorization to access their data. You can
    use :py:meth:`.authorization_url` to get the full URL to redirect the user to. When
    that's done, HealthVault will redirect the user to your URL (that you passed to :py:meth:`.authorization_url`)
    and add query parameters including the auth token. Your app needs to accept that request and
    parse it for the user auth token.

    Then call :py:meth:`.connect` passing the user's auth token, and HealthVaultConn will verify access and
    retrieve the record id and person id for the record and person that the user has granted
    access to.

    :param app_id: string, the application ID (a UUID)
    :param app_thumbprint: string, the thumbprint displayed in the ACC for the public key we're using
    :param public_key: long, the public key we're using
    :param private_key: long, the private key we're using
    :param server: string (optional), the hostname of the server to connect to, defaults to
        "platform.healthvault-ppe.com", the pre-production US server
    :param shell_server: string (optional), the hostname of the shell redirect server to connect to, defaults to
        "account.healthvault-ppe.com", the pre-production US shell server
    :param wctoken: string, the token returned from APPAUTH. If not available, leave it out and call
       :py:meth:`.connect(wctoken)` later.

    :raises: :py:exc:`HealthVaultException` if there's any problem connecting to HealthVault or getting authorized.
    """

    def __init__(self, app_id, app_thumbprint, public_key, private_key, server=None, shell_server=None, wctoken=None):
        self.wctoken = wctoken
        self.app_id = app_id
        self.app_thumbprint = app_thumbprint
        self.public_key = public_key
        self.private_key = private_key
        # Default to the US, pre-production servers
        self.server = server or 'platform.healthvault-ppe.com'
        self.shell_server = shell_server or "account.healthvault-ppe.com"

        self.sharedsec = str(randint(2 ** 64, 2 ** 65 - 1))
        self.record_id = None

        self.authorized = False

        if not isinstance(public_key, long):
            raise ValueError("public key must be a long; it's %r" % public_key)
        if not isinstance(private_key, long):
            raise ValueError("public key must be a long; it's %r" % private_key)

        # We can get our auth token now, it's not specific to wctoken
        # This will catch it early if our keys are wrong or something like that
        self.auth_token = self._get_auth_token()

        if wctoken:
            self.connect(wctoken)

    def is_authorized(self):
        """Return True if we've been authorized to HealthVault for a user.
        If not, :py:meth:`.connect()` needs to be called before attempting online access.
        Offline access might still be possible.
        """
        return self.authorized

    def connect(self, wctoken):
        """Set the wctoken to use, and establish an authorized session with HealthVault
        that can access this person's data.
        User doesn't need to call this if a wctoken was passed initially.

         :raises: HealthVaultException if there's any problem connecting to HealthVault
            or getting authorized.
        """
        self.wctoken = wctoken
        self.record_id, self.person_id = self._get_record_id()
        self.authorized = True

    def authorization_url(self, callback_url):
        """Return the URL that the user needs to be redirected to in order to
        grant authorization to this app to access their data.

        :note: Use a 307 (temporary) redirect. The user's browser might cache
            a 301 (permanent) redirect, resulting in the user not being able to
            get back to the original page because their browser keeps redirecting
            them to HealthVault due to the cached redirect for that URL.

        :param callback_url: The URL that the user will be redirected back to after
            they have finished interacting with HealthVault. It will have query
            parameters appended by HealthVault indicating whether the authorization was
            granted, and providing the wctoken value if so.

        """
        targetqs = urlencode({'appid': self.app_id, 'redirect': callback_url})
        return "https://%s/redirect.aspx?%s" % (self.shell_server, urlencode({'target': "APPAUTH", 'targetqs': targetqs}))

    def _get_auth_token(self):
        """Call HealthVault and get a session token, returning it.

        Not part of the public API, just factored out of __init__ for testability.
        """

        # Interesting note: wctoken is not needed here. The token we're getting is just
        # for our app and is not specific to a particular user.

        crypto = HVCrypto(self.public_key, self.private_key)

        sharedsec64 = base64.encodestring(self.sharedsec)

        content = '<content>'\
                      '<app-id>' + self.app_id + '</app-id>'\
                      '<shared-secret>'\
                          '<hmac-alg algName="HMACSHA1">' + sharedsec64 + '</hmac-alg>'\
                      '</shared-secret>'\
                  '</content>'
        #3. create header
        header = "<header>"\
                     "<method>CreateAuthenticatedSessionToken</method>"\
                     "<method-version>1</method-version>"\
                     "<app-id>" + self.app_id + "</app-id>"\
                     "<language>en</language><country>US</country>"\
                     "<msg-time>2008-06-21T03:13:50.750-04:00</msg-time>"\
                     "<msg-ttl>36000</msg-ttl>"\
                     "<version>" + HEALTHVAULT_VERSION + "</version>"\
                 "</header>"
        self.signature = crypto.sign(content)
        #4. create info with signed content
        info = '<info>'\
                   '<auth-info>'\
                       '<app-id>' + self.app_id + '</app-id>'\
                       '<credential>'\
                            '<appserver>'\
                                '<sig digestMethod="SHA1" sigMethod="RSA-SHA1" thumbprint="' + self.app_thumbprint + '">'\
                                       + self.signature +\
                                '</sig>'\
                                + content +\
                            '</appserver>'\
                       '</credential>'\
                   '</auth-info>'\
               '</info>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + header + info + '</wc-request:request>'

        (response, body, tree) = self._sendRequest(payload)

        token_elt = tree.find('{urn:com.microsoft.wc.methods.response.CreateAuthenticatedSessionToken}info/token')
        if token_elt is None:
            logger.error("No session token in response.  Request=%s.  Response=%s" % (payload, body))
            raise HealthVaultException("Something wrong in response from HealthVault getting session token -"
                                       " no token in response (%s)" % body)
        return token_elt.text

    def _get_record_id(self):
        """
        Returns (selected_record_id, person_id)
        """
        (response, body, tree) = self._build_and_send_request("GetPersonInfo", "<info/>", use_record_id=False)

        record_id_elt = tree.find('{urn:com.microsoft.wc.methods.response.GetPersonInfo}info/person-info/selected-record-id')
        if record_id_elt is None:
            logger.error("No record ID in response.  response=%s" % body)
            raise HealthVaultException("selected record ID not found in HV response (%s)" % body)
        person_id_elt = tree.find('{urn:com.microsoft.wc.methods.response.GetPersonInfo}info/person-info/person-id')
        if person_id_elt is None:
            logger.error("No person ID in response. Response=%s" % body)
            raise HealthVaultException("person ID not found in HV response (%s)" % body)

        return (record_id_elt.text, person_id_elt.text)

    def _sendRequest(self, payload):
        """
        Send payload as a request to the HealthVault API.

        :returns: (response, body, elementtree)

        Contents of return value::

            response:  HTTPResponse
            body:  string with body of response
            elementtree: ElementTree.Element object with parsed body

        :raises: HealthVaultException if HTTP response status is not 200 or status in parsed response is not 0.
        """
        conn = httplib.HTTPSConnection(self.server, 443)
        conn.putrequest('POST', '/platform/wildcat.ashx')
        conn.putheader('Content-Type', 'text/xml')
        conn.putheader('Content-Length', '%d' % len(payload))
        conn.endheaders()
        logger.debug("Posting request: %s" % payload)
        try:
            conn.send(payload)
        except socket.error, v:
            if v[0] == 32:      # Broken pipe
                conn.close()
            raise
        response = conn.getresponse()
        if response.status != 200:
            logger.error("Non-success HTTP response status from HealthVault.  Status=%d, message=%s" %
                         (response.status, response.reason))
            raise HealthVaultException("Non-success HTTP response status from HealthVault.  Status=%d, message=%s" %
                                       (response.status, response.reason))
        body = response.read()
        tree = ET.fromstring(body)
        status = int(tree.find('status/code').text)
        if status != 0:
            msg = tree.find("status/error/message").text
            logger.error("HealthVault error. status=%d, message=%s, request=%s, response=%s" % (status, msg, prettyxml(payload), prettyxml(body)))
            raise HealthVaultException("Non-success status from HealthVault API.  Status=%d, message=%s" % (status, msg))
        logger.debug("response body=%r" % body)
        return (response, body, tree)

        #HVAULT DataTypes
        #basicdemo = "bf516a61-5252-4c28-a979-27f45f62f78d"
        #ccrtype = "9c48a2b8-952c-4f5a-935d-f3292326bf54"
        #conditions = "7ea7a1f9-880b-4bd4-b593-f5660f20eda8"
        #weightmeasurementype = "3d34d87e-7fc1-4153-800f-f56592cb0d17"

    def _build_and_send_request(self, method_name, info, method_version=1, use_record_id=True,
                               use_target_person_id=False, use_wctoken=True):
        """
        (internal method)

        Given the <info>...</info> part of a request, wrap it with all the identification and auth stuff
        to form a complete request, call sendRequest() to send it, and return whatever sendRequest returns.

        :param method_name: String with the name of the method to call, e.g. "GetThings"
        :param info: String with the <info> part of the request
        :param method_version: Override the default method version (1)
        :param use_record_id: Whether to include the <record-id> in the request (default: True)
        :param use_target_person_id: Whether to include the <target-person-id> in the request (default: False)
        :param use_wctoken: Whether to include the wctoken (<auth-token>) in the request (default: True)
        """
        # https://platform.healthvault-ppe.com/platform/XSD/request.xsd

        infodigest = base64.encodestring(hashlib.sha1(info).digest())
        headerinfo = '<info-hash><hash-data algName="SHA1">' + infodigest.strip() + '</hash-data></info-hash>'

        header = '<header>'\
                 '<method>' + method_name + '</method>'\
                 '<method-version>' + str(method_version) + '</method-version>'
        if use_target_person_id:
            if self.person_id is not None:
                header += "<target-person-id>" + self.person_id + "</target-person-id>"
            else:
                raise ValueError("person ID is not available but use_target_person_id is True")
        if use_record_id:
            if self.record_id is not None:
                header += '<record-id>' + self.record_id + '</record-id>'
            else:
                raise ValueError("record ID is not available but use_record_id is True")

        header += \
                 '<auth-session>'\
                 '<auth-token>' + self.auth_token + '</auth-token>'
        if use_wctoken:
            if self.wctoken is not None:
                header += '<user-auth-token>' + self.wctoken + '</user-auth-token>'
            else:
                raise ValueError("wctoken is not available but use_wctoken is True")
        header += \
                 '</auth-session>'\
                 '<language>en</language>'\
                 '<country>US</country>'\
                 '<msg-time>' + _msg_time() + '</msg-time>'\
                 '<msg-ttl>36000</msg-ttl>'\
                 '<version>' + HEALTHVAULT_VERSION + '</version>' + headerinfo +\
                 '</header>'

        hashedheader = hmac.new(self.sharedsec, header, hashlib.sha1)
        hashedheader64 = base64.encodestring(hashedheader.digest())

        hauthxml = '<auth><hmac-data algName="HMACSHA1">' + hashedheader64.strip() + '</hmac-data></auth>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + hauthxml + header + info + '</wc-request:request>'

        return self._sendRequest(payload)

    def get_application_info(self):
        (response, body, tree) = self._build_and_send_request("GetApplicationInfo", "<info/>", method_version=2)
        print prettyxml(body)

    def get_authorized_people(self):
        info = '<info><parameters></parameters></info>'

        (response, body, tree) = self._build_and_send_request("GetAuthorizedPeople", info)
        print prettyxml(body)

    def parse_notification_body(self, body):
        """Given the body of a notification event request from HealthVault,
        parse it and return the data as nested dictionaries.

        :param body: A string containing the XML from the body of the notification.
        :raises: HealthVaultException if a problem is found in the content.
        :returns: A list of dictionaries, something like this.

        Example::

            [{'common':   {'subscription_id': 'a UUID'},,
            'record_change_notification':   {
                'person_id': 'a UUID representing a person',
                'record_id': 'a UUID representing a record',
                'things': [ 'a', 'list', 'of', 'thing-type', 'uuids'],
            },
            }, ...]
        """

        """From some sample MS code, here's a template of what an incoming notification
        might look like::

            <wc:notifications xmlns:wc='urn:com.microsoft.wc.notification'>
                <notification>
                    <common>
                        <subscription-id>{0}</subscription-id>
                    </common>
                    <record-change-notification>
                        <person-id>{1}</person-id>
                        <record-id>{2}</record-id>
                        <things>
                                {3}
                        </things>
                    </record-change-notification>
                </notification>
            </wc:notifications>

        # Additionally, a request header might contain::

            SomeHeaderName: HVEventingSharedKey subscription_id:key_version:hash_of_stuff

        I'm not sure what the header name should be.
        """

        tree = ET.fromstring(body)

        # https://platform.healthvault-ppe.com/platform/XSD/notification.xsd
        result = [parse_notification(n) for n in tree.findall('notification')]
        return result



    def subscribe_to_event(self, url, thing_types):
        """Create a subscription at HealthVault to be called back when an event happens.

        Can only be used when the person is online.

        Authorization
        The user must have granted the application offline read access to the data type that the subscription refers to.

        Number of subscriptions
        An application can only register 25 subscriptions at a time. This number is subject to change.

        The caller should save the returned GUID and notification key, to identify and validate
        incoming notifications later.

        For more information, see this blog entry
        http://blogs.msdn.com/b/ericgu/archive/2011/01/20/healthvault-event-notifications.aspx
        and this documentation page
        http://msdn.microsoft.com/en-us/library/gg681193.aspx

        :param thing_types: An iterable of strings with UUIDs of Thing types to be notified of changes in
        :param url: The URL that HealthVault will call when an event happens. Must begin with https:
        :returns: (sub_id, notification_key): The GUID of the new subscription (string), and the base64-encoded
            notification key for the subscription.
        """

        # http://blogs.msdn.com/b/ericgu/archive/2011/01/20/healthvault-event-notifications.aspx
        # http://developer.healthvault.com/pages/methods/methods.aspx
        # https://platform.healthvault-ppe.com/platform/XSD/method-subscribetoevent.xsd
        # https://platform.healthvault-ppe.com/platform/XSD/response-subscribetoevent.xsd
        # https://platform.healthvault-ppe.com/platform/XSD/subscription.xsd

        if not url.startswith("https://"):
            raise ValueError("URL for subscribe_to_events must start with https:// but %s does not." % url)

        # Notification key
        # <summary>The base64 encoded key bytes.</summary>
        # <remarks>
        # The length of the key must be 64 bytes before any base64 encoding is applied. The key is used by the
        # HealthVault service as the key input to the HMACSHA256 algorithm. The hash that is output by the algorithm
        # is sent with notifications that HealthVault delivers to the subscription's notification channel. If a key
        # is changed, the version key id should also be changed so that the notification handler can support both
        # keys during the changeover period.

        # We just generate a shared key randomly
        keybytes = get_random_bytes(64)
        notification_key = base64.encodestring(keybytes)
        # and set the version to 1 since this is a new subscription and key
        notification_key_version_id = str(1)

        # for SubscribeToEvent, <info> can contain a <subscription> element (?)
        subscription = '<subscription>'

        # which contains a <common>
        subscription += '<common>'

        # Note: here's where we could specify an ID for the new subscription, according to
        # the schema, but when we try it, the request is rejected as invalid. Just leave it
        # out and return the ID that HealthVaulth made up.

        # auth - we send a key that is used by HV later, when sending notifications, to prove it's them
        subscription += '<notification-authentication-info>'
        subscription += '<hv-eventing-shared-key>'
        subscription += '<notification-key>' + notification_key + '</notification-key>'
        subscription += '<notification-key-version-id>' + notification_key_version_id + '</notification-key-version-id>'
        subscription += '</hv-eventing-shared-key>'
        subscription += '</notification-authentication-info>'

        # how we get notified
        subscription += '<notification-channel>'
        subscription += '<http-notification-channel><url>%s</url></http-notification-channel>' % url
        subscription += '</notification-channel>'
        subscription += '</common>'

        # now, the subscription itself
        # only record item changed events are currently supported
        # and the only filter is on type IDs.
        # so all this nesting is kind of pointless.
        subscription += '<record-item-changed-event><filters><filter><type-ids>'
        for thing_type in thing_types:
            subscription += '<type-id>%s</type-id>' % thing_type
        subscription += '</type-ids></filter></filters></record-item-changed-event>'

        subscription += '</subscription>'

        info = '<info>' + subscription + '</info>'

        # Apparently we should NOT include the wctoken - no idea why not
        # use_target_person_id=True ==> HealthVault error. status=9, message=The account is not active.
        # use_target_person_id=False ==> Status=134, message=None
        #  but 134 is SUBSCRIPTION_INVALID 134 The subscription contains invalid data.  which is promising
        # it would be nice if it said what's invalid about it though
        (response, body, tree) = self._build_and_send_request("SubscribeToEvent", info, use_wctoken=False)

        info = tree.find('{urn:com.microsoft.wc.methods.response.SubscribeToEvent}info')
        sub_id = text_or_none(info, 'subscription-id')
        return (sub_id, notification_key)

    def get_event_subscriptions(self):
        """Get the list of our event subscriptions from HealthVault
        """
        # This request has no content
        # And apparently we should NOT include the wctoken
        # https://platform.healthvault-ppe.com/platform/XSD/response-geteventsubscriptions.xsd
        (response, body, tree) = self._build_and_send_request('GetEventSubscriptions', '<info/>', use_wctoken=False)
        info = tree.find('{urn:com.microsoft.wc.methods.response.GetEventSubscriptions}info')
        return [parse_subscription(sub) for sub in info.findall('subscriptions/subscription')]

    def unsubscribe_to_event(self, sub_id):
        """
        Delete one subscription

        :param sub_id: String containing the ID of a subscription.
        """
        info = '<info><subscription-id>%s</subscription-id></info>' % sub_id
        self._build_and_send_request('UnsubscribeToEvent', info, use_wctoken=False)
        # No need to look at response - either it worked or not, and if not, an exception will have been raised

    def getThings(self, hv_datatype, min_date=None, max_date=None, filter=None):
        """Call the getThings API to retrieve some things (data items).

        :param hv_datatype: string, the UUID representing the data type to retrieve.
        :param min_date: Only things with an effective datetime after this are returned.
        :type min_date: datetime.datetime
        :param max_date: Only things with an effective datetime before this are returned.
        :type max_date: datetime.datetime
        :param filter: string, XML to be added to the filter section of the query to
           further limit the data returned.
        :returns: ElementTree Element object containing the <wc:info> element of the response
        :raises: HealthVaultException if the request doesn't succeed with a 200 status
            or the status in the XML response is non-zero.

        See also http://msdn.microsoft.com/en-us/library/jj582876.aspx on
        Querying Data in HealthVault.
        """

        #QUERY INFO
        filter = filter or ""
        if min_date:
            filter += '<eff-date-min>' + format_datetime(min_date) + '</eff-date-min>'
        if max_date:
            filter += '<eff-date-max>' + format_datetime(max_date) + '</eff-date-max>'
        info = '<info><group>'\
                   '<filter>' \
                       '<type-id>' + hv_datatype + '</type-id>' \
                       + filter + \
                   '</filter>'\
                   '<format><section>core</section><xml/></format>'\
               '</group></info>'

        (response, body, tree) = self._build_and_send_request("GetThings", info)

        info = tree.find('{urn:com.microsoft.wc.methods.response.GetThings}info')
        return info


    def getBasicDemographicInfo(self):
        """Gets basic demographic info (v2):
        http://developer.healthvault.com/pages/types/type.aspx?id=3b3e6b16-eb69-483c-8d7e-dfe116ae6092

        :returns: a dictionary - some values might be None if they're not returned by HealthVault.

        Example::

            {'country_text': 'United States', 'postcode': '27510',
             'country_code': None, 'birthyear': 1963, 'gender': 'm'}

        :raises: HealthVaultException if the request fails in some way.
        """

        info = self.getThings(DataType.basic_demographic_data)

        basic = info.find('group/thing/data-xml/basic')
        return dict(
            gender=text_or_none(basic, 'gender'),
            birthyear=int_or_none(basic, 'birthyear'),
            country_text=text_or_none(basic, 'country/text'),
            country_code=text_or_none(basic, 'country/code/value'),
            postcode=text_or_none(basic, 'postcode'),
            state=text_or_none(basic,'state/text')
        )

    def getBloodPressureMeasurements(self, min_date=None, max_date=None):
        """Get Blood Pressure measurements.

        :returns: a list of dictionaries

        Example::

            [{'systolic': 160,
             'when': datetime.datetime(2012, 11, 12, 11, 24),
              'irregular_heartbeat': None,
              'pulse': 16,
              'diastolic': 80},
              {'systolic': 160,
              'when': datetime.datetime(2012, 11, 13, 8, 2),
              'irregular_heartbeat': None,
              'pulse': 16,
              'diastolic': 80},
              ]

        :param min_date: Only things with an effective datetime after this are returned.
        :type min_date: datetime.datetime
        :param max_date: Only things with an effective datetime before this are returned.
        :type max_date: datetime.datetime
        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings(DataType.blood_pressure_measurements, min_date, max_date)

        things = []
        for thing in info.findall('group/thing/data-xml/blood-pressure'):
            things.append(dict(
                when = when_to_datetime(thing.find("when")),
                systolic = int_or_none(thing, 'systolic'),
                diastolic = int_or_none(thing, 'diastolic'),
                pulse = int_or_none(thing, 'pulse'),
                irregular_heartbeat = boolean_or_none(thing, 'irregular-heartbeat'),
            ))
        return things

    def getHeightMeasurements(self, min_date=None, max_date=None):
        info = self.getThings(DataType.height_measurements, min_date, max_date)
        return [parse_height(e) for e in info.findall('group/thing/data-xml/height')]

    def getWeightMeasurements(self, min_date=None, max_date=None):
        """Get all weight measurements.

        :returns: a list of dictionaries

        Example::

            [{'when': datetime.datetime object,
              'kg': weight measured in kilograms,
              'lbs': weight measured in pounds
              },...
             ]

        :param min_date: Only things with an effective datetime after this are returned.
        :type min_date: datetime.datetime
        :param max_date: Only things with an effective datetime before this are returned.
        :type max_date: datetime.datetime
        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings(DataType.weight_measurements, min_date, max_date)
        return [parse_weight(e) for e in info.findall('group/thing/data-xml/weight')]

    def getDevices(self):
        """Get devices.

        :returns: a list of dictionaries.

        Example::

            [{'vendor': {
                'contact': {
                    'phone': [{'is_primary': True, 'number': ['2069053456'], 'description': 'Office'}],
                    'email': [{'is_primary': True, 'description': 'Office', 'address': 'markbo@live.com'}],
                    'address': [{'city': 'Redmond', 'state': 'WA', 'street': ['NE 34th St'],
                                  'description': '12345 Apt#234', 'country': 'US', 'is_primary': True,
                                  'postcode': '98052'}]
                 },
                 'name': None,
                 'organization': 'Microlife',
                 'type': {'text': 'Provider',
                          'code': [{'version': ['1'], 'type': 'person-types', 'family': ['wc'], 'value': '2'}]
                          },
                'id': '3456789',
                'professional_training': 'A2Z Testing'
              },
              'description': 'Mark Boyce got a Peak flow meter',
              'serial_number': '23456543',
              'model': 'PF100',
              'when': datetime.datetime(2008, 1, 1, 10, 30),
              'device_name': 'Digital Peak Flow Meter'
              }
            ]

        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings(DataType.devices)
        # http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.equipment.device.1.inlinetype.html
        return [parse_device(e) for e in info.findall('group/thing/data-xml/device')]

    def getExercise(self, min_date=None, max_date=None):
        """
        http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.exercise.2.html
        Records the completion of an exercise.

        Type Name: Exercise
        Type Id: 85a21ddb-db20-4c65-8d30-33c899ccf612
        Effective Date Element: when
        Type Root Element: urn:com.microsoft.wc.thing.exercise:exercise

        Uses Other Data Section of Thing: False
        Remarks

        :returns: list of dictionaries with exercise things
        """
        info = self.getThings(DataType.exercise, min_date, max_date)
        return [parse_exercise(e) for e in info.findall('group/thing/data-xml/exercise')]

    def getSleepSessions(self, min_date=None, max_date=None):
        info = self.getThings(DataType.sleep_sessions, min_date, max_date)
        return [parse_sleep_session(s) for s in info.findall('group/thing/data-xml/sleep-am')]

