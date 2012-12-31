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
from healthvaultlib.exceptions import _get_exception_class_for, HealthVaultHTTPException, HealthVaultException
from .hvcrypto import HVCrypto
from .xmlutils import (   pretty_xml, elt_as_string, parse_group)

logger = logging.getLogger(__name__)


# The version current when we wrote this
HEALTHVAULT_VERSION = "1.11.1023.7909"

def format_datetime(dt):
    """Format a datetime for use in HealthVault requests.

    :param dt: The datetime to format
    :type dt: datetime.datetime
    :returns: time in `HealthVault dateTime format
        <http://msdn.microsoft.com/en-us/library/ms256220.aspx>`_ (CCYY-MM-DDThh:mm:ss)
    :rtype: string
    """
    return dt.strftime("%Y-%m-%dT%H:%m:%S")


def _msg_time():
    """Get value to use as `msg-time` in a request.

    :returns: Current time in `HealthVault dateTime format
        <http://msdn.microsoft.com/en-us/library/ms256220.aspx>`_ (CCYY-MM-DDThh:mm:ss)
    :rtype: string
    """
    return format_datetime(datetime.datetime.now())


class HealthVaultConn(object):
    """A HealthVaultConn object is used to access data for one patient ("record").

    When the HealthVaultConn object is created, it connects to the server to verify the credentials it was given,
    and retrieve the record ID corresponding to the WCTOKEN.

    Often you won't have the WCTOKEN yet. Leave it out and the HealthVaultConn object will get an
    authorized session to HealthVault but not yet get the record ID.

    To get a WCTOKEN, also known as the `user auth token`, your web application needs to redirect
    the user to HealthVault to grant your application authorization to access their data. You can
    use :py:meth:`.authorization_url` to get the full URL to redirect the user to. When
    that's done, HealthVault will redirect the user to your URL (that you passed to :py:meth:`.authorization_url`)
    and add query parameters including the auth token. Your app needs to accept that request and
    parse it for the user auth token.

    Then call :py:meth:`.connect` passing the user's auth token, and HealthVaultConn will verify access and
    retrieve the record id and person id for the record and person that the user has granted
    access to.

    Check the record id (:py:attr:`.record_id`). The user could change the person (patient)
    they're granting access to, and this is the only way for an application to tell
    that this `HealthVaultConn` object is now accessing data
    for a different person.

    When constructing a new `HealthVaultConn` for the first time, you will leave out `wctoken`,
    `sharedsec`, `auth_token`, and `record_id` because they aren't known yet.

    Once a `HealthVaultConn` has been constructed successfully, it will have established authentication
    with HealthVault. You can save the sharedsec and auth_token attributes and re-use them when constructing
    future `HealthVaultConn` objects to skip the original authentication call.

    Once a `HealthVaultConn` has been successfully connected to a particular patient's data (`.connect`
    called, or wctoken passed in the constructor successfully), you can
    additionally save the `wctoken` and `record_id` attributes and re-use them when constructing
    future `HealthVaultConn` objects that will access the same person's data. However, be careful
    if the wctoken expires and you get a new one, it might be pointing at a different person's data
    with a different record_id. When a wctoken is found to be not valid, it's safest to set the `record_id`
    attribute to None or create a new `HealthVaultConn` without passing a record_id, so the new record_id
    will be retrieved.

    These parameters are related to your application and should not generally change:

    :param string app_id: the application ID (UUID)
    :param string app_thumbprint: the thumbprint displayed in the ACC for the public key we're using
        (40 hex digits)
    :param long public_key: the public key we're using (a very long number)
    :param long private_key: the private key we're using (a very long number)
    :param string server: (optional), the hostname of the server to connect to, defaults to
        "platform.healthvault-ppe.com", the pre-production US server
    :param string shell_server: (optional), the hostname of the shell redirect server to connect to, defaults to
        "account.healthvault-ppe.com", the pre-production US shell server

    These parameters can be used to save re-establishing authentication with HealthVault, but need to
    be saved from another object. One application can use these for all `HealthVaultConn` objects:

    :param string sharedsec: a random string that HealthVaultConn generates if none is passed in. If you save
       an auth_token, you need to save this with it and pass them both into any new HealthVaultConn that you
       want to use them. (string containing a long integer, 20 chars or more)
    :param string auth_token: a long, random-looking string given to us by HealthVault when we authenticate
       our application with them. It's used along with the other cryptographic data in later calls. If you save
       this, save the sharedsec that goes with it and pass them both into any new HealthVaultConn that you
       want to use them.  (240 printable ASCII chars)

    These parameters can be used to save re-establishing authorization for a particular patient's
    data,  but need to be saved from another object. These are specific to accessing one person's
    data:

    :param string wctoken: the token returned from APPAUTH. If not available, leave it out and call
       :py:meth:`.connect(wctoken)` later.  (200 printable ASCII chars)
    :param string record_id: if you already know the wctoken and have saved the corresponding record_id, you can
       pass the record_id along with the wctoken to save a network call to look up the record_id.  Note that if
       the wctoken is found to be invalid (probably expired), the record_id might not be correct when you get a
       new wctoken, so you should set your HealthVaultConn.record_id back to None before getting the new wctoken.
       (UUID)

    :raises: :py:exc:`HealthVaultException` if there's any problem connecting to HealthVault or getting authorized.
    """

    record_id = None
    """
    The HealthVault record ID corresponding to the auth-token.  A string containing a UUID, or None.
    This identifies uniquely the person whose data we are accessing.
    """

    def __init__(self, app_id, app_thumbprint, public_key, private_key, server=None, shell_server=None,
                 sharedsec=None, auth_token=None,
                 wctoken=None, record_id=None):
        self.wctoken = wctoken
        self.app_id = app_id
        self.app_thumbprint = app_thumbprint
        self.public_key = public_key
        self.private_key = private_key
        # Default to the US, pre-production servers
        self.server = server or 'platform.healthvault-ppe.com'
        self.shell_server = shell_server or "account.healthvault-ppe.com"

        self.sharedsec = sharedsec or str(randint(2 ** 64, 2 ** 65 - 1))

        self.record_id = record_id

        self.authorized = False

        if not isinstance(public_key, long):
            raise ValueError("public key must be a long; it's %r" % public_key)
        if not isinstance(private_key, long):
            raise ValueError("public key must be a long; it's %r" % private_key)

        # We can get our auth token now, it's not specific to wctoken
        # This will catch it early if our keys are wrong or something like that
        self.auth_token = auth_token or self._get_auth_token()

        if wctoken:
            self.connect(wctoken)

    def is_authorized(self):
        """Return True if we've been authorized to HealthVault for a user.
        If not, :py:meth:`.connect()` needs to be called before attempting online access.
        Offline access might still be possible.
        """
        return self.authorized

    def connect(self, wctoken):
        """Set the wctoken (user auth token) to use, and establish an authorized session with HealthVault
        that can access this person's data. You don't need to call this if a wctoken
        was passed initially.

        :param string wctoken: The auth token passed to the application after the user has
            authorized the app.  Specifically, this is the value of the `wctoken`
            query parameter on that request.

        :raises: HealthVaultException if there's any problem connecting to HealthVault
            or getting authorized.
        """
        self.wctoken = wctoken
        self.record_id = self._get_record_id()
        self.authorized = True

    def authorization_url(self, callback_url=None, record_id=None):
        """Return the URL that the user needs to be redirected to in order to
        grant authorization to this app to access their data.

        *The callback_url parameter is only valid during development*. The production server will
        always redirect the user to the application's configured ActionURL.
        It might also fail the request if a callback URL is even passed.

        :note: Use a 307 (temporary) redirect. The user's browser might cache
            a 301 (permanent) redirect, resulting in the user not being able to
            get back to the original page because their browser keeps redirecting
            them to HealthVault due to the cached redirect for that URL.

        :param string record_id: Optionally request access to a particular person's
            (patient's) data.  If this is not passed and this `HealthVaultConn` object
            has a record_id associated with it, that will be used. (UUID)

        :param URL callback_url: The URL that the user will be redirected back to after
            they have finished interacting with HealthVault. It will have query
            parameters appended by HealthVault indicating whether the authorization was
            granted, and providing the wctoken value if so.  See also
            :py:meth:`connect`.  **THIS ONLY WORKS WITH PRE-PRODUCTION HEALTHVAULT
            SERVERS. PRODUCTION HEALTHVAULT SERVERS WILL ALWAYS REDIRECT TO THE
            APPLICATIONS `ActionURL` AS CONFIGURED IN HEALTHVAULT.**

        See `APPAUTH <http://msdn.microsoft.com/en-us/library/ff803620.aspx#APPAUTH>`_.
        """
        d = {'appid': self.app_id}
        if callback_url is not None:
            d['redirect'] = callback_url
        record_id = record_id or self.record_id
        if record_id is not None:
            d['extrecordid'] = record_id
        targetqs = urlencode(d)
        return "https://%s/redirect.aspx?%s" % (self.shell_server, urlencode({'target': "APPAUTH", 'targetqs': targetqs}))

    def deauthorization_url(self, callback_url=None):
        """Return the URL that the user needs to be redirected to in order to
        cancel their authorization for this app to access their data. Useful
        for a logout action.

        HealthVault will redirect the user to your application's ActionURL
        with a `target` parameter of `SIGNOUT`.  During development only,
        a different URL may be used by passing it as `callback_url`.

        **The callback_url parameter is only valid during development**. The production server will
        always redirect the user to the application's configured ActionURL.
        It might also fail the request if a callback URL is even passed.

        :param URL callback_url: The URL that the user will be redirected back to after
            they have finished interacting with HealthVault.   **THIS ONLY WORKS WITH
            PRE-PRODUCTION HEALTHVAULT SERVERS. PRODUCTION HEALTHVAULT SERVERS WILL
            ALWAYS REDIRECT TO THE APPLICATIONS `ActionURL` AS CONFIGURED IN HEALTHVAULT.**

        See `APPSIGNOUT <http://msdn.microsoft.com/en-us/library/ff803620.aspx#APPSIGNOUT>`_.
        """
        d = {'appid': self.app_id, 'cred_token': self.auth_token}
        if callback_url is not None:
            d['redirect'] = callback_url
        targetqs = urlencode(d)
        return "https://%s/redirect.aspx?%s" % (self.shell_server, urlencode({'target': "APPSIGNOUT", 'targetqs': targetqs}))


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

        (response, body, tree) = self._send_request(payload)

        key = '{urn:com.microsoft.wc.methods.response.CreateAuthenticatedSessionToken}info'
        info = tree.find(key)
        if info is None:
            raise HealthVaultException("No %s in response (%s)" % (key, body))
        token_elt = info.find('token')
        if token_elt is None:
            logger.error("No session token in response.  Request=%s.  Response=%s" % (payload, body))
            raise HealthVaultException("Something wrong in response from HealthVault getting session token -"
                                       " no token in response (%s)" % body)
        return token_elt.text

    def _get_record_id(self):
        """
        Calls GetPersonInfo, returns selected_record_id

        If this `HealthVaultConn` already has a record_id, just returns that.

        Not part of the public API.
        """
        if self.record_id:
            return self.record_id

        (response, body, tree) = self._build_and_send_request("GetPersonInfo", "<info/>", use_record_id=False)

        record_id_elt = tree.find('{urn:com.microsoft.wc.methods.response.GetPersonInfo}info/person-info/selected-record-id')
        if record_id_elt is None:
            logger.error("No record ID in response.  response=%s" % body)
            raise HealthVaultException("selected record ID not found in HV response (%s)" % body)

        return record_id_elt.text

    def _send_request(self, payload):
        """
        Send payload as a request to the HealthVault API.

        :returns: (response, body, elementtree)

        Contents of return value::

            response
                HTTPResponse

            body
                string with body of response

            elementtree
                ElementTree.Element object with parsed body

        :param string payload: The request body
        :raises: HealthVaultException if HTTP response status is not 200 or status in parsed response is not 0.

        Not part of the public API.
        """
        conn = httplib.HTTPSConnection(self.server, 443)
        conn.putrequest('POST', '/platform/wildcat.ashx')
        conn.putheader('Content-Type', 'text/xml')
        conn.putheader('Content-Length', '%d' % len(payload))
        conn.endheaders()
        #logger.debug("Posting request: %s" % payload)
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
            raise HealthVaultHTTPException("Non-success HTTP response status from HealthVault.  Status=%d, message=%s" %
                                       (response.status, response.reason),
                                        code=response.status)
        body = response.read()
        tree = ET.fromstring(body)
        status = int(tree.find('status/code').text)
        if status != 0:
            msg = tree.find("status/error/message").text
            logger.error("HealthVault error. status=%d, message=%s, request=%s, response=%s" % (status, msg, pretty_xml(payload), pretty_xml(body)))
            exc_class = _get_exception_class_for(status)
            raise exc_class(
                "Non-success status from HealthVault API.  Status=%d, message=%s" % (status, msg),
                code=status
            )
        #logger.debug("response body=%r" % body)
        return (response, body, tree)

        #HVAULT DataTypes
        #basicdemo = "bf516a61-5252-4c28-a979-27f45f62f78d"
        #ccrtype = "9c48a2b8-952c-4f5a-935d-f3292326bf54"
        #conditions = "7ea7a1f9-880b-4bd4-b593-f5660f20eda8"
        #weightmeasurementype = "3d34d87e-7fc1-4153-800f-f56592cb0d17"

    def _build_and_send_request(self, method_name, info, method_version=1, use_record_id=True,
                               use_target_person_id=False, use_wctoken=True):
        """
        Given the <info>...</info> part of a request, wrap it with all the identification and auth stuff
        to form a complete request, call sendRequest() to send it, and return whatever sendRequest returns.

        :param string method_name: The name of the method to call, e.g. "GetThings"
        :param string info: The <info> part of the request
        :param integer method_version: Override the default method version (1)
        :param boolean use_record_id: Whether to include the <record-id> in the request (default: True)
        :param boolean use_target_person_id: Whether to include the <target-person-id> in the request (default: False)
        :param boolean use_wctoken: Whether to include the wctoken (<auth-token>) in the request (default: True)

        Not part of the public API.
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

        return self._send_request(payload)

    def batch_get(self, requests):
        """Request multiple kinds of things in a single batch request to reduce round-trip delays.

        :param list requests: A list of dictionaries. Each dictionary must have a 'datatype' key whose value
            is one of the defined datatypes :py:class:`.datatypes.DataType`.  Optionally it can have
            'min_date' and/or 'max_date' keys whose values are Python datetimes. Not all data types make
            sense to provide min_date or max_date with.  Optionally it can also have a 'max' key whose
            value is the integer maximum number of records to return.

            Records are always sorted by effective date descending, so passing max=1 will return the
            most recent record.

            Example::

                from healthvaultlib.datatypes import DataType
                batch_get([{'datatype': DataType.WEIGHT_MEASUREMENT, 'max': 1},
                           {'datatype': DataType.HEIGHT_MEASUREMENT, 'min_date': datetime.datetime(...)},
                           {'datatype': DataType.DEVICES}])

        :returns: A list containing, in order, the same results that calling the individual methods to get the
            various datatypes would have returned.

            Example::

                [what get_weight_measurements(max=1) would have returned,
                 what get_height_measurements(min_date=...) would have returned,
                 what get_devices() would have returned]
        """

        # Special case to allow passing a single request without making a list
        if not isinstance(requests, list):
            requests = [requests]

        groups = [self._build_thing_group(**request) for request in requests]
        info = '<info>' + ''.join(groups) + '</info>'

        (response, body, tree) = self._build_and_send_request("GetThings", info)
        #logger.debug("get_things response body:\n%s", body)
        info = tree.find('{urn:com.microsoft.wc.methods.response.GetThings}info')
        response = [parse_group(group) for group in info.findall('group')]
        return response

    def associate_alternate_id(self, idstring):
        """Associate some identification string from your application to the current person and record.

        This uses `AssociateAlternateId <https://platform.healthvault-ppe.com/platform/XSD/method-associatealternateid.xsd>`_

        :param string idstring: The (case-sensitive) identifier to set.
        :raises: :py:exc:`HealthVaultException` on errors. Two possible ones here:

        * ALTERNATE_IDS_LIMIT_EXCEEDED (141) If the account already has the maximum allowable number of alternate ids
            (which appears to be 100).
        * DUPLICATE_ALTERNATE_ID (139) If the application has already associated this alternate id with a person and record.

        See also :py:meth:`get_alternate_ids`.
        """
        info = '<info><alternate-id>%s</alternate-id></info>' % idstring
        self._build_and_send_request("AssociateAlternateId", info)

    def get_alternate_ids(self):
        """Return the list of alternate IDs that have been associated with this person and record by this application.

        This uses `GetAlternateIds <https://platform.healthvault-ppe.com/platform/XSD/response-getalternateids.xsd>`_

        :returns: A list of strings.
        """
        (response, body, tree) = self._build_and_send_request("GetAlternateIds", "<info/>")
        info = tree.find("{urn:com.microsoft.wc.methods.response.GetAlternateIds}info")
        return [elt.text for elt in info.findall("alternate-ids/alternate-id")]

    def disassociate_alternate_id(self, idstring):
        """Disassociate some identification string from your application from the current person and record.

        This uses `DisassociateAlternateId <https://platform.healthvault-ppe.com/platform/XSD/method-disassociatealternateid.xsd>`_

        :param string idstring: The (case-sensitive) identifier to disassociate.
        :raises: :py:exc:`HealthVaultException` on errors. Example:

        * ALTERNATE_ID_NOT_FOUND (140) If the alternate id has not been associated with a person and record.

        See also :py:meth:`associate_alternate_id` and :py:meth:`get_alternate_ids`.
        """
        info = '<info><alternate-id>%s</alternate-id></info>' % idstring
        self._build_and_send_request("DisassociateAlternateId", info)

    def _build_thing_group(self, datatype, min_date=None, max_date=None, max=None, filter=None):
        """Return the <group>...</group> part of a GetThings request for this datatype
        and optional data parameters.

        :param string datatype: The UUID representing the data type to retrieve.
        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :param integer max: Maximum number of records to return.
        :param string filter: XML to be added to the filter section of the query to
           further limit the data returned.

        :returns: string containing the "<group>...</group>" part of the GetThings request that will
           retrieve that data type with those parameters.

        Internal use only.
        """

        filter = filter or ""
        if min_date:
            filter += '<eff-date-min>' + format_datetime(min_date) + '</eff-date-min>'
        if max_date:
            filter += '<eff-date-max>' + format_datetime(max_date) + '</eff-date-max>'
        if max is None:
            grp_tag = '<group>'
        else:
            grp_tag = '<group max="%d">' % max
        return grp_tag +\
               '<filter>'\
               '<type-id>{datatype}</type-id>'\
               '{filter}' \
               '</filter>'\
               '<format><section>core</section><xml/></format>'\
               '</group>'.format(datatype=datatype, filter=filter)

    def get_things(self, hv_datatype, min_date=None, max_date=None, max=None, filter=None, debug=False):
        """Call the get_things API to retrieve some things (data items).

        See also
        `Querying Data in HealthVault <http://msdn.microsoft.com/en-us/library/jj582876.aspx>`_

        :param string hv_datatype: The UUID representing the data type to retrieve.
        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :param integer max: Maximum number of records to return.
        :param string filter: XML to be added to the filter section of the query to
           further limit the data returned.
        :returns: ElementTree Element object containing the <wc:info> element of the response
        :raises: HealthVaultException if the request doesn't succeed with a 200 status
            or the status in the XML response is non-zero.

        :note: This method is exposed because it might be useful, but in general
            applications can call other, more specific methods to interact with HealthVault,
            and should only need to use this if a HealthVault call is needed that hasn't
            yet been implemented here.
        """

        info = '<info>' + self._build_thing_group(hv_datatype, min_date, max_date, max, filter) + '</info>'

        (response, body, tree) = self._build_and_send_request("GetThings", info)
        if debug:
            logger.debug("get_things response body:\n%s", body)
        info = tree.find('{urn:com.microsoft.wc.methods.response.GetThings}info')
        print "get_things returning: %s" % elt_as_string(info)
        return info


    def get_basic_demographic_info(self):
        """Gets `basic demographic info (v2)
        <http://developer.healthvault.com/pages/types/type.aspx?id=3b3e6b16-eb69-483c-8d7e-dfe116ae6092>`_

        :returns: a dictionary - some values might be None if they're not returned by HealthVault.

        Example::

            {'country_text': 'United States', 'postcode': '27510',
             'country_code': None, 'birthyear': 1963, 'gender': 'm'}

        :raises: HealthVaultException if the request fails in some way.
        """

        return self.batch_get({'datatype': DataType.BASIC_DEMOGRAPHIC_DATA})[0]

    def get_blood_glucose_measurements(self, min_date=None, max_date=None, max=None, debug=False):
        """Get `Blood Glucose Measurements
        <http://developer.healthvault.com/pages/types/type.aspx?id=879e7c04-4e8a-4707-9ad3-b054df467ce4>`_

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :returns: a list of dictionaries.
        """
        return self.batch_get({'datatype': DataType.BLOOD_GLUCOSE_MEASUREMENT, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]

    def get_blood_pressure_measurements(self, min_date=None, max_date=None, max=None):
        """Get `Blood Pressure measurements
        <http://developer.healthvault.com/pages/types/type.aspx?id=ca3c57f4-f4c1-4e15-be67-0a3caf5414ed>`_

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
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
        return self.batch_get({'datatype': DataType.BLOOD_PRESSURE_MEASUREMENTS, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]

    def get_height_measurements(self, min_date=None, max_date=None, max=None):
        """Get `Height measurements
        <http://developer.healthvault.com/pages/types/type.aspx?id=40750a6a-89b2-455c-bd8d-b420a4cb500b>`_

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :returns: list of dictionaries
        """
        return self.batch_get({'datatype': DataType.HEIGHT_MEASUREMENTS, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]

    def get_weight_measurements(self, min_date=None, max_date=None, max=None):
        """Get all `weight measurements
        <http://developer.healthvault.com/pages/types/type.aspx?id=3d34d87e-7fc1-4153-800f-f56592cb0d17>`_

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :returns: a list of dictionaries

        Example::

            [{'when': datetime.datetime object,
              'kg': weight measured in kilograms,
              'lbs': weight measured in pounds
              },...
             ]

        :raises: HealthVaultException if the request fails in some way.
        """
        return self.batch_get({'datatype': DataType.WEIGHT_MEASUREMENTS, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]

    def get_devices(self):
        """Get `devices
        <http://developer.healthvault.com/pages/types/type.aspx?id=ef9cf8d5-6c0b-4292-997f-4047240bc7be>`_

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
        return self.batch_get({'datatype': DataType.DEVICES})[0]

    def get_exercise(self, min_date=None, max_date=None, max=None):
        """Returns `exercise records
        <http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.exercise.2.html>`_

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :returns: list of dictionaries with exercise things
        """
        return self.batch_get({'datatype': DataType.EXERCISE, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]

    def get_sleep_sessions(self, min_date=None, max_date=None, max=None):
        """Returns `sleep session records
        <http://developer.healthvault.com/pages/types/type.aspx?id=11c52484-7f1a-11db-aeac-87d355d89593>`_.

        :param datetime.datetime min_date: Only things with an effective datetime after this are returned.
        :param datetime.datetime max_date: Only things with an effective datetime before this are returned.
        :returns: list of dictionaries with sleep sessions.
        """
        return self.batch_get({'datatype': DataType.SLEEP_SESSIONS, 'min_date': min_date, 'max_date': max_date, 'max': max})[0]
