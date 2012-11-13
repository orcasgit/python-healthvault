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
import xml.etree.ElementTree as ET

from healthvaultlib.hvcrypto import HVCrypto
from healthvaultlib.xmlutils import (when_to_datetime, int_or_none, text_or_none, boolean_or_none, parse_weight,
                                     parse_device, elt_to_string, parse_exercise, parse_height, parse_sleep_session)


logger = logging.getLogger(__name__)


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
    pass


class HealthVaultConn(object):
    """A HealthVaultConn object is used to access data for one HealthVault record.

    When the HealthVaultConn object is created, it connects to the server to verify the credentials it was given,
    and retrieve the record ID corresponding to the WCTOKEN.

    :param WCTOKEN: string, the token returned from APPAUTH
    :param HV_APPID: string, the application ID (a UUID)
    :param APP_THUMBPRINT: string, the thumbprint displayed in the ACC for the public key we're using
    :param PUBLIC_KEY: long, the public key we're using
    :param PRIVATE_KEY: long, the private key we're using
    :param HV_SERVICE_SERVER: string (optional), the hostname of the server to connect to, defaults to
        "platform.healthvault-ppe.com", the pre-production US server

    :raises: HealthVaultException if there's any problem connecting to HealthVault or getting authorized.
    """

    def __init__(self, **config):
        self.wctoken = config['WCTOKEN']

        self.HV_APPID = config['HV_APPID']
        self.APP_THUMBPRINT = config['APP_THUMBPRINT']
        self.server = config.get('HV_SERVICE_SERVER', 'platform.healthvault-ppe.com')

        crypto = HVCrypto(config['PUBLIC_KEY'], config['PRIVATE_KEY'])

        sharedsec = str(randint(2 ** 64, 2 ** 65 - 1))
        self.sharedsec = sharedsec
        sharedsec64 = base64.encodestring(sharedsec)
        #2. create content with shared sec
        content = '<content>' \
                      '<app-id>' + self.HV_APPID + '</app-id>' \
                      '<shared-secret>' \
                          '<hmac-alg algName="HMACSHA1">' + sharedsec64 + '</hmac-alg>' \
                      '</shared-secret>' \
                  '</content>'
        #3. create header
        header = "<header>" \
                     "<method>CreateAuthenticatedSessionToken</method>" \
                     "<method-version>1</method-version>" \
                     "<app-id>" + self.HV_APPID + "</app-id>" \
                     "<language>en</language><country>US</country>" \
                     "<msg-time>2008-06-21T03:13:50.750-04:00</msg-time>" \
                     "<msg-ttl>36000</msg-ttl>" \
                     "<version>0.0.0.1</version>" \
                 "</header>"
        self.signature = crypto.sign(content)
        #4. create info with signed content
        info = '<info>' \
                   '<auth-info>' \
                       '<app-id>' + self.HV_APPID + '</app-id>' \
                       '<credential>' \
                           '<appserver>' \
                               '<sig digestMethod="SHA1" sigMethod="RSA-SHA1" thumbprint="' + self.APP_THUMBPRINT + '">' \
                                     + self.signature + \
                               '</sig>'\
                               + content + \
                           '</appserver>' \
                       '</credential>' \
                   '</auth-info>' \
               '</info>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + header + info + '</wc-request:request>'
        extra_headers = {'Content-type': 'text/xml'}

        (response, body, tree) = self.sendRequest(payload)

        token_elt = tree.find('{urn:com.microsoft.wc.methods.response.CreateAuthenticatedSessionToken}info/token')
        if token_elt is None:
            logger.error("No session token in response.  Request=%s.  Response=%s" % (payload, body))
            raise HealthVaultException("Something wrong in response from HealthVault getting session token -"
                                       " no token in response (%s)" % body)
        self.auth_token = token_elt.text

        #5 After you get the auth_token.. get the record id
        header = '<header>' \
                 '<method>GetPersonInfo</method>' \
                 '<method-version>1</method-version>' \
                 '<auth-session>' \
                    '<auth-token>' + self.auth_token + '</auth-token>' \
                    '<user-auth-token>' + self.wctoken + '</user-auth-token>' \
                 '</auth-session>' \
                 '<language>en</language><country>US</country>' \
                 '<msg-time>%s</msg-time>' \
                 '<msg-ttl>36000</msg-ttl>' \
                 '<version>0.0.0.1</version>' % _msg_time()
        info = '<info/>'
        infodigest = base64.encodestring(hashlib.sha1(info).digest())
        headerinfo = '<info-hash><hash-data algName="SHA1">' + infodigest.strip() + '</hash-data></info-hash>'
        header = header + headerinfo + '</header>'

        hashedheader = hmac.new(sharedsec, header, hashlib.sha1)
        hashedheader64 = base64.encodestring(hashedheader.digest())

        hauthxml = '<auth><hmac-data algName="HMACSHA1">' + hashedheader64.strip() + '</hmac-data></auth>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + hauthxml + header + info + '</wc-request:request>'

        (response, body, tree) = self.sendRequest(payload)

        record_id_elt = tree.find('{urn:com.microsoft.wc.methods.response.GetPersonInfo}info/person-info/selected-record-id')
        if record_id_elt is None:
            logger.error("No record ID in response.  request=%s, response=%s" % (payload, body))
            raise HealthVaultException("selected record ID not found in HV response (%s)" % body)
        self.record_id = record_id_elt.text

    def sendRequest(self, payload):
        """
        Send payload as a request to the HealthVault API.
        Returns (response, body, elementtree):

        response = HTTPResponse
        body = string with body of response
        elementtree = ElementTree.Element object with parsed body

        :raises: HealthVaultException if HTTP response status is not 200 or status in parsed response is not 0.
        """
        conn = httplib.HTTPSConnection(self.server, 443)
        conn.putrequest('POST', '/platform/wildcat.ashx')
        conn.putheader('Content-Type', 'text/xml')
        conn.putheader('Content-Length', '%d' % len(payload))
        conn.endheaders()
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
            logger.error("HealthVault error. status=%d, message=%s, request=%s, response=%s" % (status, msg, payload, body))
            raise HealthVaultException("Non-success status from HealthVault API.  Status=%d, message=%s" % (status, msg))
        return (response, body, tree)

        #HVAULT DataTypes
        #basicdemo = "bf516a61-5252-4c28-a979-27f45f62f78d"
        #ccrtype = "9c48a2b8-952c-4f5a-935d-f3292326bf54"
        #conditions = "7ea7a1f9-880b-4bd4-b593-f5660f20eda8"
        #weightmeasurementype = "3d34d87e-7fc1-4153-800f-f56592cb0d17"

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
        infodigest = base64.encodestring(hashlib.sha1(info).digest())
        headerinfo = '<info-hash><hash-data algName="SHA1">' + infodigest.strip() + '</hash-data></info-hash>'

        header = '<header>' \
                     '<method>GetThings</method>' \
                     '<method-version>1</method-version>' \
                     '<record-id>' + self.record_id + '</record-id>' \
                     '<auth-session>' \
                        '<auth-token>' + self.auth_token + '</auth-token>' \
                        '<user-auth-token>' + self.wctoken + '</user-auth-token>' \
                     '</auth-session>' \
                     '<language>en</language>' \
                     '<country>US</country>' \
                     '<msg-time>' + _msg_time() + '</msg-time>' \
                     '<msg-ttl>36000</msg-ttl>' \
                     '<version>0.0.0.1</version>' + headerinfo + \
                 '</header>'

        hashedheader = hmac.new(self.sharedsec, header, hashlib.sha1)
        hashedheader64 = base64.encodestring(hashedheader.digest())

        hauthxml = '<auth><hmac-data algName="HMACSHA1">' + hashedheader64.strip() + '</hmac-data></auth>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + hauthxml + header + info + '</wc-request:request>'

        (response, body, tree) = self.sendRequest(payload)

        info = tree.find('{urn:com.microsoft.wc.methods.response.GetThings}info')
        return info


    def getBasicDemographicInfo(self):
        """Gets basic demographic info (v2):
        http://developer.healthvault.com/pages/types/type.aspx?id=3b3e6b16-eb69-483c-8d7e-dfe116ae6092

        :returns: a dictionary - some values might be None if they're not returned by HealthVault.  Example::

            {'country_text': 'United States', 'postcode': '27510',
             'country_code': None, 'birthyear': 1963, 'gender': 'm'}

        :raises: HealthVaultException if the request fails in some way.
        """

        info = self.getThings("3b3e6b16-eb69-483c-8d7e-dfe116ae6092")


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

        :returns: a list of dictionaries::

            [{'when': datetime.datetime object,
              FIXME - FILL IN
             ]

        :param min_date: Only things with an effective datetime after this are returned.
        :type min_date: datetime.datetime
        :param max_date: Only things with an effective datetime before this are returned.
        :type max_date: datetime.datetime
        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings("ca3c57f4-f4c1-4e15-be67-0a3caf5414ed", min_date, max_date)

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
        info = self.getThings("40750a6a-89b2-455c-bd8d-b420a4cb500b", min_date, max_date)
        return [parse_height(e) for e in info.findall('group/thing/data-xml/height')]

    def getWeightMeasurements(self, min_date=None, max_date=None):
        """Get all weight measurements.

        :returns: a list of dictionaries::

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
        info = self.getThings("3d34d87e-7fc1-4153-800f-f56592cb0d17", min_date, max_date)
        return [parse_weight(e) for e in info.findall('group/thing/data-xml/weight')]

    def getDevices(self):
        """Get devices.

        :returns: a list of dictionaries.  Example::

            {'when': datetime.datetime(2008, 1, 1, 10, 30), 'device_name': 'Digital Peak Flow Meter'}

        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings("ef9cf8d5-6c0b-4292-997f-4047240bc7be")
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
        """
        info = self.getThings("85a21ddb-db20-4c65-8d30-33c899ccf612", min_date, max_date)
        return [parse_exercise(e) for e in info.findall('group/thing/data-xml/exercise')]

    def getSleepSessions(self, min_date=None, max_date=None):
        info = self.getThings("11c52484-7f1a-11db-aeac-87d355d89593", min_date, max_date)
        return [parse_sleep_session(s) for s in info.findall('group/thing/data-xml/sleep-am')]

