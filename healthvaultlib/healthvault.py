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
from xml.dom import minidom
import datetime
import xml.etree.ElementTree as ET


from healthvaultlib.hvcrypto import HVCrypto
from healthvaultlib.xmlutils import when_to_datetime, int_or_none, text_or_none


logger = logging.getLogger(__name__)


def _msg_time():
    """Return value to use as `msg-time` in a request."""
    # dateTime format: see <http://msdn.microsoft.com/en-us/library/ms256220.aspx>
    # CCYY-MM-DDThh:mm:ss
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%m:%S")


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
    :param HV_SERVICE_SERVER: string (optional), the hostname of the server to connect to, defaults to "platform.healthvault-ppe.com", the pre-production US server
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
        content = '<content><app-id>' + self.HV_APPID + '</app-id><shared-secret><hmac-alg algName="HMACSHA1">' + sharedsec64 + '</hmac-alg></shared-secret></content>'
        #3. create header
        header = "<header><method>CreateAuthenticatedSessionToken</method><method-version>1</method-version><app-id>" + self.HV_APPID + "</app-id><language>en</language><country>US</country><msg-time>2008-06-21T03:13:50.750-04:00</msg-time><msg-ttl>36000</msg-ttl><version>0.0.0.1</version></header>"
        self.signature = crypto.sign(content)
        #4. create info with signed content
        info = '<info><auth-info><app-id>' + self.HV_APPID + '</app-id><credential><appserver><sig digestMethod="SHA1" sigMethod="RSA-SHA1" thumbprint="' + self.APP_THUMBPRINT + '">' + self.signature + '</sig>' + content + '</appserver></credential></auth-info></info>'
        payload = '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">' + header + info + '</wc-request:request>'
        extra_headers = {'Content-type': 'text/xml'}
        response = self.sendRequest(payload)
        if response.status == 200:
            auth_response = response.read()
            dom = minidom.parseString(auth_response)
            for node in dom.getElementsByTagName("token"):
                self.auth_token = node.firstChild.nodeValue.strip()
        else:
            raise HealthVaultException("error occurred at get auth token - response status = %d, message = %s" % (response.status, response.msg))

        #5 After you get the auth_token.. get the record id
        header = '<header>' \
                 '<method>GetPersonInfo</method>' \
                 '<method-version>1</method-version>' \
                 '<auth-session><auth-token>' + self.auth_token + '</auth-token><user-auth-token>' + self.wctoken + '</user-auth-token></auth-session>' \
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

        response = self.sendRequest(payload)
        if response.status == 200:
            body = response.read()
            dom = minidom.parseString(body)
            self.record_id = None
            for node in dom.getElementsByTagName("selected-record-id"):
                self.record_id = node.firstChild.nodeValue
            if not self.record_id:
                raise HealthVaultException("Could not identify record id in response")
        else:
            raise HealthVaultException("error occurred at select record id - response status = %d, message = %s" % (response.status, response.msg))

    def sendRequest(self, payload):
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
        return response

        #HVAULT DataTypes
        #basicdemo = "bf516a61-5252-4c28-a979-27f45f62f78d"
        #ccrtype = "9c48a2b8-952c-4f5a-935d-f3292326bf54"
        #conditions = "7ea7a1f9-880b-4bd4-b593-f5660f20eda8"
        #weightmeasurementype = "3d34d87e-7fc1-4153-800f-f56592cb0d17"

    def getThings(self, hv_datatype):
        """Call the getThings API to retrieve some things (data items).

        :param hv_datatype: string, the UUID representing the data type to retrieve.
        :returns: ElementTree Element object containing the <wc:info> element of the response
        :raises: HealthVaultException if the request doesn't succeed with a 200 status.
        """

        #QUERY INFO
        info = '<info><group>'\
                   '<filter><type-id>' + hv_datatype + '</type-id></filter>'\
                   '<format><section>core</section><xml/></format>'\
               '</group></info>'
        infodigest = base64.encodestring(hashlib.sha1(info).digest())
        headerinfo = '<info-hash><hash-data algName="SHA1">' + infodigest.strip() + '</hash-data></info-hash>'

        header = '<header>' \
                     '<method>GetThings</method>' \
                     '<method-version>1</method-version>' \
                     '<record-id>' + self.record_id + '</record-id>' \
                     '<auth-session><auth-token>' + self.auth_token + '</auth-token><user-auth-token>' + self.wctoken + '</user-auth-token></auth-session>' \
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

        response = self.sendRequest(payload)
        if response.status != 200:
            raise HealthVaultException("Non-200 response getting datatype %s: status=%d, msg=%s", (hv_datatype, response.status, response.msg))

        body = response.read()
        root = ET.fromstring(body)

        status = int_or_none(root, 'status/code')
        if status != 0:
            msg = body  # For now, just include the whole thing - FIXME can we get the err message when status != 0?
            raise HealthVaultException("Non-0 status in response: status=%d, msg=%s" % (status, msg))

        info = root.find('{urn:com.microsoft.wc.methods.response.GetThings}info')
        return info


    def getBasicDemographicInfo(self):
        """Gets basic demographic info (v2):
        http://developer.healthvault.com/pages/types/type.aspx?id=3b3e6b16-eb69-483c-8d7e-dfe116ae6092

        :returns: a dictionary - some values might be None if they're not returned by HealthVault.  Example::

            {'city': None, 'country_text': 'United States', 'postcode': '27510', 'country_code': None, 'birthyear': 1963, 'gender': 'm'}

        :raises: HealthVaultException if the request fails in some way.
        """

        info = self.getThings("3b3e6b16-eb69-483c-8d7e-dfe116ae6092")
        return dict(
            birthyear=int_or_none(info, './/birthyear'),
            country_text=text_or_none(info, './/country/text'),
            country_code=text_or_none(info, './/country/code'),
            postcode=text_or_none(info, './/postcode'),
            gender=text_or_none(info, './/gender'),
            city=text_or_none(info, './/city')
        )

    def getWeightMeasurements(self):
        """Get all weight measurements.

        FIXME: restrict by daterange?

        :returns: a list of dictionaries::

            [{'when': datetime.datetime object,
              'kg': weight measured in kilograms,
              'lbs': weight measured in pounds
              },...
             ]

        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings("3d34d87e-7fc1-4153-800f-f56592cb0d17")
        weights = []
        for weight in info.findall('.//weight'):
            weights.append(dict(
                when = when_to_datetime(weight.find("when")),
                kg = int_or_none(weight, 'value/kg'),
                lbs = int_or_none(weight, "value/display[@units='lb']")
            ))
        return weights

    def getDevices(self):
        """Get devices.

        FIXME: finish this

        :returns: a list of dictionaries.  Example::

            {'when': datetime.datetime(2008, 1, 1, 10, 30), 'name': 'Digital Peak Flow Meter'}

        :raises: HealthVaultException if the request fails in some way.
        """
        info = self.getThings("ef9cf8d5-6c0b-4292-997f-4047240bc7be")
        devices = []
        for device in info.findall(".//device"):
            devices.append(dict(
                when = when_to_datetime(device.find("when")),
                name = text_or_none(info, ".//device-name")
            ))
        return devices
