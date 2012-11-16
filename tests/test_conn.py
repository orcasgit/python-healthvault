"""Tests for HealthVaultConn"""

import datetime
from unittest import TestCase
import xml.etree.ElementTree as ET

import mock

from healthvaultlib.healthvault import HealthVaultConn
from healthvaultlib.xmlutils import elt_to_string


TEST_PUBLIC_KEY = long("b81c20fc71cc63324ccb3860c8a092c464f9e54cbe6f228fb79d0a9b2e303c3b233989b4a45fa1b8595b42791beed"
                      "20c005e973ee7dcb657e735f3399d259dd25d63ac3669040dbf06030e009dfa815d1957cd0e89474d0d8addbfe435"
                      "4df1f72b37592aa49686d8d7d1d0246017ec8763b917508a05c880bff23cfaffd74290dfbe7d5b94e61bb8cb4df86"
                      "883306e6eb4d884feb70c66b2e3925ad86ebcbaee2517d24466ead5c13488dc339723f286b800e255a32ef69f69a2"
                      "f25c1e3bde49da00a6473d2b256b156fc52ffe597e56017dd49be697083c861ceb43ebf4927fe08165020df6690c3"
                      "4bcd8e4bacf1344b72cf42ec744407fb9f44c8c16ef9f77", 16)
TEST_PRIVATE_KEY = long("4f2e79d958b008b1a7697773d89586c9c48bdd5c6642b1e0919d8ee432b738104f13fdef9d0a2c2976f4d2dff76d"
                       "7d15004bae4cb5b7ad0c9d3a0cc3689cb705b4789ba64300255154aa97a9184896be8d99bf6d5309415063baff3e"
                       "8cd65b0c6c9fbf4fa1bdc37d1b44f779cd823c8df60bb2c546b73a0675871f46ec258e50b9232f2d4a782b67f9c7"
                       "5590e1bea4eb483286317b72cf11ee1df5bf56d8afef68b2504991cb3fd907f575b6f809f33e45be992598ccb475"
                       "ffd0a020e46d053233eccb07422813c9e50643b6b547fca8941a919b6c2f7e717115110a6fb51b9012f64ff69c78"
                       "88fbe3ecde8c277dec1c147b115ff5400af6146dded23419f191", 16)


class ConnTests(TestCase):
    def test_very_simple(self):
        # construct a conn, mocking all the real work
        with mock.patch.object(HealthVaultConn, '_get_auth_token') as gat:
            with mock.patch.object(HealthVaultConn, '_get_record_id') as gri:
                gri.return_value = 8, 9
                c = HealthVaultConn(
                        app_id="1", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                        wctoken="5", server="6", shell_server="7"
                    )
        self.assertEqual("1", c.app_id)
        self.assertEqual("2", c.app_thumbprint)
        self.assertEqual(TEST_PUBLIC_KEY, c.public_key)
        self.assertEqual(TEST_PRIVATE_KEY, c.private_key)
        self.assertEqual("5", c.wctoken)
        self.assertEqual("6", c.server)
        self.assertEqual("7", c.shell_server)
        self.assertEqual(8, c.record_id)
        self.assertEqual(9, c.person_id)
        # We passed in a wctoken, make sure the methods got called that set up things with HealthVault
        gat.assert_any_call()
        gri.assert_any_call()

    def test_connect(self):
        # If we build a conn without a wctoken, it doesn't do the connect
        # though it does get a session token
        # then we can call connect with a wctoken and it'll do it then
        with mock.patch.object(HealthVaultConn, '_get_auth_token') as gat:
            with mock.patch.object(HealthVaultConn, '_get_record_id') as gri:
                gri.return_value = 1, 2
                c = HealthVaultConn(
                        app_id="1", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                        wctoken=None, server="6", shell_server="7"
                    )
        self.assertIsNone(c.wctoken)
        self.assertFalse(c.is_authorized())
        gat.assert_any_call()
        self.assertFalse(gri.called)
        self.assertIsNotNone(c.auth_token)
        with mock.patch.object(HealthVaultConn, '_get_auth_token') as gat:
            with mock.patch.object(HealthVaultConn, '_get_record_id') as gri:
                gri.return_value = 8, 9
                c.connect(wctoken="5")
        self.assertEqual("5", c.wctoken)
        gri.assert_any_call()
        self.assertTrue(c.is_authorized())

    def test_is_authorized(self):
        with mock.patch.object(HealthVaultConn, '_get_auth_token'):
            c = HealthVaultConn(
                    app_id="1", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                    wctoken=None, server="6", shell_server="7"
                )
        self.assertFalse(c.is_authorized())
        c.authorized = True
        self.assertTrue(c.is_authorized())

    def test_authorization_url(self):
        with mock.patch.object(HealthVaultConn, '_get_auth_token'):
            c = HealthVaultConn(
                    app_id="123", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                    wctoken=None, server="6", shell_server="shell.server"
                )
        url = c.authorization_url("http://ourown.server.com/with/some/parts/")
#        print repr(url)
        self.assertEqual(
            'https://shell.server/redirect.aspx?targetqs=redirect%3Dhttp%253A%252F%252Fourown.server.com%252'
            'Fwith%252Fsome%252Fparts%252F%26appid%3D123&target=APPAUTH',
            url)

    def test_build_and_send_request(self):
        # construct a conn, mocking all the real work
        AUTH_TOKEN = "AUTHKEY"
        WC_TOKEN = "WCKEY"
        with mock.patch.object(HealthVaultConn, '_get_auth_token') as gat:
            with mock.patch.object(HealthVaultConn, '_get_record_id') as gri:
                gat.return_value = AUTH_TOKEN
                gri.return_value = "8", "9"
                c = HealthVaultConn(
                        app_id="1", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                        wctoken=WC_TOKEN, server="6", shell_server="7"
                    )
        with mock.patch.object(c, '_send_request') as sendRequest:
            c._build_and_send_request(method_name="METHOD", info="<info>BOO</info>")
        payload = sendRequest.call_args[0][0]
        request = ET.fromstring(payload)
#        print elt_to_string(request)
        header = request.find('header')
        method_name = header.find('method').text
        self.assertEqual("METHOD", method_name)
        self.assertEqual("1", header.find('method-version').text)
        self.assertEqual("8", header.find('record-id').text)
        self.assertEqual(AUTH_TOKEN, header.find('auth-session/auth-token').text)
        self.assertEqual(WC_TOKEN, header.find('auth-session/user-auth-token').text)
        self.assertEqual("BOO", request.find('info').text)


    def verify_get_data_api(self, xml, expected, methodname):
        """Given one of the methods that gets some XML from HealthVault and returns a dictionary or list,
        verify it returns what we expect

        :param xml: The XML that get_things will return to the method under test
        :param expected: The expected return value of the method under test
        :param methodname: The name of the method under test
        """
        # construct a conn, mocking all the real work
        with mock.patch.object(HealthVaultConn, '_get_auth_token') as gat:
            with mock.patch.object(HealthVaultConn, '_get_record_id') as gri:
                gri.return_value = 1, 2
                c = HealthVaultConn(
                        app_id="1", app_thumbprint="2", public_key=TEST_PUBLIC_KEY, private_key=TEST_PRIVATE_KEY,
                        wctoken="5", server="6", shell_server="7"
                    )
        # call get_basic_demographic_info(), mocking the actual network call
        with mock.patch.object(HealthVaultConn, 'get_things') as getThings:
            getThings.return_value = ET.fromstring(xml)
            retval = getattr(c, methodname)()
#        print retval
        self.assertEqual(expected, retval)

    def test_basic_demographic_info(self):
        test_body = '<wc:info xmlns:wc="urn:com.microsoft.wc.methods.response.GetThings">'\
                    '<group><thing><thing-id version-stamp="fb48f28c-7501-4149-9e65-6646be3c5ae5">' \
                    '33255494-be86-407d-a414-078b63cf94d2</thing-id><type-id name="Basic Demographic Information">' \
                    '3b3e6b16-eb69-483c-8d7e-dfe116ae6092</type-id><thing-state>Active</thing-state><flags>0</flags>' \
                    '<eff-date>2012-11-08T13:02:38.649</eff-date><data-xml>'\
                    '<basic><gender>m</gender><birthyear>1963</birthyear><country><text>United States</text><code>' \
                    '<value>US</value><family>iso</family><type>iso3166</type></code></country><postcode>27510' \
                    '</postcode><state><text>NC</text></state></basic><common /></data-xml></thing></group></wc:info>'
        expected_value = {'birthyear': 1963, 'state': 'NC', 'country_text': 'United States', 'postcode': '27510',
                          'country_code': 'US', 'gender': 'm'}
        self.verify_get_data_api(test_body, expected_value, 'get_basic_demographic_info')

    def test_blood_pressure_measurements(self):
        test_body = '<wc:info xmlns:wc="urn:com.microsoft.wc.methods.response.GetThings">' \
                    '<group><thing><thing-id version-stamp="42098c7d-1540-4434-83d2-5f834d36b7eb">fa32e696-ef4c-434d-ba94-a9ece88dac00' \
                    '</thing-id><type-id name="Blood Pressure Measurement">ca3c57f4-f4c1-4e15-be67-0a3caf5414ed</type-id>' \
                    '<thing-state>Active</thing-state><flags>0</flags><eff-date>2012-11-12T11:24:00</eff-date><data-xml>' \
                    '<blood-pressure><when><date><y>2012</y><m>11</m><d>12</d></date><time><h>11</h><m>24</m><s>0</s></time></when>' \
                    '<systolic>160</systolic><diastolic>80</diastolic><pulse>16</pulse></blood-pressure><common />' \
                    '</data-xml></thing></group></wc:info>'
        expected_value = [{'systolic': 160, 'when': datetime.datetime(2012, 11, 12, 11, 24),
                           'irregular_heartbeat': None, 'pulse': 16, 'diastolic': 80}]
        self.verify_get_data_api(test_body, expected_value, 'get_blood_pressure_measurements')

    def test_devices(self):
        test_body = '<wc:info xmlns:wc="urn:com.microsoft.wc.methods.response.GetThings">' \
                    '<group><thing><thing-id version-stamp="e5d2a162-bde8-45a2-815a-54736a98ee64">70fd1e73-4330-4a05-8f82-4a0300976498' \
                    '</thing-id><type-id name="Device">ef9cf8d5-6c0b-4292-997f-4047240bc7be</type-id>' \
                    '<thing-state>Active</thing-state><flags>0</flags><eff-date>2008-01-01T10:30:00</eff-date>' \
                    '<data-xml><device><when><date><y>2008</y><m>1</m><d>1</d></date>' \
                    '<time><h>10</h><m>30</m><s>0</s><f>0</f></time></when><device-name>Digital Peak Flow Meter</device-name>' \
                    '<vendor><name><full>Mark Boyce</full><title><text>Mr</text><code><value>Mr</value>' \
                    '<family>wc</family><type>name-prefixes</type><version>1</version></code></title><first>Mark</first>' \
                    '<middle /><last>Boyce</last><suffix><text>Junior</text><code><value>Jr</value><family>wc</family>' \
                    '<type>name-suffixes</type><version>1</version></code></suffix></name><organization>Microlife</organization>' \
                    '<professional-training>A2Z Testing</professional-training><id>3456789</id><contact><address>' \
                    '<description>12345 Apt#234</description><is-primary>true</is-primary><street>NE 34th St</street>' \
                    '<city>Redmond</city><state>WA</state><postcode>98052</postcode><country>US</country></address>' \
                    '<phone><description>Office</description><is-primary>true</is-primary><number>2069053456</number></phone>' \
                    '<email><description>Office</description><is-primary>true</is-primary>' \
                    '<address>markbo@live.com</address></email></contact><type><text>Provider</text><code><value>2</value>' \
                    '<family>wc</family><type>person-types</type><version>1</version></code></type></vendor>' \
                    '<model>PF100</model><serial-number>23456543</serial-number><anatomic-site>Lungs</anatomic-site>' \
                    '<description>Mark Boyce got a Peak flow meter</description></device><common /></data-xml></thing>' \
                    '</group></wc:info>'
        expected_value = [{'vendor': {'contact': {'phone': [{'is_primary': True, 'number': ['2069053456'],
                                                             'description': 'Office'}],
                                                  'email': [{'is_primary': True, 'description': 'Office',
                                                             'address': 'markbo@live.com'}],
                                                  'address': [{'city': 'Redmond', 'state': 'WA',
                                                               'street': ['NE 34th St'],
                                                               'description': '12345 Apt#234', 'country': 'US',
                                                               'is_primary': True, 'postcode': '98052'}]},
                                      'name': None, 'organization': 'Microlife',
                                      'type': {'text': 'Provider', 'code': [{'version': ['1'],
                                                                             'type': 'person-types', 'family': ['wc'],
                                                                             'value': '2'}]},
                                      'id': '3456789', 'professional_training': 'A2Z Testing'},
                           'description': 'Mark Boyce got a Peak flow meter', 'serial_number': '23456543',
                           'model': 'PF100', 'when': datetime.datetime(2008, 1, 1, 10, 30),
                           'device_name': 'Digital Peak Flow Meter'}]
        self.verify_get_data_api(test_body, expected_value, 'get_devices')

    def test_exercise(self):
        test_body = '<wc:info xmlns:wc="urn:com.microsoft.wc.methods.response.GetThings">' \
                    '<group><thing><thing-id version-stamp="0987e889-8b8e-4806-af77-ecb355f8cd74">dcb98b1e-60bd-485c-b0f0-de82bc161143' \
                    '</thing-id><type-id name="Exercise">85a21ddb-db20-4c65-8d30-33c899ccf612</type-id>' \
                    '<thing-state>Active</thing-state><flags>0</flags><eff-date>2012-11-12T03:03:00</eff-date>' \
                    '<data-xml><exercise><when><structured><date><y>2012</y><m>11</m><d>12</d></date>' \
                    '<time><h>3</h><m>3</m></time></structured></when><activity><text>Jumping to conclusions</text>' \
                    '</activity><title>Did something</title><distance><m>1609.344</m><display units="mi" units-code="mi">1</display>' \
                    '</distance><duration>10</duration><detail><name><value>Steps_count</value><family>wc</family>' \
                    '<type>exercise-detail-names</type></name><value><value>5280</value><units><text>Count</text>' \
                    '<code><value>Count</value><family>wc</family><type>exercise-units</type>' \
                    '<version>1</version></code></units></value></detail></exercise><common />' \
                    '</data-xml></thing></group></wc:info>'
        expected_value = [{'distance': {'m': 1609.344, 'display': {'units': 'mi', 'text': None, 'display': '1',
                                                                   'units_code': 'mi'}},
                           'title': 'Did something', 'duration': 10.0, 'segment': [],
                           'activity': {'text': 'Jumping to conclusions', 'code': []},
                           'when': {'structured': {'date': datetime.date(2012, 11, 12), 'tz': None,
                                                   'time': datetime.time(3, 3)}, 'descriptive': None},
                           'detail': [{'name': {'version': [], 'type': 'exercise-detail-names', 'family': ['wc'],
                                                'value': 'Steps_count'},
                                       'value': {'units': {'text': 'Count', 'code': [{'version': ['1'],
                                                                                      'type': 'exercise-units',
                                                                                      'family': ['wc'],
                                                                                      'value': 'Count'}]},
                                                 'value': 5280.0}}]}]
        self.verify_get_data_api(test_body, expected_value, 'get_exercise')

    def test_weights(self):
        test_body = '<wc:info xmlns:wc="urn:com.microsoft.wc.methods.response.GetThings">' \
                    '<group><thing><thing-id version-stamp="50b1d853-c990-407d-bd93-3cc7563d9171">10993223-00c5-45bb-b615-ef9feda9410d' \
                    '</thing-id><type-id name="Weight Measurement">3d34d87e-7fc1-4153-800f-f56592cb0d17</type-id>' \
                    '<thing-state>Active</thing-state><flags>0</flags><eff-date>2012-11-12T11:24:00</eff-date>' \
                    '<data-xml><weight><when><date><y>2012</y><m>11</m><d>12</d></date>' \
                    '<time><h>11</h><m>24</m></time></when><value><kg>11.954880503984493</kg>' \
                    '<display units="lbs" units-code="lb">26.355999999999998</display></value></weight><common />' \
                    '</data-xml></thing></group></wc:info>'
        expected_value = [{'kg': 11.954880503984493, 'lbs': None, 'when': datetime.datetime(2012, 11, 12, 11, 24)}]
        self.verify_get_data_api(test_body, expected_value, 'get_weight_measurements')
