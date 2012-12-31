"""Some utilities for handling XML"""
import StringIO
import datetime
import logging

import xml.etree.ElementTree as ET

from .datatypes import DataType
from healthvaultlib.exceptions import HealthVaultException


logger = logging.getLogger(__name__)


def pretty_xml(xml):
    """Given a string with XML, return a string with the XML formatted pretty"""
    from xml.dom import minidom
    dom = minidom.parseString(xml)
    return dom.toprettyxml()


def elt_to_string(elt):
    """Given an ElementTree element object, return a string with nicely formatted XML"""
    s = elt_as_string(elt)
    # Now s has the XML as one long string, but that's hard to read.
    # This is inefficient, but we only use it when debugging.
    return pretty_xml(s)


def elt_as_string(elt):
    et = ET.ElementTree(elt)
    s = StringIO.StringIO()
    et.write(s)
    s = s.getvalue()
    return s


# Little utils to help pull data out of the XML
def text_list(elt, xpath):
    """Return a list of the text values from the xpath (using findall)"""
    return [e.text for e in elt.findall(xpath)]


def text_or_none(element, xpath):
    """If element.find(xpath) returns an element, return the .text from it;
    otherwise, return None"""
    elt = element.find(xpath)
    return elt.text if elt is not None else None


def int_or_none(element, xpath):
    """Like text_or_none but takes int() of the result"""
    elt = element.find(xpath)
    return int(elt.text) if elt is not None else None


def float_or_none(element, xpath):
    """Like text_or_none but takes float() of the result"""
    elt = element.find(xpath)
    return float(elt.text) if elt is not None else None


def boolean_or_none(element, xpath):
    """Like text_or_none but takes bool() of the result"""
    text = text_or_none(element, xpath)
    if text:
        return text.lower() == 'true'
    return None


def parse_optional_item(elt, path, parser):
    """If elt.find(path) returns an item, apply parser to it and return the result.
    Else, return None.
    """
    item = elt.find(path)
    if item is not None:
        item = parser(item)
    return item


# Put datetime in better pythonic data structure
def when_to_datetime(when):
    """Some of the API call responses represent a date as an incredibly stupid XML structure:

    <when><date><y>1990</y><m>5</m>...

    Given the <when> element as an ElementTree element,
    returns a Python datetime object.
    """
    paths = ['date/y', 'date/m', 'date/d',
             'time/h', 'time/m', 'time/s']
    elts = [when.find(path) for path in paths]
    texts = []
    for elt in elts:
        if elt is None:
            texts.append("0")
        else:
            texts.append(elt.text)
    #texts = [elt.text for elt in elts if elt is not None else "0"]
    ints = [int(t) for t in texts]
    return datetime.datetime(*ints)
    #return datetime.datetime(*[int(when.find(path).text) for path in paths])


# Parse specific MS HealthVault XML types and return dictionaries
def parse_approximate_date(elt):
    """
    urn:com.microsoft.wc.dates:approx-date
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.dates.approx-date.1.html

    :returns: a datetime.date object
    """
    paths = ['y', 'm', 'd']
    elts = [elt.find(path) for path in paths]
    texts = []
    for elt in elts:
        if elt is None:
            texts.append("0")
        else:
            texts.append(elt.text)
    ints = [int(t) for t in texts]
    return datetime.date(*ints)


def parse_person(elt):
    """Parse a person type response element into nested dictionaries

    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.person.1.html
    """
    return dict(
        name = elt.find('name').text,
        organization = text_or_none(elt, 'organization'),
        professional_training = text_or_none(elt, 'professional-training'),
        id = text_or_none(elt, 'id'),
        contact = parse_optional_item(elt, 'contact', parse_contact),
        type = parse_optional_item(elt, 'type', parse_codable_value),
    )


def parse_name(elt):
    """Given an ElementTree element of type urn:com.microsoft.wc.thing.types:name
    (http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.name.1.html),
    return a dictionary representing the same data.
    """
    return dict(
        full = elt.find('full').text,  # http://www.w3.org/2001/XMLSchema:string
        title=parse_optional_item(elt, 'title', parse_codable_value),
        first=text_or_none(elt, 'first'),
        middle=text_or_none(elt, 'middle'),
        last=text_or_none(elt, 'last'),
        suffix=parse_optional_item(elt, 'suffix', parse_codable_value),
    )


def parse_codable_value(elt):
    """Given an ElementTree element of type  urn:com.microsoft.wc.thing.types:codable-value
    (http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.codable-value.1.html),
    return a dictionary representing the same data.
    """
    return dict(
        text = text_or_none(elt, 'text'),
        code = [parse_coded_value(e) for e in elt.findall('code')],
    )


def parse_coded_value(elt):
    """
    urn:com.microsoft.wc.thing.types:coded-value
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.coded-value.1.html
    """
    return dict(
        value = text_or_none(elt, 'value'),
        family = text_list(elt, 'family'),
        type = text_or_none(elt, 'type'),
        version = text_list(elt, 'version')
    )


def parse_device(elt):
    """
    urn:com.microsoft.wc.thing.equipment:device
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.equipment.device.1.inlinetype.html
    """
    return dict(
        when=when_to_datetime(elt.find('when')),
        device_name=text_or_none(elt, 'device-name'),
        vendor = parse_optional_item(elt, 'vendor', parse_person),
        model=text_or_none(elt, 'model'),
        serial_number=text_or_none(elt, 'serial-number'),
        description=text_or_none(elt, 'description'),
    )


def parse_contact(elt):
    """
    urn:com.microsoft.wc.thing.types:contact
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.contact.1.html
    """
    # All three parts can occur any number of times
    return dict(
        address = [parse_address(e) for e in elt.findall('address')],
        phone = [parse_phone(e) for e in elt.findall('phone')],
        email = [parse_email(e) for e in elt.findall('email')],
    )


def parse_address(elt):
    """
    urn:com.microsoft.wc.thing.types:address
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.address.1.html
    """
    return dict(
        description = text_or_none(elt, 'description'),
        is_primary = boolean_or_none(elt, 'is-primary'),
        street = text_list(elt, 'street'),
        city = text_or_none(elt, 'city'),
        state = text_or_none(elt, 'state'),
        postcode = text_or_none(elt, 'postcode'),
        country = text_or_none(elt, 'country'),
    )


def parse_phone(elt):
    """
    urn:com.microsoft.wc.thing.types:phone
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.phone.1.html
    """
    return dict(
        description=text_or_none(elt, 'description'),
        is_primary=boolean_or_none(elt, 'is-primary'),
        number=text_list(elt, 'number'),
    )


def parse_email(elt):
    """
    urn:com.microsoft.wc.thing.types:email
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.email.1.html
    """
    return dict(
        description=text_or_none(elt, 'description'),
        is_primary=boolean_or_none(elt, 'is-primary'),
        address=elt.find('address').text,
    )


def parse_weight(elt):
    """
    Parse a weight measurement
    urn.com.microsoft.wc.thing.weight.weight.1.inlinetype
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.weight.weight.1.inlinetype.html

    # Just assuming pounds as the alternate display value, rather than
    # trying to reproduce the convoluted XML data structure
    """
    return dict(
        when=when_to_datetime(elt.find('when')),
        kg=float_or_none(elt, 'value/kg'),
        lbs=float_or_none(elt, "value/display[@units='lb']"),
    )


def parse_exercise(elt):
    """
    Parse an exercise entry
    urn.com.microsoft.wc.thing.exercise.exercise.2.inlinetype
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.exercise.exercise.2.inlinetype.html
    """

    return dict(
        when=parse_structured_approximate_date_time(elt.find('when')),
        activity=parse_codable_value(elt.find('activity')),
        title=text_or_none(elt, 'title'),
        distance=parse_optional_item(elt, 'distance', parse_length_value),
        duration=parse_optional_item(elt, 'duration', parse_positive_double),
        detail=[parse_structured_name_value(e) for e in elt.findall('detail')],
        segment=[parse_exercise_segment(e) for e in elt.findall('segment')],
    )


def parse_structured_approximate_date_time(elt):
    """
    urn:com.microsoft.wc.dates:approx-date-time
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.dates.approx-date-time.1.html
    """
    return dict(
        structured=parse_structured_approximate_date(elt.find('structured')),
        descriptive=text_or_none(elt, 'descriptive'),
    )


def parse_structured_approximate_date(elt):
    """
    urn:com.microsoft.wc.dates:StructuredApproxDate
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.dates.StructuredApproxDate.1.html
    """
    return dict(
        date=parse_approximate_date(elt.find('date')),
        time=parse_optional_item(elt, 'time', parse_time),
        tz=parse_optional_item(elt, 'tz', parse_codable_value),
    )


def parse_time(elt):
    """
    urn:com.microsoft.wc.dates:time
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.dates.time.1.html

    :returns: datetime.time object
    """
    h = int_or_none(elt, 'h')
    m = int_or_none(elt, 'm')
    s = int_or_none(elt, 's') or 0
    milliseconds = int_or_none(elt, 'f') or 0
    return datetime.time(h, m, s, microsecond=1000 * milliseconds)


def parse_exercise_segment(elt):
    """
    urn:com.microsoft.wc.thing.exercise:ExerciseSegment
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.exercise.ExerciseSegment.2.html
    """
    return dict(
        activity=parse_codable_value(elt.find('activity')),
        title=text_or_none(elt, 'title'),
        distance=parse_optional_item(elt, 'distance', parse_length_value),
        duration=float_or_none(elt, 'duration'),
        offset=float_or_none(elt, 'offset'),
        detail=[parse_structured_name_value(e) for e in elt.findall('detail')],
    )


def parse_structured_name_value(elt):
    """
    urn:com.microsoft.wc.thing.exercise:StructuredNameValue
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.exercise.StructuredNameValue.2.html
    """
    return dict(
        name=parse_coded_value(elt.find('name')),
        value=parse_structured_measurement(elt.find('value')),
    )


def parse_structured_measurement(elt):
    """
    urn:com.microsoft.wc.thing.types:structured-measurement
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.structured-measurement.1.html
    """
    return dict(
        value=float_or_none(elt, 'value'),
        units=parse_optional_item(elt, 'units', parse_codable_value),
    )


def parse_length_value(elt):
    """
    urn:com.microsoft.wc.thing.types:length-value
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.length-value.1.html
    """
    return dict(
        m=parse_positive_double(elt.find('m')),
        display=parse_optional_item(elt, 'display', parse_display_value),
    )


def parse_positive_double(elt):
    """
    urn:com.microsoft.wc.thing.types:positiveDouble
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.positiveDouble.1.html
    """
    return float(elt.text)


def parse_display_value(elt):
    """
    urn:com.microsoft.wc.thing.types:display-value
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.types.display-value.1.html

    E.g.::

        <display text="10 ft 1.5 in" units="in" units-code="in">121.5</display>

    """
    return dict(
        text=elt.get('text'),
        units=elt.get('units'),
        units_code=elt.get('units-code'),
        display=elt.text,
    )


def parse_height(elt):
    """
    urn:com.microsoft.wc.thing.height:height
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.height.height.1.inlinetype.html
    """
    return dict(
        when=when_to_datetime(elt.find('when')),
        value=parse_length_value(elt.find('value')),
    )


def parse_sleep_session(elt):
    """
    urn:com.microsoft.wc.thing.sjam:sleep-am
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.sjam.sleep-am.1.inlinetype.html
    """
    return dict(
        when=when_to_datetime(elt.find('when')),
        bed_time=parse_time(elt.find('bed-time')),
        wake_time=parse_time(elt.find('wake-time')),
        sleep_minutes=int_or_none(elt, 'sleep-minutes'),
        settling_minutes=int_or_none(elt, 'setting-minutes'),
        awakening=[parse_awakening(a) for a in elt.findall('awakening')],
        medications=[parse_codable_value(m) for m in elt.findall('medications')],
    )


def parse_awakening(elt):
    """
    urn:com.microsoft.wc.thing.sjam:Awakening
    http://developer.healthvault.com/sdk/docs/urn.com.microsoft.wc.thing.sjam.Awakening.1.html
    """
    return dict(
        when=parse_time(elt.find('when')),
        minutes=int_or_none(elt, 'minutes'),
    )


def parse_subscription(elt):
    """
    https://platform.healthvault-ppe.com/platform/XSD/subscription.xsd
    """
    return dict(
        common=parse_subscription_common(elt.find('common')),
        record_item_changed_event=parse_record_item_changed_event(elt.find('record-item-changed-event')),
    )


def parse_subscription_common(elt):
    return dict(
        id=text_or_none(elt, 'id'),
        notification_authentication_info=parse_notification_authentication_info(elt.find('notification-authentication-info')),
        notification_channel=parse_notification_channel(elt.find('notification-channel')),
    )


def parse_notification_authentication_info(elt):
    return dict(
        hv_eventing_shared_key=parse_hv_eventing_shared_key(elt.find('hv-eventing-shared-key')),
    )


def parse_hv_eventing_shared_key(elt):
    return dict(
        notification_key=text_or_none(elt, 'notification-key'),
        notification_key_version_id=text_or_none(elt, 'notification-key-version-id'),
    )


def parse_notification_channel(elt):
    return dict(
        http_notification_channel=parse_optional_item(elt, 'http-notification-channel', parse_http_notification_channel),
    )


def parse_http_notification_channel(elt):
    return dict(
        url=text_or_none(elt, 'url'),
    )


def parse_record_item_changed_event(elt):
    return dict(
        filters=[parse_record_item_changed_event_filter(f) for f in elt.findall('filters/filter')]
    )


def parse_record_item_changed_event_filter(elt):
    type_ids = elt.find('type-ids')
    return dict(
        type_ids=[item.text for item in type_ids.findall('type-id')]
    )


def parse_notification(elt):
    return dict(
        common=parse_notification_common(elt.find('common')),
        record_change_notification=parse_optional_item(elt, 'record-change-notification', parse_record_change_notification),
    )


def parse_notification_common(elt):
    return dict(
        subscription_id=text_or_none(elt, 'subscription-id'),
    )


def parse_record_change_notification(elt):
    return dict(
        person_id=text_or_none(elt, 'person-id'),
        record_id=text_or_none(elt, 'record-id'),
        things=[parse_notification_thing(t) for t in elt.findall('things/thing')],
    )


def parse_notification_thing(elt):
    return text_or_none(elt, 'thing-id')


def parse_blood_glucose(elt):
    # http://developer.healthvault.com/pages/types/type.aspx?id=879e7c04-4e8a-4707-9ad3-b054df467ce4

    """
     <blood-glucose>
  <when>
    <date>
      <y>2006</y>
      <m>1</m>
      <d>1</d>
    </date>
    <time>
      <h>9</h>
      <m>30</m>
      <s>0</s>
      <f>0</f>
    </time>
  </when>
  <value>
    <mmolPerL>7.444444</mmolPerL>
    <display units="mmolPerL">7.444444</display>
  </value>
  <glucose-measurement-type>
    <text>Whole blood</text>
    <code>
      <value>wb</value>
      <family>wc</family>
      <type>glucose-measurement-type</type>
      <version>1</version>
    </code>
  </glucose-measurement-type>
  <outside-operating-temp>true</outside-operating-temp>
  <is-control-test>true</is-control-test>
  <normalcy>1</normalcy>
  <measurement-context>
    <text>Before meal</text>
    <code>
      <value>BeforeMeal</value>
      <family>wc</family>
      <type>glucose-measurement-context</type>
      <version>1</version>
    </code>
  </measurement-context>
</blood-glucose>
    """
    return dict(
        when=when_to_datetime(elt.find('when')),
        value=parse_blood_glucose_value(elt.find('value')),
        glucose_measurement_type=parse_codable_value(elt.find('glucose-measurement-type')),
        outside_operating_temperature=boolean_or_none(elt, 'outside-operating_temp'),
        is_control_test=boolean_or_none(elt, 'is-control-test'),
        normalcy=int_or_none(elt, 'normalcy'),
        measurement_context=parse_optional_item(elt, 'measurement-context', parse_codable_value),
    )


def parse_blood_glucose_value(elt):
    # http://developer.healthvault.com/pages/types/type.aspx?id=3e730686-781f-4616-aa0d-817bba8eb141#blood-glucose-value
    return dict(
        mmolperl=parse_positive_double(elt.find('mmolPerL')),
        display=parse_optional_item(elt, 'display', parse_display_value)
    )


def parse_connect_request(elt):
    # https://platform.healthvault-ppe.com/platform/XSD/response-getauthorizedconnectrequests.xsd
    return dict(
        person_id=text_or_none(elt, 'person-id'),
        app_specific_record_id=text_or_none('record-id/app-specific-record-id'),
        app_id=text_or_none(elt, 'app-id'),
        external_id=text_or_none(elt, 'external-id'),
    )


def parse_group(group):
    """Given an element that contains a <group>...</group>
    return whatever parsing that group as a response to the specific API
    would have returned.

    :param elementtree group: A `group` element.  Its type is inferred
    from the <thing><type-id>xxxxxxxx</type-id></thing> value.
    """

    if not len(group.findall('thing')):
        # No results
        return []

    data_type = group.find('thing/type-id').text

    # FIXME: should we replace all these if/elif clauses with a table-driven implementation?
    if data_type == DataType.BASIC_DEMOGRAPHIC_DATA:
        basic = group.find('thing/data-xml/basic')
        return dict(
            gender=text_or_none(basic, 'gender'),
            birthyear=int_or_none(basic, 'birthyear'),
            country_text=text_or_none(basic, 'country/text'),
            country_code=text_or_none(basic, 'country/code/value'),
            postcode=text_or_none(basic, 'postcode'),
            state=text_or_none(basic,'state/text')
        )
    elif data_type == DataType.BLOOD_GLUCOSE_MEASUREMENT:
        return [parse_blood_glucose(item) for item in group.findall('thing/data-xml/blood-glucose')]
    elif data_type == DataType.BLOOD_PRESSURE_MEASUREMENTS:
        things = []
        for thing in group.findall('thing/data-xml/blood-pressure'):
            things.append(dict(
                when = when_to_datetime(thing.find("when")),
                systolic = int_or_none(thing, 'systolic'),
                diastolic = int_or_none(thing, 'diastolic'),
                pulse = int_or_none(thing, 'pulse'),
                irregular_heartbeat = boolean_or_none(thing, 'irregular-heartbeat'),
            ))
        return things
    elif data_type == DataType.DEVICES:
        return [parse_device(e) for e in group.findall('thing/data-xml/device')]
    elif data_type == DataType.EXERCISE:
        return [parse_exercise(e) for e in group.findall('thing/data-xml/exercise')]
    elif data_type == DataType.HEIGHT_MEASUREMENTS:
        return [parse_height(e) for e in group.findall('thing/data-xml/height')]
    elif data_type == DataType.SLEEP_SESSIONS:
        return [parse_sleep_session(s) for s in group.findall('thing/data-xml/sleep-am')]
    elif data_type == DataType.WEIGHT_MEASUREMENTS:
        return [parse_weight(e) for e in group.findall('thing/data-xml/weight')]
    else:
        # import here to avoid circular imports
        raise HealthVaultException("Unknown data type in group response: name='%s'" % data_type)
