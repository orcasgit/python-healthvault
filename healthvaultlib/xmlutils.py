"""Some utilities for handling XML"""
import datetime

def get_text_value(node, name):
    """Given a node, find the first element inside it with the given name,
    and return the enclosed text.

    E.g. if the node passed in was::

        &lt;node>&lt;subnode>
            &lt;element>FOO&lt;/element>
        &lt;/subnode>&lt;/node>

    and the name was "element", it would return "FOO".
    """
    for thing in node.getElementsByTagName(name):
        return thing.firstChild.nodeValue

def xml_to_dictionary(node):
    """Given an XML node, returns a dictionary representing the same data.
    E.g.::

        &lt;thing>
            &lt;subthing>
                &lt;bit>1&lt;/bit>
                &lt;bat>for&lt;/bat>
            &lt;/subthing>
            &lt;subthing>
                &lt;other>one&lt;/other>
            &lt;/subthing>
        &lt;/thing>

    it returns::

        {'thing': [
            {'subthing': [
                {'bit': 1

    """

    # Our dictionary contains one key, the name of the top node we were given
    topkey = node.nodeName
    # Assume that the node contains EITHER children OR a text value, not both
    if node.childNodes:
        if node.childNodes.length == 1 and node.firstChild.nodeType == node.TEXT_NODE:
            return {topkey: node.firstChild.nodeValue}
        else:
            # The value is a list of the xml_to_dictionary() results for each child node
            return {topkey: [xml_to_dictionary(child) for child in node.childNodes]}
    else:
        # no children, not much of anything to say...
        return {topkey: None}

def xml_to_tuple(node):
    topkey = node.nodeName
    # Assume that the node contains EITHER children OR a text value, not both
    if node.childNodes:
        if node.childNodes.length == 1 and node.firstChild.nodeType == node.TEXT_NODE:
            return (topkey, node.firstChild.nodeValue)
        else:
            # The value is a list of the xml_to_dictionary() results for each child node
            return (topkey, [xml_to_tuple(child) for child in node.childNodes])
    else:
        # no children, not much of anything to say...
        return (topkey, None)


def when_to_datetime(when):
    """Some of the API call responses represent a date as an incredibly stupid XML structure:

    <when><date><y>1990</y><m>5</m>...

    Given the <when> element as an ElementTree element,
    returns a Python datetime object.
    """
    paths = ['./date/y', './date/m', './date/d',
             './time/h', './time/m', './time/s']
    return datetime.datetime(*[int(when.find(path).text) for path in paths])

def text_or_none(element, xpath):
    """If element.find(xpath) returns an element, return the .text from it;
    otherwise, return None"""
    elt = element.find(xpath)
    return elt.text if elt is not None else None

def int_or_none(element, xpath):
    """Like text_or_none but takes int() of the result"""
    elt = element.find(xpath)
    return int(elt.text) if elt is not None else None

if __name__ == '__main__':
    from xml.dom import minidom
    xml = """<thing><subthing><bit>1</bit><bat>for</bat></subthing><subthing><other>one</other></subthing></thing>"""
    dom = minidom.parseString(xml)
    thing = dom.firstChild
    print xml_to_dictionary(thing)
    print xml_to_tuple(thing)
