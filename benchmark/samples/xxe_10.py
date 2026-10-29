import xml.etree.ElementTree as ET
def parse_feed(xml_bytes):
    return ET.fromstring(xml_bytes)
