"""The one place XML is parsed.

Every module that reads XML must call parse_xml(). Untrusted SAML is a
classic XXE and entity-expansion target, so parsing happens in two layers:

1. defusedxml rejects any DTD, entity declaration or external reference
   before lxml sees the document. A SAML message never needs a DTD.
2. lxml then parses with entity resolution, DTD loading and network access
   switched off. lxml is still needed because signature verification needs
   its C14N support.

Comments are kept on purpose: removing them would change the canonical form
and hide comment-injection tricks inside NameID values.
"""

import defusedxml
import defusedxml.ElementTree
from lxml import etree

MAX_XML_BYTES = 5 * 1024 * 1024


class XMLRejected(ValueError):
    """The document was refused for safety reasons or is not well-formed."""


def _lxml_parser():
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
    )


def parse_xml(data):
    """Parse untrusted XML bytes (or str) and return the lxml root element."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_XML_BYTES:
        raise XMLRejected(f"XML is larger than {MAX_XML_BYTES} bytes")
    try:
        defusedxml.ElementTree.fromstring(
            data, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except defusedxml.DTDForbidden:
        raise XMLRejected("XML contains a DOCTYPE; SAML messages never need one") from None
    except (defusedxml.EntitiesForbidden, defusedxml.ExternalReferenceForbidden):
        raise XMLRejected("XML declares entities or external references") from None
    except defusedxml.ElementTree.ParseError as exc:
        raise XMLRejected(f"XML is not well-formed: {exc}") from None
    try:
        root = etree.fromstring(data, parser=_lxml_parser())
    except etree.XMLSyntaxError as exc:
        raise XMLRejected(f"XML is not well-formed: {exc}") from None
    if root.getroottree().docinfo.doctype:
        raise XMLRejected("XML contains a DOCTYPE; SAML messages never need one")
    return root
