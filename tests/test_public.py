"""Public contract tests for the invoice XXE guard."""

import xml.etree.ElementTree as ET

import pytest

from xxeguard import parse_document, xxe_batch


POLICY = {
    "allow_external_entities": False,
    "allow_external_dtd": False,
    "max_entities": 8,
    "max_entity_depth": 3,
    "allowed_elements": ["invoice", "amount", "note"],
}


def test_plain_document_parses():
    text = (
        "<?xml version='1.0'?>"
        "<invoice><amount>42</amount><?keep quiet?><note>ok</note></invoice>"
    )

    root = parse_document(text, POLICY)

    assert root.tag == "invoice"
    assert root.findtext("amount") == "42"
    assert root.findtext("note") == "ok"
    assert ET.tostring(parse_document(text, POLICY)) == ET.tostring(root)

    with pytest.raises(ValueError):
        parse_document(text + "<extra/>", POLICY)


def test_external_entity_is_rejected():
    text = (
        "<!DOCTYPE invoice ["
        '<!ENTITY leak SYSTEM "https://example.invalid/leak">'
        "]><invoice><amount>&leak;</amount></invoice>"
    )

    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_element_whitelist_is_enforced():
    text = "<invoice><amount>7</amount><script>alert(1)</script></invoice>"

    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_parse_failure_rejects_whole_document():
    text = "<invoice><amount>7</amount><note>broken"

    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_batch_documents_are_independent():
    first = (
        '<!DOCTYPE invoice [<!ENTITY token "first">]>'
        "<invoice><note>&token;</note></invoice>"
    )
    second = (
        '<!DOCTYPE invoice [<!ENTITY token "second">]>'
        "<invoice><note>&token;</note></invoice>"
    )

    output = xxe_batch([first, second], POLICY)

    assert output["errors"] == [None, None]
    assert output["results"][0].findtext("note") == "first"
    assert output["results"][1].findtext("note") == "second"