"""Security regression tests for the invoice XXE guard."""

import os
import socket

import pytest

from xxeguard import (
    XXEError,
    check_elements,
    check_entities,
    check_scheme,
    parse_document,
    reject_external,
    scan_doctype,
    validate_policy,
    xxe_batch,
)

POLICY = {
    "allow_external_entities": False,
    "allow_external_dtd": False,
    "max_entities": 8,
    "max_entity_depth": 3,
    "allowed_elements": ["invoice", "amount", "note", "items", "item"],
}


def _canonical(root):
    import xml.etree.ElementTree as ET

    return ET.tostring(root)


# ---------------------------------------------------------------------------
# External entities and external DTDs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "http://127.0.0.1/leak",
        "https://example.invalid/leak",
        "ftp://example.invalid/leak",
        "jar:file:///etc/passwd!/x",
        "php://filter/resource=/etc/passwd",
        "gopher://example.invalid/",
        "urn:example:leak",
        "relative/path.xml",
    ],
)
def test_external_entity_is_always_rejected(uri):
    text = (
        "<!DOCTYPE invoice ["
        f'<!ENTITY leak SYSTEM "{uri}">'
        "]><invoice><amount>&leak;</amount></invoice>"
    )
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_external_parameter_entity_is_rejected():
    text = (
        "<!DOCTYPE invoice ["
        '<!ENTITY % ext SYSTEM "http://example.invalid/dtd">%ext;'
        "]><invoice><amount>1</amount></invoice>"
    )
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


@pytest.mark.parametrize(
    "head",
    [
        'SYSTEM "http://example.invalid/x.dtd"',
        'SYSTEM "file:///etc/passwd"',
        'PUBLIC "-//EXAMPLE//EN" "http://example.invalid/x.dtd"',
        'PUBLIC "-//EXAMPLE//EN" "file:///etc/passwd"',
    ],
)
def test_external_dtd_is_rejected(head):
    text = f"<!DOCTYPE invoice {head}><invoice><amount>1</amount></invoice>"
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_reject_external_flags_any_external_identifier():
    doctype = scan_doctype(
        '<!DOCTYPE invoice SYSTEM "urn:example:dtd"><invoice/>'
    )
    assert reject_external(doctype) is True

    doctype = scan_doctype(
        '<!DOCTYPE invoice [<!ENTITY e SYSTEM "https://x.invalid/a">]><invoice/>'
    )
    assert reject_external(doctype) is True

    internal = scan_doctype(
        '<!DOCTYPE invoice [<!ENTITY e "ok">]><invoice/>'
    )
    assert reject_external(internal) is False


# ---------------------------------------------------------------------------
# Files and network are never reached
# ---------------------------------------------------------------------------


def test_local_file_is_not_read(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET")
    uri = secret.as_uri()

    text = (
        "<!DOCTYPE invoice ["
        f'<!ENTITY leak SYSTEM "{uri}">'
        "]><invoice><amount>&leak;</amount></invoice>"
    )
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_network_is_not_contacted(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)

    text = (
        "<!DOCTYPE invoice ["
        '<!ENTITY leak SYSTEM "http://127.0.0.1:9/leak">'
        "]><invoice><amount>&leak;</amount></invoice>"
    )
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


# ---------------------------------------------------------------------------
# Entity counting and depth
# ---------------------------------------------------------------------------


def _internal_entities(count):
    return "".join(f'<!ENTITY e{i} "v{i}">' for i in range(count))


def test_entity_count_limit_includes_internal_entities():
    allowed = len(POLICY["allowed_elements"])
    text = (
        "<!DOCTYPE invoice ["
        + _internal_entities(POLICY["max_entities"] + 1)
        + "]><invoice><amount>1</amount></invoice>"
    )
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_entity_count_at_limit_is_fine():
    count = POLICY["max_entities"]
    subset = "".join(f'<!ENTITY e{i} "v">' for i in range(count))
    text = f"<!DOCTYPE invoice [{subset}]><invoice><amount>1</amount></invoice>"
    parse_document(text, POLICY)


def test_entity_depth_limit_is_enforced():
    # e0..e4 chained: depth 5 exceeds max_entity_depth 3
    subset = (
        '<!ENTITY e0 "leaf">'
        '<!ENTITY e1 "&e0;">'
        '<!ENTITY e2 "&e1;">'
        '<!ENTITY e3 "&e2;">'
        '<!ENTITY e4 "&e3;">'
    )
    text = f"<!DOCTYPE invoice [{subset}]><invoice><note>&e4;</note></invoice>"
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_entity_depth_within_limit_expands():
    subset = '<!ENTITY e0 "leaf"><!ENTITY e1 "&e0;"><!ENTITY e2 "&e1;">'
    text = f"<!DOCTYPE invoice [{subset}]><invoice><note>&e2;</note></invoice>"
    root = parse_document(text, POLICY)
    assert root.findtext("note") == "leaf"


def test_entity_cycle_is_rejected():
    subset = '<!ENTITY a "&b;"><!ENTITY b "&a;">'
    text = f"<!DOCTYPE invoice [{subset}]><invoice><note>&a;</note></invoice>"
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_billion_laughs_is_bounded():
    subset = '<!ENTITY a "aaaaaaaaaa">'
    prev = "a"
    for i in range(1, 6):
        name = chr(ord("a") + i)
        subset += f'<!ENTITY {name} "&{prev};&{prev};&{prev};&{prev};">'
        prev = name
    text = f"<!DOCTYPE invoice [{subset}]><invoice><note>&f;</note></invoice>"
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


def test_check_entities_reports_count_and_depth():
    doctype = scan_doctype(
        "<!DOCTYPE invoice ["
        + _internal_entities(POLICY["max_entities"] + 2)
        + ']><invoice/>'
    )
    problems = check_entities(doctype, POLICY)
    assert any(p.startswith("too_many_entities:") for p in problems)


# ---------------------------------------------------------------------------
# Malformed input rejects the whole document
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "<invoice><amount>7</amount><note>broken",
        "<invoice><amount>7</amount></invoice><extra/>",
        "<invoice>&undefined;</invoice>",
        '<!DOCTYPE invoice [<!ENTITY e "x">><invoice/>',
        '<!DOCTYPE invoice [<!ENTITY e SYSTEM "http://x">]',
        "not xml at all",
        "",
        "<!DOCTYPE invoice [<!ENTITY e 'a'><!ENTITY e 'b'>]><invoice/>",
        '<!DOCTYPE invoice [<!ENTITY e "a" garbage>]><invoice/>',
        '<!DOCTYPE invoice SYSTEM "http://x" JUNK><invoice/>',
    ],
)
def test_malformed_document_rejects_whole(text):
    with pytest.raises(ValueError):
        parse_document(text, POLICY)


# ---------------------------------------------------------------------------
# Element whitelist
# ---------------------------------------------------------------------------


def test_whitelist_is_applied_by_parse_document():
    with pytest.raises(ValueError):
        parse_document("<invoice><script>alert(1)</script></invoice>", POLICY)

    with pytest.raises(ValueError):
        parse_document("<evil/>", POLICY)

    root = parse_document(
        "<invoice><items><item>1</item></items></invoice>", POLICY
    )
    assert root.tag == "invoice"


def test_check_elements_reports_disallowed():
    root = parse_document("<invoice><amount>1</amount></invoice>", POLICY)
    assert check_elements(root, ["invoice"]) == ["element_not_allowed:amount"]


# ---------------------------------------------------------------------------
# Processing instructions and comments are ignored
# ---------------------------------------------------------------------------


def test_processing_instructions_are_ignored():
    text = (
        "<?xml version='1.0'?>"
        "<?target data?><invoice><?evil x?><amount>1</amount></invoice>"
    )
    root = parse_document(text, POLICY)
    assert root.findtext("amount") == "1"


def test_comments_are_ignored_and_do_not_hide_markup():
    text = "<invoice><!-- <script>x</script> --><amount>1</amount></invoice>"
    root = parse_document(text, POLICY)
    assert root.findtext("amount") == "1"


def test_entity_reference_inside_cdata_or_comment_is_not_expanded():
    subset = '<!ENTITY e "SECRET">'
    text = (
        f"<!DOCTYPE invoice [{subset}]>"
        "<invoice><note><![CDATA[&e;]]><!-- &e; -->&e;</note></invoice>"
    )
    root = parse_document(text, POLICY)
    assert "SECRET" in root.findtext("note")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_document_parses_identically_twice():
    text = (
        '<!DOCTYPE invoice [<!ENTITY e "v">]>'
        "<invoice><note>&e;</note></invoice>"
    )
    first = _canonical(parse_document(text, POLICY))
    second = _canonical(parse_document(text, POLICY))
    assert first == second


# ---------------------------------------------------------------------------
# Batch independence
# ---------------------------------------------------------------------------


def test_batch_failure_only_affects_its_slot():
    good = "<invoice><note>ok</note></invoice>"
    evil = (
        '<!DOCTYPE invoice [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
        "<invoice><note>&leak;</note></invoice>"
    )
    broken = "<invoice><note>broken"

    output = xxe_batch([good, evil, broken], POLICY)

    assert output["results"][0] is not None
    assert output["results"][1] is None
    assert output["results"][2] is None
    assert output["errors"][0] is None
    assert output["errors"][1] is not None
    assert output["errors"][2] is not None


def test_batch_entity_names_do_not_leak_between_documents():
    first = (
        '<!DOCTYPE invoice [<!ENTITY token "first">]>'
        "<invoice><note>&token;</note></invoice>"
    )
    # Second document has no declaration; the first document's entity must not
    # be visible to it.
    second = "<invoice><note>&token;</note></invoice>"

    output = xxe_batch([first, second], POLICY)

    assert output["results"][0].findtext("note") == "first"
    assert output["results"][1] is None
    assert output["errors"][1] is not None


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "override",
    [
        {"allow_external_entities": True},
        {"allow_external_dtd": True},
        {"allow_external_entities": None},
        {"allow_external_dtd": 0},
        {"max_entities": 0},
        {"max_entities": -1},
        {"max_entities": True},
        {"max_entity_depth": 0},
        {"allowed_elements": []},
        {"allowed_elements": ["ok", ""]},
    ],
)
def test_invalid_policy_is_rejected(override):
    policy = dict(POLICY)
    policy.update(override)
    assert validate_policy(policy)
    with pytest.raises(ValueError):
        parse_document("<invoice/>", policy)


def test_valid_policy_passes():
    assert validate_policy(POLICY) == []


# ---------------------------------------------------------------------------
# Schemes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "uri, allowed",
    [
        ("file:///etc/passwd", False),
        ("http://example.invalid", False),
        ("https://example.invalid", False),
        ("ftp://example.invalid", False),
        ("relative/path", False),
        ("", False),
        ("urn:example:x", True),
    ],
)
def test_check_scheme(uri, allowed):
    assert check_scheme(uri) is allowed
