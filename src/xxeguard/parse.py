"""XXE guard for invoice documents with an optional internal DTD.

The public entry points work on plain text and Element objects.  A policy
describes the entity limits, the element whitelist and whether external
constructs are permitted.  External identifiers are described by
``scan_doctype`` but are never fetched by this module: no code path opens a
file or a socket.

Security model
--------------

* External entities and external DTDs are rejected outright.  The policy keys
  ``allow_external_entities`` and ``allow_external_dtd`` must be ``False``.
* The number of entity declarations and the depth of entity expansion are
  bounded.  Expansion is performed by this module under both limits, so a
  document cannot make the process allocate an unbounded amount of text.
* Any malformed document -- including a malformed DTD -- rejects the whole
  document; no partial tree is ever returned.
* Only elements named by the policy whitelist may appear in the result.
* Processing instructions and comments are ignored.
* Batch parsing keeps no state between documents; each document is parsed
  from scratch and a failure only affects its own slot.
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element
from xml.parsers import expat

SAFE_SCHEMES = frozenset({"urn"})

DEFAULT_MAX_ENTITIES = 16
DEFAULT_MAX_ENTITY_DEPTH = 4

# Hard ceilings applied while expanding entities.  They are independent from
# the policy: even when a policy asks for very large limits a single document
# cannot make expansion run away.  Both are far above anything an invoice
# needs.
MAX_ENTITY_EXPANSIONS = 10_000
MAX_EXPANDED_CHARS = 2_000_000

_NAME = r"[A-Za-z_:][A-Za-z0-9_.:-]*"
_NAME_RE = re.compile(_NAME)
_ENTITY_REF_RE = re.compile(r"&(" + _NAME + r");")
_PARAM_REF_RE = re.compile(r"%(" + _NAME + r");")

_XML_BUILTINS = frozenset({"amp", "lt", "gt", "quot", "apos"})


class XXEError(ValueError):
    """Base error for documents rejected by the XXE guard."""


class XXESecurityError(XXEError):
    """Raised when a document or policy violates a security rule."""


class XXEParseError(XXEError):
    """Raised when the document is not well formed."""


# ---------------------------------------------------------------------------
# Low level scanning helpers
# ---------------------------------------------------------------------------


def _skip_comment(text: str, index: int) -> int:
    """Return the index after the comment starting at ``index``."""

    end = text.find("-->", index + 4)
    if end < 0:
        raise XXEParseError("unterminated comment")
    return end + 3


def _skip_pi(text: str, index: int) -> int:
    end = text.find("?>", index + 2)
    if end < 0:
        raise XXEParseError("unterminated processing instruction")
    return end + 2


def _skip_cdata(text: str, index: int) -> int:
    end = text.find("]]>", index + 9)
    if end < 0:
        raise XXEParseError("unterminated CDATA section")
    return end + 3


def _find_doctype_span(text: str) -> tuple[int, int] | None:
    """Return the half open span of the first DOCTYPE declaration."""

    index = 0
    length = len(text)
    while index < length:
        if text.startswith("<!--", index):
            index = _skip_comment(text, index)
            continue
        if text.startswith("<![CDATA[", index):
            index = _skip_cdata(text, index)
            continue
        if text.startswith("<?", index):
            index = _skip_pi(text, index)
            continue
        if text.startswith("<!DOCTYPE", index):
            return _doctype_end(text, index)
        index += 1
    return None


def _doctype_end(text: str, start: int) -> tuple[int, int]:
    depth = 0
    quote: str | None = None
    index = start + len("<!DOCTYPE")
    while index < len(text):
        if quote is None:
            if text.startswith("<!--", index):
                index = _skip_comment(text, index)
                continue
            if text.startswith("<?", index):
                index = _skip_pi(text, index)
                continue
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise XXEParseError("unbalanced internal subset")
        elif char == ">" and depth == 0:
            return start, index + 1
        index += 1
    raise XXEParseError("unterminated DOCTYPE declaration")


def _read_literal(text: str, index: int) -> tuple[str, int]:
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] not in "'\"":
        raise XXEParseError("expected a quoted literal")
    quote = text[index]
    end = text.find(quote, index + 1)
    if end < 0:
        raise XXEParseError("unterminated quoted literal")
    return text[index + 1 : end], end + 1


def _parse_external_head(head: str) -> dict[str, str | None]:
    """Parse the part of a DOCTYPE between its name and the internal subset.

    An empty head means the DOCTYPE has no external identifier.  Anything
    else must be a well formed SYSTEM or PUBLIC declaration; junk is a parse
    error rather than something to ignore.
    """

    text = head.strip()
    if not text:
        return {"public_id": None, "system_id": None}

    public = re.fullmatch(
        r"(?is)PUBLIC\s*(['\"])(.*?)\1\s*(['\"])(.*?)\3\s*", text
    )
    if public:
        return {"public_id": public.group(2), "system_id": public.group(4)}

    system = re.fullmatch(r"(?is)SYSTEM\s*(['\"])(.*?)\1\s*", text)
    if system:
        return {"public_id": None, "system_id": system.group(2)}

    raise XXEParseError("malformed DOCTYPE external identifier")


def _find_unquoted(text: str, target: str) -> int:
    quote: str | None = None
    index = 0
    length = len(text)
    while index < length:
        if quote is None:
            if text.startswith("<!--", index):
                index = _skip_comment(text, index)
                continue
            if text.startswith("<?", index):
                index = _skip_pi(text, index)
                continue
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == target:
            return index
        index += 1
    return -1


def _matching_bracket(text: str, start: int) -> int:
    quote: str | None = None
    depth = 0
    index = start
    while index < len(text):
        if quote is None:
            if text.startswith("<!--", index):
                index = _skip_comment(text, index)
                continue
            if text.startswith("<?", index):
                index = _skip_pi(text, index)
                continue
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                raise XXEParseError("unbalanced internal subset")
        index += 1
    raise XXEParseError("unterminated internal subset")


def _declaration_end(text: str, start: int) -> int:
    quote: str | None = None
    index = start + 2
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == ">":
            return index
        index += 1
    raise XXEParseError("unterminated entity declaration")


def _strip_comments(text: str) -> str:
    parts: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("<!--", index):
            index = _skip_comment(text, index)
            continue
        parts.append(text[index])
        index += 1
    return "".join(parts)


def _parse_entity_declaration(raw: str) -> tuple[str, dict[str, Any]]:
    index = 0
    while index < len(raw) and raw[index].isspace():
        index += 1
    parameter = False
    if index < len(raw) and raw[index] == "%":
        parameter = True
        index += 1
        while index < len(raw) and raw[index].isspace():
            index += 1

    match = _NAME_RE.match(raw, index)
    if not match:
        raise XXEParseError("malformed entity declaration")
    name = match.group(0)
    index = match.end()
    while index < len(raw) and raw[index].isspace():
        index += 1
    rest = raw[index:]

    external = False
    value: str | None = None
    public_id: str | None = None
    system_id: str | None = None

    keyword = rest[:6].upper()
    if keyword == "SYSTEM":
        system_id, cursor = _read_literal(rest, 6)
        external = True
        trailer = rest[cursor:].strip()
        if trailer and not re.fullmatch(r"(?is)NDATA\s+" + _NAME, trailer):
            raise XXEParseError("malformed external entity declaration")
    elif keyword == "PUBLIC":
        public_id, cursor = _read_literal(rest, 6)
        system_id, cursor = _read_literal(rest, cursor)
        external = True
        trailer = rest[cursor:].strip()
        if trailer and not re.fullmatch(r"(?is)NDATA\s+" + _NAME, trailer):
            raise XXEParseError("malformed external entity declaration")
    else:
        value, cursor = _read_literal(rest, 0)
        if rest[cursor:].strip():
            raise XXEParseError("malformed entity declaration")

    entity = {
        "name": name,
        "parameter": parameter,
        "external": external,
        "value": value,
        "public_id": public_id,
        "system_id": system_id,
    }
    return name, entity


def _scan_entity_declarations(subset: str) -> dict[str, dict[str, Any]]:
    clean = _strip_comments(subset)
    entities: dict[str, dict[str, Any]] = {}
    index = 0
    while True:
        index = clean.find("<!ENTITY", index)
        if index < 0:
            break
        end = _declaration_end(clean, index)
        raw = clean[index + len("<!ENTITY") : end]
        name, entity = _parse_entity_declaration(raw)
        if name in entities:
            # Duplicate declarations make the effective binding ambiguous;
            # refuse rather than guess which one a later expansion would use.
            raise XXEParseError("duplicate entity declaration: " + name)
        entities[name] = entity
        index = end + 1
    return entities


# ---------------------------------------------------------------------------
# DTD scanning
# ---------------------------------------------------------------------------


def scan_doctype(text: str) -> dict:
    """Scan the format definition and describe its external and internal parts."""

    if not isinstance(text, str):
        raise XXEParseError("document must be text")

    blank = {
        "name": "",
        "external_id": None,
        "public_id": None,
        "internal_subset": "",
        "entities": {},
        "external_entities": [],
        "parameter_entities": [],
    }

    span = _find_doctype_span(text)
    if span is None:
        return blank

    start, end = span
    declaration = text[start:end]
    content = declaration[len("<!DOCTYPE") : -1].strip()

    name_match = _NAME_RE.match(content)
    if not name_match:
        raise XXEParseError("DOCTYPE is missing a name")
    name = name_match.group(0)
    rest = content[name_match.end() :]

    bracket = _find_unquoted(rest, "[")
    if bracket < 0:
        head = rest
        subset = ""
    else:
        close = _matching_bracket(rest, bracket)
        head = rest[:bracket]
        subset = rest[bracket + 1 : close]
        if rest[close + 1 :].strip():
            raise XXEParseError("unexpected data after internal subset")

    external = _parse_external_head(head)
    entities = _scan_entity_declarations(subset)
    external_entities = [
        entity_name
        for entity_name, entity in entities.items()
        if entity["external"] and not entity["parameter"]
    ]
    parameter_entities = [
        entity_name for entity_name, entity in entities.items() if entity["parameter"]
    ]

    return {
        "name": name,
        "external_id": external["system_id"],
        "public_id": external["public_id"],
        "internal_subset": subset,
        "entities": entities,
        "external_entities": external_entities,
        "parameter_entities": parameter_entities,
    }


# ---------------------------------------------------------------------------
# DTD policy checks
# ---------------------------------------------------------------------------


def _as_mapping(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def reject_external(doctype: dict) -> bool:
    """Return True when a DOCTYPE names an external entity or external DTD.

    Any external identifier is rejected, whatever its scheme: a document
    store is never consulted, so an external identifier can only ever be a
    way to reach the network or the filesystem.
    """

    if not isinstance(doctype, Mapping):
        return True

    if doctype.get("external_id") or doctype.get("public_id"):
        return True

    for entity in _as_mapping(doctype.get("entities")).values():
        if not isinstance(entity, Mapping):
            return True
        if entity.get("external"):
            return True
        if entity.get("system_id") or entity.get("public_id"):
            return True

    # Also honour a pre-computed list, in case a caller supplies one.
    if _as_mapping(doctype).get("external_entities"):
        return True

    return False


def _policy_limit(policy: Mapping | None, key: str, default: int) -> int:
    if not isinstance(policy, Mapping):
        return default
    value = policy.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return default
    return value


def _entity_value(entity: Mapping) -> str:
    value = entity.get("value")
    if value is None:
        return ""
    if not isinstance(value, str):
        return str(value)
    return value


def _entity_references(value: str) -> set[str]:
    references = set(_ENTITY_REF_RE.findall(value))
    references.update(_PARAM_REF_RE.findall(value))
    return references


def _entity_depths(
    entities: Mapping,
    cycles: set[str],
) -> dict[str, int | None]:
    """Compute the expansion depth of every declared entity.

    Depth one means an entity whose value references no other declared
    entity.  A value that participates in a cycle is reported as ``None``.
    The computation is memoised so an entity graph with heavy sharing is
    still cheap.
    """

    memo: dict[str, int | None] = {}

    def visit(name: str, trail: frozenset[str]) -> int | None:
        if name in memo:
            return memo[name]
        if name in trail:
            cycles.add(name)
            return None

        entity = _as_mapping(entities.get(name))
        references = _entity_references(_entity_value(entity))

        depth = 1
        for reference in references:
            if reference not in entities:
                continue
            child = visit(reference, trail | {name})
            if child is None:
                cycles.add(name)
                memo[name] = None
                return None
            depth = max(depth, 1 + child)

        memo[name] = depth
        return depth

    for name in entities:
        visit(name, frozenset())
    return memo


def check_entities(doctype: dict, policy: dict) -> list[str]:
    """Return the entity count and expansion depth problems in a DOCTYPE."""

    problems: list[str] = []
    if not isinstance(doctype, Mapping):
        return ["doctype must be a mapping"]

    entities = _as_mapping(doctype.get("entities"))
    if not all(isinstance(entity, Mapping) for entity in entities.values()):
        return ["entity declarations must be mappings"]

    max_entities = _policy_limit(policy, "max_entities", DEFAULT_MAX_ENTITIES)
    max_depth = _policy_limit(policy, "max_entity_depth", DEFAULT_MAX_ENTITY_DEPTH)

    total = len(entities)
    if total > max_entities:
        problems.append(f"too_many_entities:{total}>{max_entities}")

    cycles: set[str] = set()
    depths = _entity_depths(entities, cycles)

    for name in entities:
        depth = depths.get(name)
        if depth is None:
            continue
        if depth > max_depth:
            problems.append(f"entity_depth_exceeded:{name}:{depth}>{max_depth}")

    for name in sorted(cycles):
        problems.append(f"entity_cycle:{name}")

    return problems


def check_scheme(uri: str) -> bool:
    """Return True when an entity identifier uses a permitted scheme.

    Only schemes in :data:`SAFE_SCHEMES` are permitted.  In particular
    ``file``, ``http`` and ``https`` are not, and a relative reference with
    no scheme is not either.
    """

    if not isinstance(uri, str) or not uri.strip():
        return False
    try:
        parts = urlsplit(uri.strip())
    except ValueError:
        return False
    return parts.scheme.lower() in SAFE_SCHEMES


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def _strip_doctype(text: str) -> str:
    span = _find_doctype_span(text)
    if span is None:
        return text
    start, end = span
    return text[:start] + text[end:]


def _expand_entities(
    text: str,
    entities: Mapping,
    policy: Mapping,
    state: list[int],
    depth: int,
) -> str:
    """Expand internal entity references without touching markup constructs.

    References inside comments, CDATA sections and processing instructions
    are left alone, as the XML specification requires.  Expansion is bounded
    both in depth and in total output so a hostile entity graph cannot make
    the process exhaust memory or time.
    """

    max_depth = _policy_limit(policy, "max_entity_depth", DEFAULT_MAX_ENTITY_DEPTH)

    parts: list[str] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]

        if char == "<":
            if text.startswith("<!--", index):
                end = _skip_comment(text, index)
                parts.append(text[index:end])
                index = end
                continue
            if text.startswith("<![CDATA[", index):
                end = _skip_cdata(text, index)
                parts.append(text[index:end])
                index = end
                continue
            if text.startswith("<?", index):
                end = _skip_pi(text, index)
                parts.append(text[index:end])
                index = end
                continue
            parts.append(char)
            index += 1
            continue

        if char == "&":
            match = _ENTITY_REF_RE.match(text, index)
            if match is None:
                parts.append(char)
                index += 1
                continue

            name = match.group(1)
            if name in _XML_BUILTINS:
                parts.append(match.group(0))
                index = match.end()
                continue

            entity = entities.get(name)
            if not isinstance(entity, Mapping):
                raise XXEParseError("undefined entity: " + name)
            if entity.get("external"):
                raise XXESecurityError(
                    "external entity reference is not allowed: " + name
                )

            if depth + 1 > max_depth:
                raise XXESecurityError(
                    f"entity expansion depth exceeded at {name}: "
                    f"{depth + 1}>{max_depth}"
                )

            state[0] += 1
            if state[0] > MAX_ENTITY_EXPANSIONS:
                raise XXESecurityError("too many entity expansions")

            expansion = _expand_entities(
                _entity_value(entity),
                entities,
                policy,
                state,
                depth + 1,
            )
            state[1] += len(expansion)
            if state[1] > MAX_EXPANDED_CHARS:
                raise XXESecurityError("entity expansion output is too large")
            parts.append(expansion)
            index = match.end()
            continue

        parts.append(char)
        index += 1

    return "".join(parts)


class _TreeBuilder:
    def __init__(self) -> None:
        self.root: Element | None = None
        self.stack: list[Element] = []

    def start(self, name: str, attrs: dict) -> None:
        node = Element(name, dict(attrs))
        if self.stack:
            self.stack[-1].append(node)
        elif self.root is None:
            self.root = node
        self.stack.append(node)

    def end(self, _name: str) -> None:
        if self.stack:
            self.stack.pop()

    def data(self, data: str) -> None:
        if not self.stack:
            return
        parent = self.stack[-1]
        if len(parent):
            last = parent[-1]
            last.tail = (last.tail or "") + data
        else:
            parent.text = (parent.text or "") + data


def _reject_dtd(*_args: Any) -> None:
    raise XXESecurityError("DTD constructs are not allowed in the document body")


def _refuse_external(*_args: Any) -> int:
    # Returning 0 aborts the parse instead of resolving anything.
    return 0


def _parse_tree(text: str) -> Element:
    builder = _TreeBuilder()
    parser = expat.ParserCreate()
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data
    parser.ProcessingInstructionHandler = lambda _target, _data: None
    parser.CommentHandler = lambda _data: None

    # Defence in depth: the DOCTYPE has already been stripped, so expat must
    # never see a DTD construct.  If one slips through it is rejected.
    parser.StartDoctypeDeclHandler = _reject_dtd
    parser.EntityDeclHandler = _reject_dtd
    parser.UnparsedEntityDeclHandler = _reject_dtd
    parser.NotationDeclHandler = _reject_dtd
    parser.ElementDeclHandler = _reject_dtd
    parser.AttlistDeclHandler = _reject_dtd
    parser.ExternalEntityRefHandler = _refuse_external

    try:
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    except (AttributeError, ValueError):  # pragma: no cover - platform detail
        pass

    try:
        parser.Parse(text, True)
    except expat.ExpatError as exc:
        raise XXEParseError(f"malformed document: {exc}") from exc

    if builder.root is None:
        raise XXEParseError("document has no root element")
    return builder.root


def _parse_body(text: str, doctype: Mapping, policy: Mapping) -> Element:
    body = _strip_doctype(text)
    # Any DTD construct that survived the strip is refused by the parser's
    # declaration handlers in ``_parse_tree``.
    expanded = _expand_entities(
        body,
        _as_mapping(doctype.get("entities")),
        policy,
        [0, 0],
        0,
    )
    return _parse_tree(expanded)


def _parse_document(text: str, policy: dict) -> Element:
    if not isinstance(text, str):
        raise XXEParseError("document must be text")

    problems = validate_policy(policy)
    if problems:
        raise XXESecurityError("unusable policy: " + "; ".join(problems))

    doctype = scan_doctype(text)
    if reject_external(doctype):
        raise XXESecurityError("external identifiers are not allowed")

    try:
        entity_problems = check_entities(doctype, policy)
    except RecursionError as exc:
        raise XXESecurityError("entity graph is too deep") from exc
    if entity_problems:
        raise XXESecurityError("entity policy violation: " + "; ".join(entity_problems))

    try:
        root = _parse_body(text, doctype, policy)
    except RecursionError as exc:
        raise XXESecurityError("entity expansion is too deep") from exc

    element_problems = check_elements(root, policy.get("allowed_elements") or [])
    if element_problems:
        raise XXESecurityError(
            "element policy violation: " + "; ".join(element_problems)
        )

    return root


def parse_document(text: str, policy: dict) -> Element:
    """Parse one document with the configured DTD and element policy.

    Any rule violation raises a :class:`ValueError` subclass.  No partial
    result is returned and no external resource is ever read.
    """

    return _parse_document(text, policy)


def check_elements(root: Element, allowed: list[str]) -> list[str]:
    """Return the elements that are absent from the whitelist."""

    if root is None:
        return ["root_missing"]
    if not isinstance(root, Element):
        return ["root_is_not_an_element"]

    names = {str(name) for name in (allowed or []) if str(name)}
    problems: list[str] = []
    seen: set[str] = set()
    stack = [root]
    while stack:
        element = stack.pop()
        tag = str(element.tag)
        if tag not in names and tag not in seen:
            seen.add(tag)
            problems.append(f"element_not_allowed:{tag}")
        stack.extend(list(element)[::-1])
    return problems


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_policy(policy: dict) -> list[str]:
    """Return the problems found in a parsing policy."""

    if not isinstance(policy, Mapping):
        return ["policy_must_be_a_mapping"]

    problems: list[str] = []

    if policy.get("allow_external_entities") is not False:
        problems.append("allow_external_entities_must_be_false")
    if policy.get("allow_external_dtd") is not False:
        problems.append("allow_external_dtd_must_be_false")

    if not _positive_int(policy.get("max_entities")):
        problems.append("max_entities_missing")
    if not _positive_int(policy.get("max_entity_depth")):
        problems.append("max_entity_depth_missing")

    allowed = policy.get("allowed_elements")
    if not isinstance(allowed, (list, tuple, set)) or not allowed:
        problems.append("allowed_elements_empty")
    elif not all(isinstance(name, str) and name.strip() for name in allowed):
        problems.append("allowed_elements_invalid")

    return problems


def xxe_batch(docs: list[str], policy: dict) -> dict:
    """Parse several documents and return one result and error per document.

    Documents are parsed in isolation: no entity, whitelist or parser state
    is shared between iterations, so a failure only affects its own slot.
    """

    results: list[Element | None] = []
    errors: list[str | None] = []

    for document in docs or []:
        try:
            if isinstance(document, bytes):
                document = document.decode("utf-8")
            root = parse_document(document, policy)
            results.append(root)
            errors.append(None)
        except Exception as exc:
            results.append(None)
            errors.append(str(exc) or exc.__class__.__name__)

    return {"results": results, "errors": errors}


__all__ = [
    "XXEError",
    "XXEParseError",
    "XXESecurityError",
    "scan_doctype",
    "reject_external",
    "check_entities",
    "check_scheme",
    "parse_document",
    "check_elements",
    "validate_policy",
    "xxe_batch",
]
