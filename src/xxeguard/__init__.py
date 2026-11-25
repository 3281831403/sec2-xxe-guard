"""Guards for parsing invoice documents that carry an optional DTD."""

from .parse import (
    XXEError,
    XXEParseError,
    XXESecurityError,
    check_elements,
    check_entities,
    check_scheme,
    parse_document,
    reject_external,
    scan_doctype,
    validate_policy,
    xxe_batch,
)

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