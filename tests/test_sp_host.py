"""noblecloak.service_principal._host: the host of a URL in the one form the package accepts."""

from __future__ import annotations

import pytest

from noblecloak.service_principal._host import normal_host  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("host", "normal"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("example.com.", "example.com."),
        ("localhost", "localhost"),
        ("a_b.example", "a_b.example"),
        ("straße.example", "xn--strae-oqa.example"),  # UTS #46 non-transitional: not `strasse.example`
        ("STRASSE.example", "strasse.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("\uff41.example", "a.example"),  # a full-width letter maps to its ASCII form
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("1.2.3.4", "1.2.3.4"),
        ("::1", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("a" * 63 + ".example", "a" * 63 + ".example"),
    ],
)
def test_the_host_is_returned_in_lower_case_ascii(host: str, normal: str) -> None:
    assert normal_host(host) == normal


@pytest.mark.parametrize(
    "host",
    [
        "",
        ".",
        "a..b",
        ".a",
        "-" + "a" * 63 + "." + "b" * 64,
        "a" * 64 + ".example",
        ".".join(["a" * 60] * 5),  # over 253 characters
        "a‍.example",  # a zero-width joiner
        "⒈.example",
        "xn--a.example",  # not punycode
        "xn--.example",
        "ex%61mple.com",  # percent-encoded
        "a b.example",
        "a/b.example",
        "0x7f.1",  # IPv4 in another spelling
        "1.2.3.04",
        "2130706433",
        "127.1",
        "1.2.3.4.",
        "a.0x",
        "e.1",
        "[::1]",
        "::1%eth0",
        "::g",
        "1:2:3:4:5:6:7:8:9",
    ],
)
def test_a_host_that_parsers_would_read_differently_or_that_no_resolver_takes_is_refused(host: str) -> None:
    assert normal_host(host) is None
