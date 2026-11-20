"""Byte-exact URL recovery — the part most likely to break silently."""
from __future__ import annotations

import pytest

from app.urls import UrlError, extract_from_raw, parse_target


def split(path: str, query: str = "") -> tuple[bytes, bytes]:
    return path.encode("latin-1"), query.encode("latin-1")


class TestExtract:
    def test_plain_https(self):
        t = extract_from_raw(*split("/u/ABC123/https://example.com/a.zip"))
        assert t.token == "ABC123"
        assert t.url == b"https://example.com/a.zip"

    def test_double_slash_in_scheme_survives(self):
        """/u/<t>/https://... — the '//' must not be collapsed.

        This is the single assumption behind the whole link shape, and it holds
        only because nginx is configured with a URI-less proxy_pass. If it ever
        breaks, this test still passes here and the e2e nginx test fails, which
        is exactly the signal we want.
        """
        t = extract_from_raw(*split("/u/TOK/https://e.com/a//b.zip"))
        assert t.url == b"https://e.com/a//b.zip"

    def test_query_is_reattached_byte_for_byte(self):
        t = extract_from_raw(*split("/u/TOK/https://e.com/get", "a=1&b=2%20x"))
        assert t.url == b"https://e.com/get?a=1&b=2%20x"
        assert t.has_query is True

    def test_encoded_slash_survives(self):
        t = extract_from_raw(*split("/u/TOK/https://e.com/x%2Fy.zip"))
        assert t.url == b"https://e.com/x%2Fy.zip"

    def test_utf8_percent_escapes_survive(self):
        t = extract_from_raw(*split("/u/TOK/https://e.com/%e4%b8%ad%e6%96%87.zip"))
        assert t.url == b"https://e.com/%e4%b8%ad%e6%96%87.zip"

    def test_query_containing_question_mark(self):
        t = extract_from_raw(*split("/u/TOK/https://e.com/p?next=https://x/y"))
        assert t.url == b"https://e.com/p?next=https://x/y"

    def test_missing_target_is_404(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/TOK/"))
        assert exc.value.status == 404

    def test_missing_token_is_404(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u//https://e.com/a"))
        assert exc.value.status == 404

    def test_relative_target_rejected(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/TOK/e.com/a.zip"))
        assert exc.value.status == 400

    def test_ftp_target_rejected(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/TOK/ftp://e.com/a.zip"))
        assert exc.value.status == 400

    def test_bare_percent_is_400(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/TOK/https://e.com/100%.zip"))
        assert exc.value.status == 400

    def test_nul_byte_is_400(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/TOK/https://e.com/a%00b.zip"))
        assert exc.value.status == 400

    def test_overlong_url_is_414(self):
        path = "/u/TOK/https://e.com/" + "L" * 9000
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split(path), max_url_bytes=8192)
        assert exc.value.status == 414

    def test_token_with_punctuation_is_404(self):
        with pytest.raises(UrlError) as exc:
            extract_from_raw(*split("/u/AB-CD/https://e.com/a"))
        assert exc.value.status == 404


class TestParseTarget:
    def test_accepts_https(self):
        assert parse_target(b"https://e.com/a.zip") == "https://e.com/a.zip"

    def test_accepts_port_443(self):
        assert parse_target(b"https://e.com:443/a.zip") == "https://e.com:443/a.zip"

    def test_accepts_port_80(self):
        assert parse_target(b"http://e.com:80/a.zip") == "http://e.com:80/a.zip"

    def test_rejects_other_ports(self):
        with pytest.raises(UrlError) as exc:
            parse_target(b"https://e.com:8443/a.zip")
        assert exc.value.status == 400

    def test_rejects_userinfo(self):
        with pytest.raises(UrlError) as exc:
            parse_target(b"https://user:pass@e.com/a.zip")
        assert exc.value.status == 400

    def test_strips_fragment(self):
        """Browsers never send '#', so an arriving one came from a paste."""
        assert parse_target(b"https://e.com/a.zip#frag") == "https://e.com/a.zip"

    def test_strips_empty_fragment(self):
        assert parse_target(b"https://e.com/a.zip#") == "https://e.com/a.zip"

    def test_rejects_space(self):
        with pytest.raises(UrlError) as exc:
            parse_target(b"https://e.com/a b.zip")
        assert exc.value.status == 400

    def test_rejects_empty_host(self):
        with pytest.raises(UrlError) as exc:
            parse_target(b"https:///path")
        assert exc.value.status == 400

    def test_dotdot_is_preserved_for_the_origin(self):
        """'..' is the origin server's business, not ours — we relay verbatim."""
        assert parse_target(b"https://e.com/../etc/passwd") == "https://e.com/../etc/passwd"

    def test_uppercase_scheme_ok(self):
        assert parse_target(b"HTTPS://E.COM/A.ZIP").startswith("HTTPS://")
