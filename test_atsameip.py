"""Offline tests for the intercode.info 'at same IP' (atsameip) primary source.

Fully offline (no network): we feed hand-built HTML that mirrors the real page
layout to app._names_from_atsameip_html() and assert that:

  * same-IP `<a class="domain">` anchors are extracted (from href, or text);
  * everything under the "sites on IP-addresses nearby" heading is EXCLUDED
    (those domains live on other IPs and would be false positives);
  * junk (bare IPs, non-FQDN labels) is rejected via clean_hostname();
  * the block-detection heuristic flags 429/403 and challenge pages.
"""
import os
import tempfile

os.environ.setdefault("RECON_PASS", "test")
os.environ["RECON_RESULTS_DIR"] = tempfile.mkdtemp(prefix="recon_ats_test_")

import app

# Mirrors the real markup: each same-IP result is an <a class="domain"> (with a
# companion whois <a class="pop">); long names are wrapped in <acronym>; the
# neighbour-IP section starts at the "sites on IP-addresses nearby" heading.
SAMPLE = """
<html><body>
<h2>Domains hosted on the same IP-address</h2>
<a href="http://good-one.com/" target="_blank" class="domain" rel="nofollow">good-one.com</a>
<a href="?domain=good-one.com&amp;sia" class="pop">whois</a><br/>
<a href="http://sub.good-two.org/" target="_blank" class="domain" rel="nofollow">sub.good-two.org</a><br/>
<a href="http://verylongdomain.example.net/" class="domain"><acronym title="x">verylo&hellip;</acronym></a><br/>
<a class="domain">text-only.example.io</a><br/>
<a href="http://8.8.8.8/" class="domain">8.8.8.8</a><br/>
<a href="http://nodot/" class="domain">nodot</a><br/>
<h2 style="">sites on IP-addresses nearby</h2>
<a href="http://nearby-false.com/" class="domain">nearby-false.com</a><br/>
<a href="?domain=neighbour.net&amp;sia" class="point_in">neighbour.net</a>
</body></html>
"""

EXPECTED = {
    "good-one.com",
    "sub.good-two.org",
    "verylongdomain.example.net",  # recovered from href despite acronym text
    "text-only.example.io",        # recovered from anchor text (no href)
}


class _Resp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


def main():
    got = app._names_from_atsameip_html(SAMPLE)
    print(f"[A] parsed same-IP names: {sorted(got)}")
    assert got == EXPECTED, f"parse mismatch: {sorted(got)} != {sorted(EXPECTED)}"

    # Nearby-section domains must never leak in.
    assert "nearby-false.com" not in got, "nearby-IP domain leaked past the cut"
    assert "neighbour.net" not in got, "point_in (nearby) domain leaked"
    # Junk rejected.
    assert "8.8.8.8" not in got and "nodot" not in got, "junk name not rejected"

    # Empty / missing input is safe.
    assert app._names_from_atsameip_html("") == set()
    assert app._names_from_atsameip_html("<html>no anchors here</html>") == set()

    # A page with no nearby heading returns all same-IP anchors.
    no_nearby = ('<a href="http://a.example.com/" class="domain">a.example.com</a>'
                 '<a href="http://b.example.com/" class="domain">b.example.com</a>')
    assert app._names_from_atsameip_html(no_nearby) == {"a.example.com", "b.example.com"}
    print("[B] cut/junk/empty handling OK")

    # Block detection.
    assert app._ats_looks_blocked(_Resp(429)) is True
    assert app._ats_looks_blocked(_Resp(403)) is True
    assert app._ats_looks_blocked(_Resp(200, "please solve the CAPTCHA to continue")) is True
    assert app._ats_looks_blocked(_Resp(200, "<a class='domain'>ok.com</a>")) is False
    print("[C] block detection OK")

    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
