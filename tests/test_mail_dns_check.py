import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import mail_dns_check as m  # noqa: E402

G = {"MX": ["aspmx.l.google.com"]}


def zone(domain, spf=None, dmarc=None, mx=None, dkim=None, extra=None):
    z = {domain: {"MX": mx if mx is not None else ["aspmx.l.google.com"],
                  "TXT": spf if spf is not None else ["v=spf1 include:_spf.google.com ~all"]}}
    if dmarc:
        z["_dmarc." + domain] = {"TXT": dmarc}
    for sel in dkim or []:
        z[f"{sel}._domainkey.{domain}"] = {"TXT": ["v=DKIM1; p=ABC"]}
    z["_spf.google.com"] = {"TXT": ["v=spf1 ip4:192.0.2.0/24 ~all"]}
    z.update(extra or {})
    return z


GOOD_DMARC = ["v=DMARC1; p=reject; rua=mailto:d@example.com"]


def run(zones, domain, sel=()):
    return m.check_domain(domain, m.FakeResolver(zones), list(sel))


def levels(r):
    return {i["check"]: i["level"] for i in r["checks"]}


class T(unittest.TestCase):
    def test_good(self):
        r = run(zone("example.com", dmarc=GOOD_DMARC, dkim=["google"]), "example.com")
        self.assertEqual(r["overall"], "OK")

    def test_no_dmarc(self):
        r = run(zone("example.com", dkim=["google"]), "example.com")
        self.assertEqual(levels(r)["DMARC"], "FAIL")
        fix = next(i["fix"] for i in r["checks"] if i["check"] == "DMARC")
        self.assertIn("v=DMARC1; p=none; rua=mailto:dmarc@example.com", fix)

    def test_dmarc_none_and_no_rua(self):
        r = run(zone("example.com", dmarc=["v=DMARC1; p=none"], dkim=["google"]), "example.com")
        self.assertEqual(levels(r)["DMARC"], "WARN")
        self.assertEqual(levels(r)["DMARC reports"], "WARN")
        self.assertEqual(r["overall"], "WARN")

    def test_double_spf(self):
        r = run(zone("example.com", spf=["v=spf1 -all", "v=spf1 ~all"], dmarc=GOOD_DMARC), "example.com")
        self.assertEqual(levels(r)["SPF"], "FAIL")

    def test_plus_all(self):
        r = run(zone("example.com", spf=["v=spf1 include:_spf.google.com +all"], dmarc=GOOD_DMARC), "example.com")
        self.assertEqual(levels(r)["SPF"], "FAIL")

    def test_question_all_and_missing_all(self):
        r = run(zone("example.com", spf=["v=spf1 include:_spf.google.com ?all"]), "example.com")
        self.assertEqual(levels(r)["SPF"], "WARN")
        r = run(zone("example.com", spf=["v=spf1 include:_spf.google.com"]), "example.com")
        self.assertEqual(levels(r)["SPF"], "WARN")

    def test_too_many_lookups(self):
        extra = {f"n{i}.example.net": {"TXT": [f"v=spf1 include:n{i+1}.example.net a mx ~all"]} for i in range(6)}
        r = run(zone("example.com", spf=["v=spf1 include:n0.example.net ~all"], dmarc=GOOD_DMARC, extra=extra),
                "example.com")
        self.assertEqual(levels(r)["SPF lookups"], "FAIL")

    def test_include_loop(self):
        extra = {"a.example.net": {"TXT": ["v=spf1 include:b.example.net ~all"]},
                 "b.example.net": {"TXT": ["v=spf1 include:a.example.net ~all"]}}
        r = run(zone("example.com", spf=["v=spf1 include:a.example.net ~all"], extra=extra), "example.com")
        self.assertEqual(levels(r)["SPF lookups"], "FAIL")

    def test_no_mx(self):
        r = run(zone("example.com", mx=[], dmarc=GOOD_DMARC), "example.com")
        self.assertEqual(levels(r)["MX"], "FAIL")
        self.assertEqual(r["overall"], "FAIL")

    def test_provider_include_missing(self):
        r = run(zone("example.com", spf=["v=spf1 ip4:192.0.2.1 ~all"], dmarc=GOOD_DMARC), "example.com")
        self.assertEqual(levels(r)["SPF provider"], "WARN")

    def test_dkim_selector(self):
        base = zone("example.com", dmarc=GOOD_DMARC, dkim=["mysel"])
        self.assertEqual(levels(run(base, "example.com"))["DKIM"], "WARN")
        self.assertEqual(levels(run(base, "example.com", ["mysel"]))["DKIM"], "OK")

    def test_dns_error(self):
        r = run({"example.com": {"ERR": True}}, "example.com")
        self.assertTrue(r["error"])
        self.assertEqual(r["overall"], "FAIL")

    def test_main_exit_codes_and_json(self):
        res = m.FakeResolver(zone("example.com", dmarc=GOOD_DMARC, dkim=["google"]))
        self.assertEqual(m.main(["example.com"], res), 0)
        self.assertEqual(m.main(["example.com", "--json"], res), 0)
        self.assertEqual(m.main([], res), 2)
        self.assertEqual(m.main(["bad_domain"], res), 2)
        self.assertEqual(m.main(["--nope"], res), 2)
        self.assertEqual(m.main(["example.net"], res), 2)  # no MX

    def test_file_and_demo(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("example.com\n# c\n\nexample.com\n")
        try:
            res = m.FakeResolver(zone("example.com", dmarc=GOOD_DMARC, dkim=["google"]))
            self.assertEqual(m.main(["--file", f.name], res), 0)
        finally:
            os.unlink(f.name)
        self.assertEqual(m.main(["--demo"]), 2)


class Fixes(unittest.TestCase):
    def test_null_mx(self):
        z = {"example.com": {"MX": [""], "TXT": ["v=spf1 -all"]},
             "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]}}
        r = run(z, "example.com")
        self.assertEqual(r["overall"], "OK")
        self.assertIn("null MX", r["checks"][0]["message"])
        self.assertNotIn("DKIM", levels(r))
        z["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com ~all"]
        z.pop("_dmarc.example.com")
        r = run(z, "example.com")
        self.assertEqual(levels(r)["SPF"], "WARN")
        self.assertEqual(levels(r)["DMARC"], "WARN")

    def test_dkim_empty_p_revoked(self):
        z = zone("example.com", dmarc=GOOD_DMARC)
        z["google._domainkey.example.com"] = {"TXT": ["v=DKIM1; p="]}
        r = run(z, "example.com")
        self.assertEqual(levels(r)["DKIM"], "WARN")
        self.assertIn("revoked", next(i["message"] for i in r["checks"] if i["check"] == "DKIM"))

    def test_dkim_wildcard(self):
        z = zone("example.com", dmarc=GOOD_DMARC)
        for s in m.COMMON_SELECTORS:
            z[f"{s}._domainkey.example.com"] = {"TXT": ["v=DKIM1; p="]}
        r = run(z, "example.com")
        self.assertIn("wildcard", next(i["message"] for i in r["checks"] if i["check"] == "DKIM"))

    def test_redirect_provider_and_ignored_with_all(self):
        z = zone("example.com", spf=["v=spf1 redirect=_spf.google.com"], dmarc=GOOD_DMARC, dkim=["google"])
        r = run(z, "example.com")
        self.assertNotIn("SPF provider", levels(r))
        self.assertEqual(r["overall"], "OK")
        z = zone("example.com", spf=["v=spf1 -all redirect=_spf.google.com"], dmarc=GOOD_DMARC, dkim=["google"])
        r = run(z, "example.com")
        self.assertIn("0 of 10", next(i["message"] for i in r["checks"] if i["check"] == "SPF lookups"))

    def test_parse_dig_status(self):
        ok = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com.\t5\tIN\tTXT\t\"v=spf1 -all\"\n"
        self.assertEqual(m.parse_dig(ok, "TXT", "example.com"), ['"v=spf1 -all"'])
        nx = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n"
        self.assertEqual(m.parse_dig(nx, "TXT", "example.com"), [])
        with self.assertRaises(m.DnsError):
            m.parse_dig(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n", "TXT", "example.com")
        with self.assertRaises(m.DnsError):
            m.parse_dig("", "TXT", "example.com")

    def test_include_target_missing_and_voids(self):
        z = zone("example.com", spf=["v=spf1 include:gone.example.net ~all"], dmarc=GOOD_DMARC)
        self.assertEqual(levels(run(z, "example.com"))["SPF lookups"], "FAIL")
        z = zone("example.com", spf=["v=spf1 include:_spf.google.com a:x1.example.net a:x2.example.net a:x3.example.net ~all"],
                 dmarc=GOOD_DMARC)
        self.assertEqual(levels(run(z, "example.com"))["SPF void lookups"], "WARN")

    def test_dmarc_walk_up(self):
        z = zone("mail.example.com", dkim=["google"], extra={"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]}})
        r = run(z, "mail.example.com")
        msg = next(i["message"] for i in r["checks"] if i["check"] == "DMARC")
        self.assertIn("inherited from _dmarc.example.com", msg)
        self.assertEqual(levels(r)["DMARC"], "OK")
        z["_dmarc.example.com"]["TXT"] = ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"]
        self.assertEqual(levels(run(z, "mail.example.com"))["DMARC"], "WARN")

    def test_dmarc_missing_p_with_rua(self):
        r = run(zone("example.com", dmarc=["v=DMARC1; rua=mailto:d@example.com"]), "example.com")
        self.assertEqual(levels(r)["DMARC"], "WARN")

    def test_spf_prefix_match_and_m365(self):
        z = zone("example.com", spf=["v=spf1x include:a.example.net", "v=spf1 ~all"], dmarc=GOOD_DMARC)
        self.assertEqual(levels(run(z, "example.com"))["SPF"], "OK")
        z = zone("example.com", mx=["x.mx.microsoft"], dmarc=GOOD_DMARC)
        self.assertIn("Microsoft 365", run(z, "example.com")["checks"][0]["message"])


if __name__ == "__main__":
    unittest.main()
