#!/usr/bin/env python3
"""mail_dns_check - read-only SPF / DKIM / DMARC / MX posture check. Python 3.10+.

Uses dnspython if installed, else `dig +short`. Exit codes: 0 = ok, 1 = warn, 2 = fail/error.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys

OK, WARN, FAIL = 0, 1, 2
NAMES = {OK: "OK", WARN: "WARN", FAIL: "FAIL"}
COMMON_SELECTORS = ["google", "selector1", "selector2", "k1", "s1", "s2",
                    "default", "dkim", "mail", "zoho", "mxvault"]
SPF_MAX_LOOKUPS = 10
SPF_MAX_DEPTH = 10

# provider name -> (MX hostname fragments, SPF include fragment, include to suggest)
PROVIDERS = {
    "Google Workspace": (("google.com", "googlemail.com"), "_spf.google.com", "_spf.google.com"),
    "Microsoft 365": (("protection.outlook.com", "mx.microsoft"), "spf.protection.outlook.com", "spf.protection.outlook.com"),
    "Zoho": (("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au"), "zoho.", "zoho.com"),
}


class DnsError(Exception):
    """A lookup failed for a reason other than 'name does not exist'."""


# ---------------------------------------------------------------- resolvers
class Resolver:
    """Interface: txt(name) -> list[str], mx(name) -> list[str] (hostnames).
    Missing names / no records return []. Real failures raise DnsError."""

    def txt(self, name: str) -> list[str]:
        raise NotImplementedError

    def mx(self, name: str) -> list[str]:
        raise NotImplementedError

    def addr(self, name: str) -> list[str]:
        raise NotImplementedError


class DnsPythonResolver(Resolver):
    def __init__(self) -> None:
        import dns.resolver  # noqa: F401
        self.dns = __import__("dns.resolver", fromlist=["resolver"])
        self.r = self.dns.Resolver()
        self.r.lifetime = 8.0

    def _q(self, name: str, rtype: str):
        try:
            return list(self.r.resolve(name, rtype))
        except (self.dns.NXDOMAIN, self.dns.NoAnswer):
            return []
        except Exception as e:  # timeout, SERVFAIL, no nameservers
            raise DnsError(f"{rtype} lookup for {name} failed: {type(e).__name__}") from e

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._q(name, "TXT")]

    def mx(self, name: str) -> list[str]:
        return [str(r.exchange).rstrip(".").lower() for r in self._q(name, "MX")]

    def addr(self, name: str) -> list[str]:
        return [str(r) for r in self._q(name, "A") or self._q(name, "AAAA")]


def parse_dig(out: str, rtype: str, name: str) -> list[str]:
    """Parse `dig +noall +answer +comments` output. Only NOERROR / NXDOMAIN count as an answer."""
    status, recs = None, []
    for ln in out.splitlines():
        m = re.search(r"status: (\w+)", ln)
        if m:
            status = m.group(1)
        if not ln.strip() or ln.startswith(";"):
            continue
        parts = ln.split(None, 4)
        if len(parts) == 5 and parts[3].upper() == rtype:
            recs.append(parts[4].strip())
    if status not in ("NOERROR", "NXDOMAIN"):
        raise DnsError(f"{rtype} lookup for {name} failed (status: {status or 'no answer'})")
    return recs


class DigResolver(Resolver):
    def _q(self, name: str, rtype: str) -> list[str]:
        try:
            p = subprocess.run(["dig", "+noall", "+answer", "+comments", "+time=5", "+tries=2", rtype, name],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise DnsError(f"dig failed for {name}: {e}") from e
        if p.returncode != 0:
            raise DnsError(f"{rtype} lookup for {name} failed (dig exit {p.returncode})")
        return parse_dig(p.stdout, rtype, name)

    def txt(self, name: str) -> list[str]:
        return ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', r)) for r in self._q(name, "TXT")]

    def mx(self, name: str) -> list[str]:
        out = []
        for r in self._q(name, "MX"):
            parts = r.split()
            if len(parts) == 2 and parts[0].isdigit():
                out.append(parts[1].rstrip(".").lower())
        return out

    def addr(self, name: str) -> list[str]:
        return self._q(name, "A") or self._q(name, "AAAA")


def default_resolver() -> Resolver:
    try:
        return DnsPythonResolver()
    except ImportError:
        pass
    if shutil.which("dig"):
        return DigResolver()
    raise DnsError("no DNS backend: run `pip install dnspython` (recommended) or install `dig`")


# ---------------------------------------------------------------- results
class Result:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, level: int, check: str, msg: str, fix: str | None = None) -> None:
        self.items.append({"level": NAMES[level], "check": check, "message": msg, "fix": fix})

    @property
    def status(self) -> int:
        return max((FAIL if i["level"] == "FAIL" else WARN if i["level"] == "WARN" else OK
                    for i in self.items), default=OK)


# ---------------------------------------------------------------- MX
NULL_MX = "null"


def check_mx(domain: str, res: Resolver, out: Result) -> str | None:
    """Return a provider name, NULL_MX, or None."""
    hosts = res.mx(domain)
    if not hosts:
        out.add(FAIL, "MX", "no MX: inbound mail unreliable or none (implicit A fallback)",
                f"Add the MX records your mail provider gives you for {domain}.")
        return None
    if all(h == "" for h in hosts):
        out.add(OK, "MX", "domain declares it receives no mail (null MX)")
        return NULL_MX
    provider = next((n for n, (frags, _, _) in PROVIDERS.items()
                     if any(h.endswith(f) for h in hosts for f in frags)), None)
    out.add(OK, "MX", f"{len(hosts)} MX record(s); provider guess: {provider or 'other'}"
            f" ({', '.join(sorted(hosts)[:3])})")
    return provider


# ---------------------------------------------------------------- SPF
ALL_RE = re.compile(r"[+\-~?]?all")
SPF_KEYS = ("include", "a", "mx", "ptr", "exists", "redirect")


def spf_records(res: Resolver, name: str) -> list[str]:
    return [t for t in res.txt(name) if re.match(r"v=spf1(\s|$)", t, re.I)]


def walk_spf(domain: str, res: Resolver, st: dict, path: tuple[str, ...] = ()) -> None:
    """Count DNS-lookup mechanisms through include/redirect. st collects count, voids, bad, missing, targets."""
    recs = spf_records(res, domain)
    if not recs:
        st["missing"].append(domain)
        return
    terms = recs[0].lower().split()[1:]
    has_all = any(ALL_RE.fullmatch(t) for t in terms)  # RFC 7208: redirect is ignored if 'all' is present
    for term in terms:
        t = term.lstrip("+-~?")
        key = re.split(r"[:=/]", t, maxsplit=1)[0]
        if key not in SPF_KEYS or (key == "redirect" and has_all):
            continue
        st["count"] += 1
        spec = t.split(":", 1)[1] if ":" in t else ""
        if key in ("include", "redirect"):
            target = t.split("=", 1)[1] if key == "redirect" and "=" in t else spec
            st["targets"].append(target)
            if not target:
                continue
            if target in path + (domain,) or len(path) >= SPF_MAX_DEPTH:
                st["bad"] = True
            else:
                walk_spf(target, res, st, path + (domain,))
        elif key in ("a", "mx"):
            host = spec.split("/")[0] or domain
            if "%" not in host and not (res.addr(host) if key == "a" else res.mx(host)):
                st["voids"] += 1
        elif key == "exists" and spec and "%" not in spec and not res.addr(spec):
            st["voids"] += 1


def check_spf(domain: str, res: Resolver, provider: str | None, out: Result) -> None:
    recs = spf_records(res, domain)
    if not recs:
        inc = f" include:{PROVIDERS[provider][2]}" if provider in PROVIDERS else ""
        out.add(FAIL, "SPF", "no SPF record found",
                f'Add a TXT record on {domain}: "v=spf1{inc} ~all" '
                "(list every service that sends mail for you).")
        return
    if len(recs) > 1:
        out.add(FAIL, "SPF", f"{len(recs)} SPF records found; only one is allowed, receivers treat this as an error",
                f"Merge them into a single TXT record on {domain} (combine the include: parts, one 'all' at the end).")
        return
    terms = recs[0].lower().split()[1:]
    allterm = next((t for t in terms if ALL_RE.fullmatch(t)), None)
    if allterm in ("-all", "~all"):
        out.add(OK, "SPF", f"one SPF record, ends with {allterm}")
    elif allterm in ("+all", "all"):
        out.add(FAIL, "SPF", "SPF ends with +all, which lets anyone send as you",
                "Change the ending to ~all (or -all once you are sure every sender is listed).")
    elif allterm == "?all":
        out.add(WARN, "SPF", "SPF ends with ?all (neutral), which gives little protection",
                "Change ?all to ~all (soft fail) or -all (hard fail).")
    elif any(t.startswith("redirect=") for t in terms):
        out.add(OK, "SPF", "one SPF record (policy comes from redirect=)")
    else:
        out.add(WARN, "SPF", "SPF has no 'all' ending, so the policy is unclear",
                "Add ~all at the end of the SPF record.")
    st = {"count": 0, "voids": 0, "bad": False, "missing": [], "targets": []}
    walk_spf(domain, res, st)
    if st["bad"]:
        out.add(FAIL, "SPF lookups", "SPF include chain loops or is nested too deep",
                "Remove the circular include: so the chain ends; flatten nested includes if needed.")
    elif st["missing"]:
        out.add(FAIL, "SPF lookups", f"include/redirect target has no SPF record: {', '.join(st['missing'])} (permerror)",
                "Fix the spelling of that include:, or remove it if the service is no longer used.")
    elif st["count"] > SPF_MAX_LOOKUPS:
        out.add(FAIL, "SPF lookups", f"{st['count']} DNS lookups, the limit is {SPF_MAX_LOOKUPS}; receivers may reject SPF (permerror)",
                "Remove include: entries for services you no longer use, or ask each service for a shorter record.")
    else:
        out.add(OK, "SPF lookups", f"{st['count']} of {SPF_MAX_LOOKUPS} allowed DNS lookups used")
    if st["voids"] > 2:
        out.add(WARN, "SPF void lookups", f"{st['voids']} a/mx/exists lookups return nothing (limit is 2 void lookups)",
                "Remove a:, mx: or exists: entries that point at names that do not exist.")
    if provider in PROVIDERS:
        want = PROVIDERS[provider][1]
        if not any(want in i for i in st["targets"]):
            out.add(WARN, "SPF provider", f"MX points to {provider} but SPF has no include for it",
                    f"Add include:{PROVIDERS[provider][2]} to the SPF record (before the 'all').")


# ---------------------------------------------------------------- DMARC
def parse_tags(rec: str) -> dict:
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


def find_dmarc(domain: str, res: Resolver) -> tuple[list[str], str]:
    """Look at _dmarc.<domain>, then walk up the labels (no public-suffix list; stops at 2 labels)."""
    labels = domain.split(".")
    while True:
        name = ".".join(labels)
        recs = [t for t in res.txt(f"_dmarc.{name}") if re.match(r"v=dmarc1(\s*;|\s*$)", t, re.I)]
        if recs or len(labels) <= 2:
            return recs, name
        labels = labels[1:]


def check_dmarc(domain: str, res: Resolver, out: Result) -> None:
    recs, owner = find_dmarc(domain, res)
    starter = f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
    if not recs:
        out.add(FAIL, "DMARC", "no DMARC record found (Gmail and Yahoo expect one from bulk senders)",
                f'Add a TXT record on _dmarc.{domain}: "{starter}" then tighten later.')
        return
    if len(recs) > 1:
        out.add(FAIL, "DMARC", f"{len(recs)} DMARC records found at _dmarc.{owner}; only one is allowed",
                f"Delete the extra TXT records on _dmarc.{owner} and keep one.")
        return
    tags = parse_tags(recs[0])
    inherited = owner != domain
    p = (tags.get("sp") or tags.get("p", "")).lower() if inherited else tags.get("p", "").lower()
    where = f" (inherited from _dmarc.{owner}, applies as {'sp' if tags.get('sp') else 'p'}={p or 'unset'})" if inherited else ""
    if p in ("quarantine", "reject"):
        out.add(OK, "DMARC", f"policy p={p}{where}")
    elif p == "none":
        out.add(WARN, "DMARC", f"policy p=none is monitoring only; it does not tell receivers to act{where}",
                "After reading reports for a few weeks and fixing senders, move to p=quarantine, then p=reject.")
    elif not p and "rua" in tags and not inherited:
        out.add(WARN, "DMARC", "no p= tag; receivers treat this as p=none (monitoring only)",
                "Add p=none now, later p=quarantine or p=reject.")
    else:
        out.add(FAIL, "DMARC", f"missing or invalid p= policy{where}", f'Use a record like "{starter}".')
    if "rua" not in tags:
        out.add(WARN, "DMARC reports", "no rua= address, so you get no reports",
                f"Add rua=mailto:dmarc@{owner} (use a mailbox you actually read).")
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        out.add(WARN, "DMARC pct", f"pct={pct}: policy applies to only {pct}% of mail",
                "Raise pct to 100 once reports look clean.")
    if "sp" in tags and not inherited:
        out.add(OK, "DMARC sp", f"subdomain policy sp={tags['sp']}")


# ---------------------------------------------------------------- null MX (RFC 7505)
def check_null_mail(domain: str, res: Resolver, out: Result) -> None:
    spf = spf_records(res, domain)
    if len(spf) == 1 and spf[0].lower().split()[1:] == ["-all"]:
        out.add(OK, "SPF", "v=spf1 -all (nothing may send as this domain)")
    else:
        out.add(WARN, "SPF", "a no-mail domain should publish an SPF that allows nobody",
                f'Set the TXT record on {domain} to "v=spf1 -all".')
    recs, _ = find_dmarc(domain, res)
    if len(recs) == 1 and parse_tags(recs[0]).get("p", "").lower() == "reject":
        out.add(OK, "DMARC", "p=reject")
    else:
        out.add(WARN, "DMARC", "a no-mail domain should have DMARC p=reject",
                f'Add a TXT record on _dmarc.{domain}: "v=DMARC1; p=reject".')


# ---------------------------------------------------------------- DKIM
def dkim_state(recs: list[str]) -> str:
    """'ok' for a usable key, 'revoked' for an empty p=, '' for nothing."""
    state = ""
    for r in recs:
        t = parse_tags(r)
        if "p" not in t or t.get("v", "DKIM1").upper() != "DKIM1":
            continue
        if t["p"]:
            return "ok"
        state = "revoked"
    return state


def check_dkim(domain: str, res: Resolver, extra: list[str], out: Result) -> None:
    sels = list(dict.fromkeys(extra + COMMON_SELECTORS))
    seen = {s: res.txt(f"{s}._domainkey.{domain}") for s in sels}
    uniq = {tuple(sorted(v)) for v in seen.values()}
    if len(sels) > 1 and len(uniq) == 1 and next(iter(uniq)):
        out.add(WARN, "DKIM", "wildcard TXT, selector scan unreliable (every selector returned the same record)",
                "Pass your real selector with --selector and check it in your mail provider's admin console.")
        return
    states = {s: dkim_state(v) for s, v in seen.items()}
    found = [s for s, v in states.items() if v == "ok"]
    revoked = [s for s, v in states.items() if v == "revoked"]
    if found:
        out.add(OK, "DKIM", f"found selector(s): {', '.join(found)}")
    elif revoked:
        out.add(WARN, "DKIM", f"revoked key (empty p=) at selector(s): {', '.join(revoked)}; no working key found",
                "Publish a new key for that selector from your mail provider's admin console.")
    else:
        out.add(WARN, "DKIM", "could not find DKIM (selectors cannot be listed; only common names were tried)",
                "Pass your selector with --selector (find it in the provider's admin page or a mail's DKIM-Signature s= tag). "
                "If DKIM is not turned on, enable it in your mail provider's admin console.")


# ---------------------------------------------------------------- driver
def check_domain(domain: str, res: Resolver, selectors: list[str]) -> dict:
    out = Result()
    try:
        provider = check_mx(domain, res, out)
        if provider == NULL_MX:
            check_null_mail(domain, res, out)
        else:
            check_spf(domain, res, provider, out)
            check_dmarc(domain, res, out)
            check_dkim(domain, res, selectors, out)
    except DnsError as e:
        out.add(FAIL, "DNS", str(e), "Check your network or resolver and try again.")
        return {"domain": domain, "overall": "FAIL", "error": True, "checks": out.items}
    return {"domain": domain, "overall": NAMES[out.status], "error": False, "checks": out.items}


def render(r: dict) -> str:
    lines = [r["domain"]]
    for i in r["checks"]:
        lines.append(f"  {i['level']:<4} {i['check']}: {i['message']}")
        if i["fix"]:
            lines.append(f"       Fix: {i['fix']}")
    lines.append(f"  OVERALL: {r['overall']}")
    return "\n".join(lines)


def read_domains(args) -> list[str]:
    doms = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            doms += [ln.split("#")[0].strip() for ln in f]
    clean = []
    for d in doms:
        d = d.strip().lower().rstrip(".")
        if d and d not in clean:
            if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", d):
                raise ValueError(f"not a valid domain name: {d!r}")
            clean.append(d)
    return clean


def main(argv: list[str] | None = None, resolver: Resolver | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only SPF/DKIM/DMARC/MX check with plain-English fixes.")
    ap.add_argument("domains", nargs="*", help="domain(s) to check")
    ap.add_argument("--file", help="text file with one domain per line")
    ap.add_argument("--selector", action="append", default=[], help="extra DKIM selector (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--demo", action="store_true", help="run against built-in FAKE zones, no network")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        if args.demo:
            resolver = FakeResolver(DEMO_ZONES)
            args.domains = args.domains or list(DEMO_DOMAINS)
            args.selector = args.selector or ["google"]
        domains = read_domains(args)
        if not domains:
            print("error: give at least one domain or --file", file=sys.stderr)
            return 2
        resolver = resolver or default_resolver()
    except (ValueError, OSError, DnsError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    results = [check_domain(d, resolver, args.selector) for d in domains]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if args.demo:
            print("DEMO: fake zones built into the tool, no DNS was queried.\n")
        print("\n\n".join(render(r) for r in results))
    levels = {r["overall"] for r in results}
    return 2 if "FAIL" in levels else 1 if "WARN" in levels else 0


# ---------------------------------------------------------------- fake zones (tests + --demo)
class FakeResolver(Resolver):
    """zones: {name: {"TXT": [...], "MX": [...], "ERR": True}}. Unknown names are empty."""

    def __init__(self, zones: dict) -> None:
        self.zones = zones

    def _get(self, name: str, rtype: str) -> list[str]:
        z = self.zones.get(name.lower(), {})
        if z.get("ERR"):
            raise DnsError(f"simulated failure for {name}")
        return list(z.get(rtype, []))

    def txt(self, name: str) -> list[str]:
        return self._get(name, "TXT")

    def mx(self, name: str) -> list[str]:
        return self._get(name, "MX")

    def addr(self, name: str) -> list[str]:
        return self._get(name, "A")


DEMO_DOMAINS = ["good.example.com", "nodmarc.example.org", "nomail.example.net"]
DEMO_ZONES = {
    "good.example.com": {"MX": ["aspmx.l.google.com"],
                         "TXT": ["v=spf1 include:_spf.google.com -all"]},
    "_dmarc.good.example.com": {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@good.example.com"]},
    "google._domainkey.good.example.com": {"TXT": ["v=DKIM1; k=rsa; p=MIIBFAKE"]},
    "_spf.google.com": {"TXT": ["v=spf1 ip4:192.0.2.0/24 ~all"]},
    "nodmarc.example.org": {"MX": ["example-org.mail.protection.outlook.com"],
                            "TXT": ["v=spf1 include:spf.protection.outlook.com ~all"]},
    "nomail.example.net": {"MX": [""], "TXT": ["v=spf1 -all"]},
    "_dmarc.nomail.example.net": {"TXT": ["v=DMARC1; p=reject"]},
    "spf.protection.outlook.com": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
}

if __name__ == "__main__":
    sys.exit(main())
