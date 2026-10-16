# mail-dns-check

A small command-line tool that checks the SPF, DKIM, DMARC and MX records of your domain and tells you, in plain English, what to fix.

## The problem

Small firms set up Google Workspace, Microsoft 365 or a newsletter tool, and then their mail lands in junk
because SPF, DKIM or DMARC is missing or wrong. Job titles like these appear in public freelance job posts
(paraphrased, Oct 2026):

- "Gmail spam/DNS"
- "email deliverability"
- "Setup Gmail Bisnis Profesional - MX/SPF/DKIM/DMARC"

Since February 2024, Gmail and Yahoo have asked more of senders. As far as we know, from Google's
"Email sender guidelines" page: all senders to Gmail should have SPF or DKIM, and bulk senders (about 5,000 or
more messages a day to Gmail) need SPF, DKIM and a DMARC record. Read that page for the current wording, it can change.

## What it does / does NOT do

Does:
- Looks up MX, SPF, DMARC and DKIM records for one or more domains.
- Prints OK / WARN / FAIL for each check, with a "Fix:" line and the record to add where possible.

Does not:
- Change your DNS, send any mail, or read any mailbox.
- Find DKIM selectors you do not tell it. Selectors cannot be listed in DNS, so it tries common names
  (google, selector1, selector2, k1, s1, s2, default, dkim, mail, zoho, mxvault) plus any `--selector` you pass.
- Check MTA-STS or BIMI.

Only ordinary public DNS lookups leave your machine.

## Why use this instead of a web checker

- Check many domains at once from a file (`--file domains.txt`).
- `--json` and exit codes make it usable from cron or CI.
- Free, scriptable, no account, and it runs on your own machine.

## Quick start

```
pip install dnspython        # recommended; without it the tool falls back to the `dig` command
python3 mail_dns_check.py --demo
python3 mail_dns_check.py example.com --selector google
```

Needs Python 3.10+. Single file: `mail_dns_check.py`.

## Example output

This is FAKE output from `--demo`. It runs against built-in made-up zones for example.com / example.org, offline.

```
DEMO: fake zones built into the tool, no DNS was queried.

good.example.com
  OK   MX: 1 MX record(s); provider guess: Google Workspace (aspmx.l.google.com)
  OK   SPF: one SPF record, ends with -all
  OK   SPF lookups: 1 of 10 allowed DNS lookups used
  OK   DMARC: policy p=quarantine
  OK   DKIM: found selector(s): google
  OVERALL: OK

nodmarc.example.org
  OK   MX: 1 MX record(s); provider guess: Microsoft 365 (example-org.mail.protection.outlook.com)
  OK   SPF: one SPF record, ends with ~all
  OK   SPF lookups: 1 of 10 allowed DNS lookups used
  FAIL DMARC: no DMARC record found (Gmail and Yahoo expect one from bulk senders)
       Fix: Add a TXT record on _dmarc.nodmarc.example.org: "v=DMARC1; p=none; rua=mailto:dmarc@nodmarc.example.org" then tighten later.
  WARN DKIM: could not find DKIM (selectors cannot be listed; only common names were tried)
       Fix: Pass your selector with --selector (find it in the provider's admin page or a mail's DKIM-Signature s= tag). If DKIM is not turned on, enable it in your mail provider's admin console.
  OVERALL: FAIL

nomail.example.net
  OK   MX: domain declares it receives no mail (null MX)
  OK   SPF: v=spf1 -all (nothing may send as this domain)
  OK   DMARC: p=reject
  OVERALL: OK
```

## Options

- `DOMAIN ...` one or more domains.
- `--file domains.txt` one domain per line (`#` comments allowed).
- `--selector NAME` extra DKIM selector to try; repeat for several.
- `--json` machine-readable output.
- `--demo` offline run on fake zones, no network.

Checks in short: SPF must be a single record ending `~all` or `-all` (`+all` is FAIL, `?all` or none is WARN),
with at most 10 DNS lookups counted through nested includes, and an include for your mail provider.
DMARC must exist with a `p=` policy (`p=none` is WARN, monitoring only) and `rua=` for reports.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | all OK |
| 1 | warnings |
| 2 | any FAIL, bad arguments, or a DNS error |

Run the tests (no network needed): `python3 -m pytest tests` or `python3 -m unittest discover -s tests`.

## Limits

- DNS only. Passing every check is not a deliverability guarantee.
- Sender reputation, message content, IP blocklists, reverse DNS and mailbox-provider filtering are not checked.
- A missing DKIM result may just mean an unusual selector name.
- The SPF lookup count is an estimate: it follows include and redirect, but does not expand the extra address lookups an `mx` mechanism can cause.
- Provider detection is a guess from MX hostnames.

## Licence

MIT, see `LICENSE`.

Need this done for your business? Simplicity Idea Tech — info@simplicityideatech.com
