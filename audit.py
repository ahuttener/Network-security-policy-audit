#!/usr/bin/env python3
"""
Network Security Policy Auditor
===============================

Audits a firewall / network policy ruleset (JSON) against a set of
best-practice checks drawn from NIST SP 800-41r1 and CIS Controls v8, and
reports prioritised findings with concrete remediation.

Change-management friendly:
  * exit code 2 if any CRITICAL/HIGH finding, 1 if only MEDIUM/LOW, 0 if clean
    -> drop it into CI to fail a merge that introduces a risky rule
  * `--baseline old.json` flags rules that are NEW versus a known-good baseline

No third-party dependencies (Python 3.8+, standard library only).

Usage:
    python audit.py rules/sample-firewall.json
    python audit.py rules/sample-firewall.json --json
    python audit.py rules/new.json --baseline rules/approved.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys

# ---------------------------------------------------------------- reference data
ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5985: "WinRM", 5986: "WinRM/HTTPS"}
DB_PORTS = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 5984: "CouchDB"}
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 161: "SNMP", 512: "rexec", 513: "rlogin"}

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

ANSI = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;91m", "MEDIUM": "\033[1;93m",
        "LOW": "\033[1;94m", "OK": "\033[1;92m", "DIM": "\033[2m", "B": "\033[1m", "R": "\033[0m"}


# ---------------------------------------------------------------- ruleset helpers
def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("rules", data if isinstance(data, list) else [])


def is_internet(src):
    s = str(src).strip().lower()
    if s in ("any", "0.0.0.0/0", "::/0", "*"):
        return True
    try:
        return ipaddress.ip_network(s, strict=False).prefixlen == 0
    except ValueError:
        return False


def source_hosts(src):
    """Number of addresses the source covers (float('inf') for 'any')."""
    s = str(src).strip().lower()
    if s in ("any", "*"):
        return float("inf")
    try:
        return ipaddress.ip_network(s, strict=False).num_addresses
    except ValueError:
        return 1


def ports_of(rule):
    """Return a set of ints, or the string 'any'."""
    p = str(rule.get("port", "any")).strip().lower()
    if p in ("any", "*", "0", ""):
        return "any"
    out = set()
    for part in p.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                out.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return out or "any"


def hits(rule, port_map):
    """Which of the ports in port_map this rule exposes (label list)."""
    ports = ports_of(rule)
    if ports == "any":
        return list(port_map.values())
    return [name for num, name in port_map.items() if num in ports]


def is_allow(rule):
    return str(rule.get("action", "allow")).lower() in ("allow", "permit", "accept")


def rule_key(rule):
    return (str(rule.get("action", "")).lower(), str(rule.get("src", "")).lower(),
            str(rule.get("dst", "")).lower(), str(rule.get("port", "")).lower(),
            str(rule.get("proto", "")).lower())


# ---------------------------------------------------------------- the checks
def audit(rules):
    findings = []

    def add(check, sev, rule, title, detail, fix, ref):
        findings.append({"check": check, "severity": sev, "rule_id": rule.get("id", "?"),
                         "title": title, "detail": detail, "remediation": fix, "reference": ref})

    seen = {}
    default_deny = False

    for i, rule in enumerate(rules):
        rid = rule.get("id", i + 1)
        allow = is_allow(rule)
        net = is_internet(rule.get("src", "any"))
        ports = ports_of(rule)

        # track a trailing default-deny (deny any->any all ports)
        if not allow and net and is_internet(rule.get("dst", "any")) and ports == "any":
            default_deny = True

        if allow:
            admin = hits(rule, ADMIN_PORTS)
            db = hits(rule, DB_PORTS)
            insecure = hits(rule, INSECURE_PORTS)

            if net and admin and ports != "any":
                add("NPA001", "CRITICAL", rule,
                    "Admin service exposed to the internet",
                    f"Rule {rid} allows {', '.join(admin)} from {rule.get('src')} — remote management open to the world.",
                    "Restrict the source to a bastion host or VPN CIDR; never expose admin ports to 0.0.0.0/0.",
                    "NIST SP 800-41r1 §2.2 · CIS v8 4.4 · MITRE T1021")

            if net and db and ports != "any":
                add("NPA002", "CRITICAL", rule,
                    "Database port exposed to the internet",
                    f"Rule {rid} allows {', '.join(db)} from {rule.get('src')} — the datastore is directly reachable.",
                    "Place databases in a private subnet; allow only app-tier security groups, never the internet.",
                    "NIST SP 800-41r1 §2.4 · CIS v8 4.5 · MITRE T1190")

            if net and ports == "any":
                add("NPA003", "CRITICAL", rule,
                    "Any-source / any-port allow",
                    f"Rule {rid} allows ALL ports from {rule.get('src')} — the internet can reach every service behind it.",
                    "Replace with least-privilege rules that name each required port and source.",
                    "NIST SP 800-41r1 §2.1 · CIS v8 4.4")

            if insecure and ports != "any" and (net or source_hosts(rule.get("src", "any")) > 65536):
                add("NPA004", "HIGH", rule,
                    "Cleartext / insecure protocol permitted",
                    f"Rule {rid} permits {', '.join(insecure)} over a wide source — credentials/data travel unencrypted.",
                    "Disable the legacy service; use SSH/SFTP/SNMPv3/HTTPS equivalents instead.",
                    "NIST SP 800-41r1 §2.4 · CIS v8 4.1")

            if not net and ports != "any" and source_hosts(rule.get("src", "any")) >= 1 << 20:
                add("NPA005", "MEDIUM", rule,
                    "Overly broad source range",
                    f"Rule {rid} sources from {rule.get('src')} (~{source_hosts(rule.get('src')):,.0f} hosts) — larger than a single tier needs.",
                    "Narrow the source CIDR to the specific subnet or security group that requires access.",
                    "CIS v8 4.4")

        # NPA008 — documentation / ownership hygiene (change management)
        if not str(rule.get("desc", "")).strip() and not str(rule.get("owner", "")).strip():
            add("NPA008", "LOW", rule,
                "Undocumented rule",
                f"Rule {rid} has no description or owner — untracked rules accumulate and are never reviewed.",
                "Require a description and owner on every rule as part of change management.",
                "CIS v8 4.2")

        # NPA007 — exact duplicate / shadowed rule
        key = rule_key(rule)
        if key in seen:
            add("NPA007", "LOW", rule,
                "Redundant / shadowed rule",
                f"Rule {rid} duplicates rule {seen[key]} — dead configuration that hides intent.",
                "Remove the duplicate; keep one authoritative rule.",
                "NIST SP 800-41r1 §4.1")
        else:
            seen[key] = rid

    if rules and not default_deny:
        add("NPA006", "MEDIUM", {"id": "-"},
            "No explicit default-deny",
            "The ruleset does not end with an explicit deny any->any. Implicit behaviour varies by platform.",
            "Append an explicit `deny any any` as the final rule so the default posture is unambiguous.",
            "NIST SP 800-41r1 §2.1 · CIS v8 4.4")

    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], str(f["rule_id"])))
    return findings


def new_rules(rules, baseline):
    base = {rule_key(r) for r in baseline}
    return [r for r in rules if rule_key(r) not in base]


# ---------------------------------------------------------------- reporting
def report(policy, findings, new=None, color=True):
    c = ANSI if color else {k: "" for k in ANSI}
    out = []
    out.append(f"\n{c['B']}Network Security Policy Audit{c['R']}  —  policy: {c['B']}{policy}{c['R']}")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    summary = "  ".join(f"{c[s]} {s} {c['R']} {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    out.append(summary + "\n")

    if new:
        out.append(f"{c['B']}⟳ {len(new)} rule(s) new vs baseline{c['R']} {c['DIM']}(change-management review){c['R']}")
        for r in new:
            out.append(f"  + rule {r.get('id','?')}: {r.get('action','allow')} {r.get('src','?')} -> {r.get('dst','?')}:{r.get('port','any')}")
        out.append("")

    if not findings:
        out.append(f"{c['OK']}✔ No policy violations found.{c['R']}\n")
        return "\n".join(out)

    for f in findings:
        out.append(f"{c[f['severity']]} {f['severity']:<8}{c['R']} {c['B']}{f['check']}  {f['title']}{c['R']}  {c['DIM']}(rule {f['rule_id']}){c['R']}")
        out.append(f"    {f['detail']}")
        out.append(f"    {c['OK']}fix{c['R']} {f['remediation']}")
        out.append(f"    {c['DIM']}ref {f['reference']}{c['R']}\n")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit a firewall/network policy ruleset against NIST/CIS best practices.")
    ap.add_argument("ruleset", help="path to the ruleset JSON")
    ap.add_argument("--baseline", help="approved ruleset to diff against (flags new rules)")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    args = ap.parse_args(argv)

    # keep UTF-8 output on legacy consoles (Windows cp1252) instead of crashing
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        rules = load(args.ruleset)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read ruleset: {e}", file=sys.stderr)
        return 3

    policy = "unnamed"
    try:
        with open(args.ruleset, encoding="utf-8") as fh:
            policy = json.load(fh).get("policy", "unnamed")
    except Exception:
        pass

    findings = audit(rules)
    new = new_rules(rules, load(args.baseline)) if args.baseline else None

    if args.json:
        print(json.dumps({"policy": policy, "findings": findings,
                          "new_vs_baseline": [r.get("id") for r in (new or [])]}, indent=2))
    else:
        color = not args.no_color and sys.stdout.isatty()
        print(report(policy, findings, new, color=color))

    worst = max((SEV_ORDER[f["severity"]] for f in findings), default=0)
    return 2 if worst >= SEV_ORDER["HIGH"] else (1 if worst else 0)


if __name__ == "__main__":
    sys.exit(main())
