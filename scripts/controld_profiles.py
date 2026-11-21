#!/usr/bin/env python3
"""Summarise a Control D GET /profiles response.

Usage:
  python3 controld_profiles.py profiles.json [--tz -6] [--csv out.csv] [--diff PK_A PK_B]
  cat profiles.json | python3 controld_profiles.py -

Input may be the raw API JSON ({"body": {"profiles": [...]}}) or a bare list.
"""
import argparse, csv, json, sys
from datetime import datetime, timezone, timedelta

DA = {0: "block", 1: "bypass", 2: "spoof", 3: "redirect"}
OPT_NOTES = {
    "ttl_blck": "TTL blocked", "ttl_spff": "TTL spoofed", "ttl_pass": "TTL passed",
    "block_rfc1918": "block RFC1918 answers", "no_dnssec": "DNSSEC option",
    "ai_malware": "AI malware threshold", "b_resp": "block response mode",
    "block_attacks": "attack filter", "ecs_subnet": "EDNS client subnet", "dns64": "DNS64",
}


def load(path):
    raw = json.load(sys.stdin if path == "-" else open(path))
    if isinstance(raw, list):
        return raw
    return raw.get("body", raw).get("profiles", [])


def norm(p, tz):
    prof = p.get("profile", {})
    opts = {o["PK"]: o["value"] for o in prof.get("opt", {}).get("data", [])}
    da = prof.get("da", {})
    locked = bool(p.get("lock") or p.get("lock_status"))
    return {
        "pk": p["PK"], "name": p.get("name"),
        "rules": prof.get("rule", {}).get("count", 0),
        "svc": prof.get("svc", {}).get("count", 0),
        "grp": prof.get("grp", {}).get("count", 0),
        "flt": prof.get("flt", {}).get("count", 0),
        "cflt": prof.get("cflt", {}).get("count", 0),
        "ipflt": prof.get("ipflt", {}).get("count", 0),
        "default": DA.get(da.get("do"), da.get("do")),
        "da_enabled": da.get("status") == 1,
        "disabled": bool(p.get("disable")),
        "locked": locked, "lock_msg": p.get("lock_message"),
        "updated": datetime.fromtimestamp(p["updated"], timezone(timedelta(hours=tz))),
        "opts": opts,
    }


def table(rows):
    cols = ["name", "pk", "rules", "svc", "grp", "flt", "cflt", "ipflt", "default", "locked", "updated"]
    fmt = lambda r, c: r[c].strftime("%Y-%m-%d %H:%M") if c == "updated" else str(r[c])
    w = {c: max(len(c), *(len(fmt(r, c)) for r in rows)) for c in cols}
    print("  ".join(c.ljust(w[c]) for c in cols))
    print("  ".join("-" * w[c] for c in cols))
    for r in rows:
        print("  ".join(fmt(r, c).ljust(w[c]) for c in cols))


def option_matrix(rows):
    keys = sorted({k for r in rows for k in r["opts"]})
    print("\nOptions matrix ('-' = not set)")
    names = [r["name"][:14] for r in rows]
    print("option".ljust(15), "  ".join(n.ljust(14) for n in names))
    for k in keys:
        print(k.ljust(15), "  ".join(str(r["opts"].get(k, "-")).ljust(14) for r in rows),
              f"  # {OPT_NOTES.get(k, '')}")


def diff(rows, a, b):
    ra = next(r for r in rows if r["pk"] == a)
    rb = next(r for r in rows if r["pk"] == b)
    print(f"\nDiff {ra['name']} -> {rb['name']}")
    for k in ("rules", "svc", "grp", "flt", "cflt", "ipflt", "default"):
        if ra[k] != rb[k]:
            print(f"  {k}: {ra[k]} -> {rb[k]}")
    for k in sorted(set(ra["opts"]) | set(rb["opts"])):
        if ra["opts"].get(k) != rb["opts"].get(k):
            print(f"  opt.{k}: {ra['opts'].get(k, '-')} -> {rb['opts'].get(k, '-')}")


def devices_report(path, rows, tz):
    byp = {r["pk"]: r for r in rows}
    raw = json.load(open(path))
    devs = raw.get("body", raw).get("devices", [])
    ts = lambda t: datetime.fromtimestamp(t, timezone(timedelta(hours=tz))).strftime("%Y-%m-%d %H:%M") if t else "-"
    print("\nDevices (profile joined; secrets such as deactivation_pin are NOT printed)")
    for d in sorted(devs, key=lambda d: d["ts"]):
        pr = d.get("profile", {})
        cur = byp.get(pr.get("PK"))
        stale = ""
        if cur and cur["updated"].timestamp() != pr.get("updated"):
            stale = "  [profile changed since device snapshot]"
        hm, ct, dd = d.get("host_metadata", {}), d.get("ctrld", {}), d.get("ddns", {})
        print(f"- {d['name']} ({d['PK']}) icon={d.get('icon')} created={ts(d['ts'])} "
              f"profile={pr.get('name')} ({pr.get('PK')}) ip_count={d.get('ip_count')} "
              f"learn_ip={d.get('learn_ip')} status={d.get('status')}{stale}")
        if hm:
            print(f"    host: {hm.get('os')} {hm.get('chassis_type')} user={hm.get('username')} observed={ts(hm.get('observed_at'))}")
        if ct:
            print(f"    ctrld: {ct.get('version')} target={ct.get('version_target')} update={ct.get('update_status')} last_fetch={ts(ct.get('last_fetch'))}")
        if dd:
            print(f"    ddns: {dd.get('hostname')} -> {dd.get('record')}")
        if "deactivation_pin" in d:
            print("    deactivation_pin: set (redacted)")
    used = {d.get("profile", {}).get("PK") for d in devs}
    print("\nProfiles with no device attached:", ", ".join(r["name"] for r in rows if r["pk"] not in used))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--tz", type=float, default=-6, help="UTC offset hours (default -6)")
    ap.add_argument("--csv")
    ap.add_argument("--diff", nargs=2, metavar=("PK_A", "PK_B"))
    ap.add_argument("--devices", help="GET /devices JSON; joins devices to profiles")
    a = ap.parse_args()

    rows = sorted((norm(p, a.tz) for p in load(a.file)), key=lambda r: r["updated"], reverse=True)
    table(rows)
    option_matrix(rows)
    for r in rows:
        if r["locked"]:
            print(f"\nLOCKED: {r['name']} ({r['pk']}): {r['lock_msg']!r}")
    if a.diff:
        diff(rows, *a.diff)
    if a.devices:
        devices_report(a.devices, rows, a.tz)
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            keys = [k for k in rows[0] if k != "opts"]
            w = csv.DictWriter(f, keys + ["opts"])
            w.writeheader()
            for r in rows:
                w.writerow({**r, "opts": json.dumps(r["opts"])})


if __name__ == "__main__":
    main()
