#!/usr/bin/env python3
"""Aggregate 7-day activity per device. In memory only; prints counts and top blocked names.
Usage: python3 controld_activity.py [days=7]"""
import collections, datetime as d, json, os, subprocess, sys, urllib.parse
tok = os.environ.get("CONTROL_D_API_TOKEN", "dummy")
days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
def get(u):
    return json.loads(subprocess.run(["curl", "-s", "-m", "30", "-H", f"Authorization: Bearer {tok}", u],
                                     capture_output=True, text=True).stdout)
ep = get("https://api.controld.com/users")["body"]["stats_endpoint"]
base = f"https://{ep}.analytics.controld.com/v2/activity-log"
now = d.datetime.now(d.timezone.utc); st = now - d.timedelta(days=days)
iso = lambda t: t.isoformat().replace("+00:00", "Z")
for dev in get("https://api.controld.com/devices")["body"]["devices"]:
    qs = []
    for p in range(40):
        q = urllib.parse.urlencode({"startTime": iso(st), "endTime": iso(now), "page": p,
                                    "pageSize": 200, "endpointId": dev["PK"]})
        page = get(f"{base}?{q}").get("body", {}).get("queries", [])
        if not page: break
        qs += page
    act = collections.Counter(x.get("action") for x in qs)
    top = collections.Counter(x.get("question") for x in qs if x.get("action") == 0).most_common(5)
    print(f"{dev['name']}: n={len(qs)}{' (page cap)' if len(qs) >= 8000 else ''} actions={dict(act)} blocked={top}")
