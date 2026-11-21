#!/usr/bin/env python3
"""Read-only Control D snapshot. Token from CONTROL_D_API_TOKEN (any value works in
Claude Code cloud, where the proxy injects the real credential). Strips deactivation_pin.
Usage: python3 controld_snapshot.py [outdir] [--tz -7]"""
import json, os, subprocess, sys
from pathlib import Path
A = "https://api.controld.com"
tok = os.environ.get("CONTROL_D_API_TOKEN", "dummy")
out = Path(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "snapshot")
tz = sys.argv[sys.argv.index("--tz") + 1] if "--tz" in sys.argv else "-7"
out.mkdir(parents=True, exist_ok=True)

def get(path):
    r = subprocess.run(["curl", "-s", "-m", "20", "-H", f"Authorization: Bearer {tok}", A + path],
                       capture_output=True, text=True)
    return json.loads(r.stdout)

profiles = get("/profiles"); json.dump(profiles, open(out / "profiles.json", "w"))
devices = get("/devices?last_activity=1")
for d in devices["body"]["devices"]:
    d.pop("deactivation_pin", None)
json.dump(devices, open(out / "devices.json", "w"))
for n, p in [("network", "/network"), ("proxies", "/proxies")]:
    json.dump(get(p), open(out / f"{n}.json", "w"))
for d in devices["body"]["devices"]:
    json.dump(get(f"/access?device_id={d['PK']}"), open(out / f"access_{d['PK']}.json", "w"))
for p in profiles["body"]["profiles"]:
    for k in ("rules", "filters", "services", "groups"):
        json.dump(get(f"/profiles/{p['PK']}/{k}"), open(out / f"{k}_{p['PK']}.json", "w"))
here = Path(__file__).parent
subprocess.run([sys.executable, str(here / "controld_profiles.py"), str(out / "profiles.json"),
                "--tz", tz, "--devices", str(out / "devices.json")])
