#!/usr/bin/env python3
"""Regenerate largeheatmap.raw: retail 2012 baseline + live BO2 players on top.

Wire format the client already parses fine (RE_REFERENCE.md #4):
zlib([u32 count][count x {s16 lat_centideg, s16 lon_centideg, u8 weight}]),
big-endian, weight in [1,255]. UI_GeneratePlaylistPopulationTextureInternal
(RPL 0x00711c50, lives in the base .rpx - not dumped in this project, so it
can't be decompiled here) turns this into the globe's orange dots.

ponytail: two experiments (1 lone point, then a 100-point jittered cluster)
both rendered *nothing*, while the untouched retail blob (2290 points, 9956
bytes) is confirmed to render - so the client is rejecting our replacement
outright (size/format/count floor unknown), not just failing to make a few
points visible. Rather than keep guessing blind at a client-side threshold we
can't decompile, this layers live players ON TOP of the retail baseline
instead of replacing it: the file stays the same order of magnitude the
client has already proven it accepts, so the globe can't regress to fully
blank even if this still doesn't surface new dots. Revert to a pure live-only
blob once the real threshold is confirmed one way or the other.

Player IPs come from bo2-demonware's own journal ("New session N from
IP:port") in the last ACTIVE_WINDOW_MIN - the same rough window matchmaking
already treats as "still around" (~5 min keepalive cadence seen live).
Geolocated via ip-api.com's free batch endpoint (no key, <=100 IPs/request,
~45 req/min) - this sends the connected IPs to a third party every run.
Swap in a local MaxMind GeoLite2-City lookup instead if that's not wanted;
geolocate() is the only function that would need to change.
"""
import json
import os
import random
import re
import struct
import subprocess
import sys
import urllib.request
import zlib

ACTIVE_WINDOW_MIN = 6
BASE_PATH = "storage/publisher/18480/largeheatmap.raw.retail2012-bak"  # relative to repo root, like every other storage/ path in this project
OUT_PATH = "storage/publisher/18480/largeheatmap.raw"

# Give each live connection enough mass to stand out against the retail
# baseline's own density without dwarfing the file (retail = 2290 points).
CLUSTER_SIZE = 40
JITTER_DEG = 0.2
LIVE_WEIGHT = 255  # max byte value: brightest tier the retail data also uses


def load_baseline() -> list[tuple[int, int, int]]:
    raw = zlib.decompress(open(BASE_PATH, "rb").read())
    count = struct.unpack_from(">I", raw, 0)[0]
    return [struct.unpack_from(">hhB", raw, 4 + i * 5) for i in range(count)]


def recent_ips() -> set[str]:
    out = subprocess.run(
        ["journalctl", "-u", "bo2-demonware", "--since", f"-{ACTIVE_WINDOW_MIN} min",
         "--no-pager", "-q"],
        capture_output=True, text=True, check=True,
    ).stdout
    return set(re.findall(r"New session \d+ from ([0-9.]+):\d+", out))


def geolocate(ips: set[str]) -> dict[str, tuple[float, float]]:
    if not ips:
        return {}
    batch = [{"query": ip, "fields": "query,status,lat,lon"} for ip in list(ips)[:100]]
    req = urllib.request.Request(
        "http://ip-api.com/batch",
        data=json.dumps(batch).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        results = json.load(r)
    return {
        row["query"]: (row["lat"], row["lon"])
        for row in results
        if row.get("status") == "success"
    }


def build_blob(points: list[tuple[int, int, int]]) -> bytes:
    body = struct.pack(">I", len(points))
    for lat_i, lon_i, weight in points:
        body += struct.pack(">hhB", lat_i, lon_i, weight)
    return zlib.compress(body)


def main() -> None:
    points = load_baseline()

    ips = recent_ips()
    geo = geolocate(ips)
    live_added = 0
    for lat, lon in geo.values():
        for _ in range(CLUSTER_SIZE):
            jlat = max(-327.68, min(327.67, lat + random.uniform(-JITTER_DEG, JITTER_DEG)))
            jlon = max(-327.68, min(327.67, lon + random.uniform(-JITTER_DEG, JITTER_DEG)))
            points.append((int(round(jlat * 100)), int(round(jlon * 100)), LIVE_WEIGHT))
            live_added += 1

    tmp = OUT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(build_blob(points))
    os.replace(tmp, OUT_PATH)  # atomic swap - publisher_file.rs reads this live

    print(f"heatmap: {len(points)} total point(s) ({live_added} live, "
          f"for {len(geo)} player(s) geolocated from {len(ips)} recent IP(s))",
          file=sys.stderr)


if __name__ == "__main__":
    main()
