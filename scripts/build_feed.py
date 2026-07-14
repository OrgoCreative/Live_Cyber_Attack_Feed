#!/usr/bin/env python3
"""
Live threat-motion feed builder.

WHAT THIS DOES (in plain terms):
  1. Makes read-only HTTPS GET requests to PUBLIC, FREE threat blocklists.
  2. Counts how many malicious/attacking IPs are currently active (this number is
     REAL and changes every refresh).
  3. Generates a set of animated "attack" events (origin -> US target) for the map,
     with the VOLUME and CHURN driven by that real count.
  4. Writes the result to public/attacks.json.

WHAT THIS DOES NOT DO:
  - No credentials, API keys, secrets, or tokens of any kind.
  - No access to any of your systems, SOC, email, or private data.
  - No inbound connections; only outbound GETs to the URLs listed in FEEDS below.
  - No third-party Python packages: standard library only (urllib, json, random).

Every external URL it will ever contact is listed in FEEDS. Nothing else is called.
"""

import os, json, random, ssl, urllib.request, datetime

# ---- The ONLY external addresses this script ever contacts (all public, free, keyless) ----
FEEDS = [
    "https://lists.blocklist.de/lists/all.txt",        # attacking IPs reported by a sensor network (~hourly)
    "https://cinsscore.com/list/ci-badguys.txt",       # CI Army malicious IP list (free, keyless)
]

# Representative global attack-origin regions (lat, lng, relative weight).
# NOTE: with a keyless setup we do NOT geolocate each individual IP, so ORIGIN
# coordinates are a documented representative distribution. What is REAL and live
# is the total volume/churn from the feeds above. (A free MaxMind GeoLite2 key can
# be added later to make each origin a true per-IP geolocation — see README.)
# (lat, lng, weight) — country noted in comments
ORIGINS = [
    (39.9,116.4,26),  # China
    (55.7,37.6,18),   # Russia
    (38.0,-97.0,10),  # United States
    (20.6,78.9,8),    # India
    (-14.2,-51.9,6),  # Brazil
    (14.1,108.3,6),   # Vietnam
    (36.5,127.8,5),   # South Korea
    (32.4,53.7,5),    # Iran
    (52.1,5.3,4),     # Netherlands
    (51.2,10.4,4),    # Germany
    (-0.8,113.9,4),   # Indonesia
    (48.4,31.2,3),    # Ukraine
    (38.9,35.2,3),    # Turkey
    (9.1,8.7,3),      # Nigeria
    (54.0,-2.0,3),    # United Kingdom
]

# US target cities (lat, lng, weight ~ size/exposure). Attacks animate INTO these.
TARGETS = [
    (40.71,-74.0,10),(34.05,-118.24,9),(41.88,-87.63,8),(29.76,-95.37,7),(33.45,-112.07,5),
    (39.74,-104.99,5),(47.61,-122.33,5),(33.75,-84.39,6),(25.76,-80.19,6),(44.98,-93.27,4),
    (42.33,-83.05,4),(38.90,-77.04,7),(32.78,-96.80,6),(37.77,-122.42,6),(40.76,-111.89,3),
    (39.10,-94.58,4),(36.16,-86.78,4),(45.52,-122.68,3),(38.63,-90.20,4),(35.08,-106.65,3),
    (30.27,-97.74,5),(30.33,-81.66,4),(39.95,-75.16,5),(42.36,-71.06,5),(35.23,-80.84,4),
    (36.17,-115.14,4),(27.95,-82.46,4),(21.31,-157.86,2),(61.22,-149.90,2),(43.62,-116.20,2),
]

TYPES = ["malware","phishing","exploit"]
UA = {"User-Agent": "live-threat-feed/1.0 (public blocklist reader)"}

def fetch_count(url):
    """Return how many IP-looking lines a feed currently lists (real, live number)."""
    try:
        req = urllib.request.Request(url, headers=UA)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            text = r.read().decode("utf-8", "ignore")
        return sum(1 for ln in text.splitlines()
                   if ln[:1].isdigit() and ln.count(".") == 3)
    except Exception as e:
        print(f"  feed unavailable ({url}): {e}")
        return 0

def weighted(items):
    total = sum(w for *_, w in items)
    x = random.uniform(0, total)
    for *vals, w in items:
        x -= w
        if x <= 0:
            return vals
    return items[-1][:-1]

def main():
    active = sum(fetch_count(u) for u in FEEDS)          # REAL count of active malicious IPs right now
    now = datetime.datetime.now(datetime.timezone.utc)
    random.seed(int(now.timestamp()) // 60)              # varies minute to minute

    # Number of on-screen events scales with the real volume (bounded for the animation).
    n_events = max(30, min(140, active // 40))
    events = []
    for _ in range(n_events):
        oy, ox = weighted(ORIGINS)          # (lat, lng)
        ty, tx = weighted(TARGETS)
        jx, jy = random.uniform(-2.5, 2.5), random.uniform(-2.5, 2.5)
        events.append({
            "sLat": round(oy + jy, 3), "sLng": round(ox + jx, 3),
            "tLat": round(ty + random.uniform(-0.6, 0.6), 3),
            "tLng": round(tx + random.uniform(-0.6, 0.6), 3),
            "type": random.choice(TYPES),
        })

    out = {
        "updated": now.isoformat(timespec="seconds"),
        "activeMaliciousSources": active,   # real, from the feeds
        "eventCount": len(events),
        "note": "Volume/churn from public blocklists (blocklist.de, CINS). Origins are a "
                "representative distribution; targets are U.S. cities. No private/SOC data.",
        "events": events,
    }
    os.makedirs("public", exist_ok=True)
    with open("public/attacks.json", "w") as f:
        json.dump(out, f, separators=(",", ":"))
    print(f"active malicious sources: {active} -> {len(events)} events written")

if __name__ == "__main__":
    main()
