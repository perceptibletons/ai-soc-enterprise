import os
import json
import re
import requests

IP_CACHE_PATH = os.path.join("logs", "ip_geo_cache.json")

def load_ip_cache():
    try:
        if os.path.exists(IP_CACHE_PATH):
            with open(IP_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_ip_cache(cache):
    try:
        os.makedirs(os.path.dirname(IP_CACHE_PATH), exist_ok=True)
        with open(IP_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def seed_demo_ips(cache):
    seeds = {
        "45.33.12.1": {"lat": 37.7749, "lon": -122.4194, "country": "US"},
        "103.5.11.9": {"lat": 19.075984, "lon": 72.877656, "country": "IN"},
        "192.168.5.2": {"lat": 51.5074, "lon": -0.1278, "country": "GB"},
        "10.0.0.5": {"lat": 48.8566, "lon": 2.3522, "country": "FR"},
        "8.8.8.8": {"lat": 37.751, "lon": -97.822, "country": "US"},
        "1.1.1.1": {"lat": -33.494, "lon": 143.2104, "country": "AU"},
        "185.199.108.153": {"lat": 37.786, "lon": -122.399, "country": "US"},
        "13.35.37.89": {"lat": 47.610, "lon": -122.107, "country": "US"}
    }
    for k, v in seeds.items():
        if k not in cache:
            cache[k] = v
    return cache

_ipv4_re = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
def is_ipv4(addr):
    return bool(_ipv4_re.match(str(addr).strip()))

ip_cache = load_ip_cache()
ip_cache = seed_demo_ips(ip_cache)
save_ip_cache(ip_cache)

import hashlib

def geolocate_ip(ip):
    if not ip:
        return None
    ip = str(ip).strip()
    if not is_ipv4(ip):
        return None
    if ip in ip_cache:
        return ip_cache[ip]
    
    # For the AI SOC demo, securely generate deterministic coordinates instantly 
    # based on the IP instead of blocking the UI thread with HTTP requests.
    h = hashlib.md5(ip.encode('utf-8')).hexdigest()
    lat = -80 + (int(h[:8], 16) % 16000) / 100.0
    lon = -180 + (int(h[8:16], 16) % 36000) / 100.0
    
    rec = {"lat": lat, "lon": lon, "country": "SIMULATED"}
    ip_cache[ip] = rec
    return rec
