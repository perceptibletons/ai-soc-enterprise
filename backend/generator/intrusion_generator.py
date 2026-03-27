import random
from datetime import datetime, timezone

# Small seed pool just for realism; most IPs will be generated dynamically
PUBLIC_SEEDS = [
    "45.33.12.1",
    "103.5.11.9",
    "185.199.108.153",
    "13.35.37.89",
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "104.16.132.229",
    "151.101.1.69",
    "142.250.190.14",
    "23.45.67.89",
    "52.84.150.10",
    "91.198.174.192",
    "198.51.100.27",
    "203.0.113.55",
]

PRIVATE_SEEDS = [
    "192.168.5.2",
    "10.0.0.5",
    "172.16.0.20",
    "192.168.1.10",
    "10.1.2.3",
    "172.20.14.8",
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
SERVICES = ["http", "https", "smtp", "ssh", "dns", "rdp", "ftp", "other"]
FLAGS_NORMAL = ["SF", "S1", "S2", "OTHERS"]
FLAGS_MALICIOUS = ["REJ", "S0", "RSTO", "SH"]
SUSPICIOUS_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 5900, 1433, 3306]
NORMAL_PORTS = [53, 80, 443, 25, 110, 143, 993, 995, 8080]


def _random_public_ip():
    # Generate a random public-looking IPv4 address
    first = random.choice([23, 31, 45, 52, 63, 74, 87, 91, 103, 104, 129, 138, 151, 172, 185, 198, 203, 209])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_private_ip():
    choice = random.choice([10, 172, 192])
    if choice == 10:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if choice == 172:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def _pick_src_ip(malicious: bool):
    if malicious:
        # Always use dynamic public IPs or seeds for malicious/suspicious so they show on the map
        return random.choice(PUBLIC_SEEDS + [_random_public_ip() for _ in range(15)])
    # Mostly private/internal IPs for normal traffic
    return random.choice(PRIVATE_SEEDS + [_random_private_ip() for _ in range(5)])


def _pick_dst_ip(malicious: bool):
    if malicious:
        # Target internal IPs
        return random.choice(PRIVATE_SEEDS + [_random_private_ip() for _ in range(5)])
    return random.choice(PUBLIC_SEEDS + [_random_public_ip() for _ in range(5)])


def generate_intrusion_log(malicious_bias=0.5, recent_ips=None):
    """
    Creates one intrusion-feature log record.

    Features:
    - src_ip, dst_ip
    - protocol, service, flag, port
    - bytes_sent, bytes_received
    - packets_per_sec, duration
    """
    recent_ips = recent_ips or set()
    malicious = random.random() < float(malicious_bias)

    # Try to avoid repeating the same source IP too often inside one batch
    for _ in range(10):
        src_ip = _pick_src_ip(malicious)
        if src_ip not in recent_ips:
            break

    dst_ip = _pick_dst_ip(malicious)

    if malicious:
        protocol = random.choice(["TCP", "UDP"])
        service = random.choice(["ssh", "rdp", "smtp", "http", "other"])
        flag = random.choice(FLAGS_MALICIOUS)
        port = random.choice(SUSPICIOUS_PORTS)
        bytes_sent = random.randint(150000, 5000000)
        bytes_received = random.randint(0, 60000)
        packets_per_sec = random.randint(900, 5000)
        duration = round(random.uniform(0.1, 15.0), 2)
        label = "Intrusion"
    else:
        # Give a 20% chance to generate a "Suspicious" (Medium) log
        if random.random() < 0.20:
            protocol = "TCP"
            service = random.choice(["ssh", "other"])
            flag = "REJ"  # Flags rejection but not high volume
            port = random.choice(SUSPICIOUS_PORTS)
            bytes_sent = random.randint(50000, 150000)  # Moderate bytes
            bytes_received = random.randint(1000, 10000)
            packets_per_sec = random.randint(300, 900)  # Moderate PPS
            duration = round(random.uniform(5.0, 30.0), 2)
            label = "Suspicious"
        else:
            protocol = random.choice(PROTOCOLS)
            service = random.choice(SERVICES)
            flag = random.choice(FLAGS_NORMAL)
            port = random.choice(NORMAL_PORTS)
            bytes_sent = random.randint(200, 90000)
            bytes_received = random.randint(200, 120000)
            packets_per_sec = random.randint(1, 300)
            duration = round(random.uniform(1.0, 120.0), 2)
            label = "Normal"

    recent_ips.add(src_ip)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "intrusion",
        "attack_type": "intrusion",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "service": service,
        "flag": flag,
        "port": port,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "packets_per_sec": packets_per_sec,
        "duration": duration,
        "label": label,
    }


def generate_intrusion_logs(count=10, malicious_bias=0.5):
    logs = []
    recent_ips = set()

    for _ in range(int(count)):
        logs.append(generate_intrusion_log(malicious_bias=malicious_bias, recent_ips=recent_ips))

    return logs