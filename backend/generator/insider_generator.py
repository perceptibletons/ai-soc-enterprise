import random
from datetime import datetime, timezone

USERNAMES = [
    "alice.j", "bob.smith", "carol.hr", "david.ops",
    "eve.finance", "frank.it", "grace.admin", "henry.dev",
    "irene.qa", "james.soc", "kate.support", "leo.manager",
]

DEPARTMENTS = [
    "Finance", "IT", "HR", "Operations", "Engineering",
    "Security", "Legal", "Executive", "Support", "Marketing",
]

ASSET_TYPES = [
    "financial_reports", "employee_records", "source_code",
    "customer_data", "network_configs", "contracts",
    "product_roadmaps", "executive_emails", "audit_logs",
]


def generate_insider_threat_sample():
    """Off-hours access + high file count = insider threat."""
    # Login at suspicious hours: midnight–2am or 10pm–midnight
    hour = random.choice(list(range(0, 3)) + list(range(21, 24)))
    minute = random.randint(0, 59)
    file_access_count = random.randint(55, 350)
    activity_score = random.randint(75, 100)
    username = random.choice(USERNAMES)
    dept = random.choice(DEPARTMENTS)
    asset = random.choice(ASSET_TYPES)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "insider",
        "attack_type": "insider",
        "username": username,
        "department": dept,
        "login_hour": hour,
        "login_minute": minute,
        "file_access_count": file_access_count,
        "activity_score": activity_score,
        "accessed_asset_type": asset,
        "vpn_used": random.choice([True, False]),
        "label": "Insider Threat",
    }


def generate_normal_user_sample():
    """Business-hours login + low file count = normal."""
    hour = random.randint(8, 18)
    minute = random.randint(0, 59)
    file_access_count = random.randint(0, 30)
    activity_score = random.randint(0, 50)
    username = random.choice(USERNAMES)
    dept = random.choice(DEPARTMENTS)
    asset = random.choice(ASSET_TYPES)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "insider",
        "attack_type": "insider",
        "username": username,
        "department": dept,
        "login_hour": hour,
        "login_minute": minute,
        "file_access_count": file_access_count,
        "activity_score": activity_score,
        "accessed_asset_type": asset,
        "vpn_used": random.choice([True, False]),
        "label": "Normal",
    }


def generate_suspicious_sample():
    """Edge-case: slightly elevated but not clearly malicious."""
    hour = random.randint(6, 8)
    minute = random.randint(0, 59)
    file_access_count = random.randint(25, 55)
    activity_score = random.randint(55, 80)
    username = random.choice(USERNAMES)
    dept = random.choice(DEPARTMENTS)
    asset = random.choice(ASSET_TYPES)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "insider",
        "attack_type": "insider",
        "username": username,
        "department": dept,
        "login_hour": hour,
        "login_minute": minute,
        "file_access_count": file_access_count,
        "activity_score": activity_score,
        "accessed_asset_type": asset,
        "vpn_used": random.choice([True, False]),
        "label": "Suspicious",
    }


def generate_insider_batch(n=10, threat_ratio=0.4):
    samples = []
    for _ in range(n):
        r = random.random()
        if r < threat_ratio:
            samples.append(generate_insider_threat_sample())
        elif r < threat_ratio + 0.2:
            samples.append(generate_suspicious_sample())
        else:
            samples.append(generate_normal_user_sample())
    return samples


if __name__ == "__main__":
    for s in generate_insider_batch(3):
        print(s)
