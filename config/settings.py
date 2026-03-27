import os

attack_analysis = {
    "SQL Injection": {
        "analysis": "Possible SQL injection attack detected targeting database queries.",
        "response": "Block source IP and inspect database logs."
    },
    
    "Brute Force": {
        "analysis": "Multiple login attempts detected indicating possible password brute force attack.",
        "response": "Temporarily block IP and enable account lockout policy."
    },

    "DDoS": {
        "analysis": "Unusual high traffic volume detected which may indicate a distributed denial of service attack.",
        "response": "Rate limit traffic and activate DDoS protection."
    },

    "Phishing": {
        "analysis": "Suspicious email activity detected attempting credential theft.",
        "response": "Alert user and block malicious email source."
    },

    "Ransomware": {
        "analysis": "File exhibits characteristics similar to ransomware (high entropy, packer signatures, high process activity).",
        "response": "Isolate host and begin incident response playbook for ransomware."
    },

    "Intrusion": {
        "analysis": "Network flow shows suspicious traffic (high packets/sec or abnormal packet sizes) consistent with an intrusion attempt.",
        "response": "Investigate source IP and block if confirmed malicious; collect PCAP for analysis."
    },

    "Insider Threat": {
        "analysis": "User activity deviates from baseline (odd login hours and many file accesses). May indicate misuse of privileges.",
        "response": "Review user activity, restrict access, and escalate to SOC analyst for deeper review."
    }
}

mitre_mapping = {
    "Phishing": {
        "technique": "Phishing",
        "mitre_id": "T1566",
        "tactic": "Initial Access"
    },

    "Ransomware": {
        "technique": "Data Encrypted for Impact",
        "mitre_id": "T1486",
        "tactic": "Impact"
    },

    "Intrusion": {
        "technique": "Exploit Public-Facing Application",
        "mitre_id": "T1190",
        "tactic": "Initial Access"
    },

    "Insider Threat": {
        "technique": "Exfiltration Over Web Services",
        "mitre_id": "T1567",
        "tactic": "Exfiltration"
    },

    "Brute Force": {
        "technique": "Brute Force",
        "mitre_id": "T1110",
        "tactic": "Credential Access"
    },

    "SQL Injection": {
        "technique": "Exploit Public-Facing Application",
        "mitre_id": "T1190",
        "tactic": "Initial Access"
    }
}

BACKEND_URL_DEFAULT = os.getenv("AI_SOC_BACKEND_URL", "http://127.0.0.1:8000")
