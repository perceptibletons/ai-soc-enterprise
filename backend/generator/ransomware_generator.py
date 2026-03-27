import random
from datetime import datetime

# ---------------- FILE NAME LISTS ---------------- #

ransomware_files = [
    "invoice_update.exe", "urgent_patch.exe", "security_update.exe", "payment_receipt.exe",
    "bank_statement.exe", "salary_slip.exe", "tax_invoice.exe", "account_verification.exe",
    "system_update_critical.exe", "windows_patch.exe", "chrome_update.exe",
    "adobe_flash_update.exe", "zoom_update.exe", "vpn_setup.exe",
    "email_attachment.exe", "document_viewer.exe", "pdf_reader_update.exe",
    "backup_restore.exe", "data_recovery.exe", "file_unlocker.exe",
    "license_keygen.exe", "crack_tool.exe", "activation_tool.exe",
    "setup_temp.exe", "installer_update.exe", "driver_update.exe",
    "security_scan.exe", "antivirus_update.exe", "patch_installer.exe",
    "system_optimizer.exe", "cleanup_tool.exe"
]

benign_files = [
    "chrome.exe", "firefox.exe", "edge.exe", "notepad.exe", "explorer.exe",
    "cmd.exe", "powershell.exe", "word.exe", "excel.exe", "powerpoint.exe",
    "teams.exe", "zoom.exe", "skype.exe", "vlc.exe", "spotify.exe",
    "discord.exe", "outlook.exe", "onenote.exe", "calculator.exe",
    "paint.exe", "taskmgr.exe", "services.exe", "svchost.exe",
    "winlogon.exe", "lsass.exe", "system_idle.exe", "runtimebroker.exe",
    "searchindexer.exe", "spoolsv.exe", "dllhost.exe"
]

# ---------------- DYNAMIC FILE NAME ---------------- #

def random_filename(base_list):
    base = random.choice(base_list)
    prefix = random.choice(["", "tmp_", "sys_", "upd_", "new_"])
    suffix = random.choice(["", "_v2", "_final", "_001", "_backup"])

    name = base.replace(".exe", "")
    return f"{prefix}{name}{suffix}.exe"


# ---------------- RANSOMWARE SAMPLE ---------------- #

def generate_ransomware_sample():
    return {
        "timestamp": datetime.utcnow().isoformat(),

        "file_name": random_filename(ransomware_files),

        "file_size_bytes": random.randint(300000, 5000000),
        "num_sections": random.randint(5, 10),
        "num_imports": random.randint(5, 30),
        "num_exports": random.randint(0, 1),

        # HIGH entropy (packed/encrypted)
        "entry_point_entropy": round(random.uniform(6.5, 8.0), 2),
        "avg_section_entropy": round(random.uniform(6.0, 8.0), 2),

        "contains_packer_signature": random.choice([True, True, False]),
        "has_digital_signature": random.choice([False, False, True]),

        "has_tls_callback": random.choice([True, False]),
        "has_anti_debug_indicators": random.choice([True, True, False]),
        "has_anti_vm_indicators": random.choice([True, False]),

        "process_activity_count": random.randint(10, 40),

        "label": "ransomware"
    }


# ---------------- BENIGN SAMPLE ---------------- #

def generate_benign_sample():
    return {
        "timestamp": datetime.utcnow().isoformat(),

        "file_name": random_filename(benign_files),

        "file_size_bytes": random.randint(20000, 800000),
        "num_sections": random.randint(3, 6),
        "num_imports": random.randint(20, 100),
        "num_exports": random.randint(0, 2),

        # LOW entropy (normal binaries)
        "entry_point_entropy": round(random.uniform(3.0, 5.5), 2),
        "avg_section_entropy": round(random.uniform(2.5, 5.0), 2),

        "contains_packer_signature": False,
        "has_digital_signature": random.choice([True, True, False]),

        "has_tls_callback": False,
        "has_anti_debug_indicators": False,
        "has_anti_vm_indicators": False,

        "process_activity_count": random.randint(1, 8),

        "label": "benign"
    }


# ---------------- SUSPICIOUS SAMPLE ---------------- #

def generate_suspicious_sample():
    # Elevated process activity or slightly high entropy on a benign file
    return {
        "timestamp": datetime.utcnow().isoformat(),

        "file_name": random_filename(benign_files),

        "file_size_bytes": random.randint(1000000, 5000000),
        "num_sections": random.randint(4, 7),
        "num_imports": random.randint(15, 60),
        "num_exports": random.randint(0, 1),

        # MEDIUM entropy
        "entry_point_entropy": round(random.uniform(5.5, 6.2), 2),
        "avg_section_entropy": round(random.uniform(5.0, 5.8), 2),

        "contains_packer_signature": random.choice([True, False]),
        "has_digital_signature": random.choice([True, False]),

        "has_tls_callback": False,
        "has_anti_debug_indicators": False,
        "has_anti_vm_indicators": False,

        "process_activity_count": random.randint(15, 25),

        "label": "suspicious"
    }


# ---------------- BATCH GENERATOR ---------------- #

def generate_batch(n=20, ransomware_ratio=0.4):
    data = []

    for _ in range(n):
        r = random.random()
        if r < ransomware_ratio:
            data.append(generate_ransomware_sample())
        elif r < ransomware_ratio + 0.2:
            data.append(generate_suspicious_sample())
        else:
            data.append(generate_benign_sample())

    return data


# ---------------- TEST RUN ---------------- #

if __name__ == "__main__":
    samples = generate_batch(5)
    for s in samples:
        print(s)