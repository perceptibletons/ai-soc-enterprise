import random
from datetime import datetime, timezone

# ── Phishing keyword pool ──
PHISHING_SUBJECTS = [
    "Urgent: Verify Your Account", "Your account has been suspended",
    "Action Required: Update Payment Info", "Security Alert: Unauthorized Login Detected",
    "Final Warning: Password Expiration", "Confirm Your Identity Immediately",
    "Your bank account needs attention", "Click to claim your reward",
    "Invoice attached – payment overdue", "IT Department: Reset your password now",
    "Unusual sign-in activity on your account", "Your subscription will be cancelled",
]

BENIGN_SUBJECTS = [
    "Meeting notes from today", "Weekly team standup recap",
    "Project update: Q1 roadmap", "Reminder: PTO submission deadline",
    "Welcome to the platform", "Your order has shipped",
    "Invoice #4829 – thank you for your business", "Monthly newsletter",
    "New document shared with you", "Upcoming maintenance window",
]

PHISHING_BODIES = [
    "Dear user, your account has been compromised. Click here to verify your credentials immediately or your account will be suspended.",
    "Your bank account shows unusual activity. Login now to confirm your identity and reset your password.",
    "URGENT: We have detected unauthorized access. Please verify your account by clicking the link below.",
    "Your password will expire in 24 hours. Click here to reset your password and secure your account.",
    "You have won a prize! Claim now. Enter your credit card details to receive your reward.",
    "Your subscription has been cancelled. Click to reactivate and verify payment information.",
    "Alert – Multiple failed login attempts detected on your account. Verify now to regain access.",
    "Account suspension notice: Your email will be deactivated. Update your details now.",
]

BENIGN_BODIES = [
    "Hi team, please find the meeting notes attached. Let me know if you have any questions.",
    "Reminder that the Q1 performance review is scheduled for next Friday. Please come prepared.",
    "The monthly newsletter is now available. Highlights include new product features and upcoming events.",
    "Your order #38274 has been shipped and will arrive within 3-5 business days.",
    "Hello, just a quick update on the project timeline. We are on track for the April release.",
    "Please submit your PTO requests for the upcoming holiday period by end of week.",
    "Welcome aboard! Your account has been successfully created. No further action is required.",
    "The system will undergo scheduled maintenance this Sunday from 2am to 4am UTC.",
]

PHISHING_URLS = [
    "http://secure-bankupdate.com/verify", "http://account-alert.xyz/login",
    "http://paypal-secure.net/confirm", "http://update-your-info.tk/reset",
    "http://login-alert.ml/verify-account", "http://office365-login.ga/auth",
    "http://amazon-security.cf/update", "http://google-verify.gq/confirm",
]

BENIGN_URLS = [
    "https://company.com/newsletter", "https://docs.google.com/spreadsheet/abc123",
    "https://zoom.us/meeting/start/123", "https://github.com/team/project",
    "https://jira.company.com/ticket/SOC-44", "https://confluence.company.com/page/review",
    "https://mail.google.com/mail/inbox", "",
]

PHISHING_DOMAINS = [
    "secure-bankupdate.com", "account-alert.xyz", "paypal-secure.net",
    "update-your-info.tk", "login-alert.ml", "office365-login.ga",
    "amazon-security.cf", "google-verify.gq",
]

BENIGN_DOMAINS = [
    "company.com", "google.com", "zoom.us", "github.com",
    "microsoft.com", "amazon.com", "jira.company.com", "confluence.company.com",
]

USERNAMES = [
    "alice@corp.com", "bob@enterprise.net", "j.smith@securecorp.io",
    "admin@business.com", "finance@company.org", "hr.manager@firm.co",
    "john.doe@startup.ai", "sarah.k@techco.io",
]


def generate_phishing_sample():
    url = random.choice(PHISHING_URLS)
    domain = random.choice(PHISHING_DOMAINS)
    body = random.choice(PHISHING_BODIES)
    subject = random.choice(PHISHING_SUBJECTS)
    recipient = random.choice(USERNAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "phishing",
        "attack_type": "phishing",
        "subject": subject,
        "email_text": f"Subject: {subject}\n\n{body}",
        "url": url,
        "sender_domain": domain,
        "recipient": recipient,
        "label": "Phishing",
    }


def generate_benign_email_sample():
    url = random.choice(BENIGN_URLS)
    domain = random.choice(BENIGN_DOMAINS)
    body = random.choice(BENIGN_BODIES)
    subject = random.choice(BENIGN_SUBJECTS)
    recipient = random.choice(USERNAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "phishing",
        "attack_type": "phishing",
        "subject": subject,
        "email_text": f"Subject: {subject}\n\n{body}",
        "url": url,
        "sender_domain": domain,
        "recipient": recipient,
        "label": "Benign",
    }


def generate_suspicious_email_sample():
    # Mix benign body with a suspicious keyword or slightly phishy subject
    url = random.choice(BENIGN_URLS)
    domain = random.choice(BENIGN_DOMAINS)
    body = random.choice(BENIGN_BODIES) + " Please login to check."
    subject = "Action Required: " + random.choice(BENIGN_SUBJECTS)
    recipient = random.choice(USERNAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "phishing",
        "attack_type": "phishing",
        "subject": subject,
        "email_text": f"Subject: {subject}\n\n{body}",
        "url": url,
        "sender_domain": domain,
        "recipient": recipient,
        "label": "Suspicious",
    }


def generate_phishing_batch(n=10, phishing_ratio=0.5):
    samples = []
    for _ in range(n):
        r = random.random()
        if r < phishing_ratio:
            samples.append(generate_phishing_sample())
        elif r < phishing_ratio + 0.2:
            samples.append(generate_suspicious_email_sample())
        else:
            samples.append(generate_benign_email_sample())
    return samples


if __name__ == "__main__":
    for s in generate_phishing_batch(3):
        print(s)
