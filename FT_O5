import re

def check_phishing_email(email_subject, email_sender, email_body, email_links, email_attachments):
    red_flags = []

    if re.search(r'urgent|suspension|important|verify|immediate action', email_subject, re.IGNORECASE):
        red_flags.append("Suspicious subject line creating urgency.")
    
    if not re.match(r'^[\w.-]+@([\w-]+\.)+(com|org|net|gov)$', email_sender):
        red_flags.append("Suspicious sender domain.")
    
    if re.search(r'dear customer|dear user', email_body, re.IGNORECASE):
        red_flags.append("Generic greeting instead of recipient's name.")
    
    for link in email_links:
        if not re.match(r'^https://(www\.)?[a-zA-Z0-9.-]+\.com', link):
            red_flags.append(f"Suspicious link detected: {link}")
    
    if re.search(r'password|SSN|credit card|bank account', email_body, re.IGNORECASE):
        red_flags.append("Request for sensitive information detected.")
    
    for attachment in email_attachments:
        if attachment.endswith(('.exe', '.zip', '.scr', '.js', '.bat')):
            red_flags.append(f"Potentially dangerous attachment detected: {attachment}")
    
    if red_flags:
        report = "Potential phishing email detected! Red flags:\n"
        for flag in red_flags:
            report += f"- {flag}\n"
        report += "\nHow to Avoid Phishing Attacks:\n"
        report += "1. Verify the sender's email domain before trusting any message.\n"
        report += "2. Be cautious of urgent or threatening language in emails.\n"
        report += "3. Avoid clicking on suspicious links; hover over them to inspect the actual URL.\n"
        report += "4. Never share sensitive information via email.\n"
        report += "5. Do not open unexpected attachments, especially executable files.\n"
        report += "6. Enable two-factor authentication (2FA) to protect your accounts.\n"
        print(report)
    else:
        print("Email appears to be safe.")

test_email = {
    "subject": "Urgent: Account Suspension Notice",
    "sender": "support@bank-secure.com",
    "body": "Dear Customer, We have noticed suspicious activity on your account. To prevent suspension, click the link below and verify your credentials immediately.",
    "links": ["http://bank-secure.com/login"],
    "attachments": ["document.zip"]
}

check_phishing_email(test_email["subject"], test_email["sender"], test_email["body"], test_email["links"], test_email["attachments"])
