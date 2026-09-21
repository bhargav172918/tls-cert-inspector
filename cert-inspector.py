import socket
import ssl
import datetime
import httpx
import os
from dotenv import load_dotenv
import json

load_dotenv()

# Configuration
DOMAINS = json.loads(os.getenv("DOMAINS", "[]"))
WARNING_THRESHOLD_DAYS = os.getenv("WARNING_THRESHOLD_DAYS")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

def get_cert_expiry_days(hostname: str, port: int = 443) -> int:
    """Connects via TLS, extracts the expiration date, and returns days remaining."""
    context = ssl.create_default_context()
    
    # Connect directly to the host over TLS
    with socket.create_connection((hostname, port), timeout=5.0) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            
            # Extract 'notAfter' (e.g., "Oct 17 12:32:16 2026 GMT")
            expiry_str = cert['notAfter']
            expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            
            # Calculate remaining days from today
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days_left = (expiry_date - now).days
            return days_left

def send_teams_alert(
        domain: str, days_left: int
    ) -> None:

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": (
                        "application/vnd.microsoft.card.adaptive"
                    ),
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": (
                                    f"⚠️ *SSL Certificate Warning*: The certificate for *{domain}* expires in *{days_left} days*! Please renew it soon."
                                ),
                                "weight": "Bolder",
                                "size": "Medium",
                                "wrap": True,
                            },
                        ],
                        "$schema": (
                            "http://adaptivecards.io/schemas/"
                            "adaptive-card.json"
                        ),
                        "version": "1.4",
                    },
                }
            ],
        }

        response = httpx.post(
            TEAMS_WEBHOOK_URL,
            json=payload,
            timeout=10.0,
        )

        response.raise_for_status()


def run_check():
    print(DOMAINS)
    for domain in DOMAINS:
        try:
            days_left = get_cert_expiry_days(domain)
            print(f"[OK] {domain}: {days_left} days remaining")
            
            if days_left <= 100:
                send_teams_alert(domain, days_left)
                
        except Exception as e:
            print(f"[ERROR] Could not inspect {domain}: {e}")
            # Optional: send alert that the domain/instance is down or failing handshake

if __name__ == "__main__":
    run_check()