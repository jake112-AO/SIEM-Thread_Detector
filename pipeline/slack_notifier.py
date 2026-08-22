import os
import requests
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


def send_slack_alert(alert: dict):
    """
    Sends a formatted notification to Slack for a single alert.
    Only meant to be called for critical-severity alerts - Slack
    should be reserved for things that genuinely need immediate
    human attention, not a firehose of every low-severity event.
    """
    if not WEBHOOK_URL:
        print("SLACK_WEBHOOK_URL not set - skipping Slack notification")
        return

    technique_str = ", ".join(alert.get("mitre.technique", []))
    tactic_str = ", ".join(alert.get("mitre.tactic", []))

    message = {
        "text": f"🚨 CRITICAL ALERT: {alert.get('rule.name')}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 CRITICAL: {alert.get('rule.name')}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{alert.get('source.ip')}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{alert.get('severity')}"},
                    {"type": "mrkdwn", "text": f"*MITRE Technique:*\n{technique_str}"},
                    {"type": "mrkdwn", "text": f"*MITRE Tactic:*\n{tactic_str}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{alert.get('description')}"},
            },
        ],
    }

    try:
        response = requests.post(WEBHOOK_URL, json=message, timeout=5)
        if response.status_code == 200:
            print(f"  📤 Slack notification sent for: {alert.get('rule.name')}")
        else:
            print(f"  ⚠️  Slack notification failed: {response.status_code} {response.text}")
    except requests.RequestException as e:
        print(f"  ⚠️  Slack notification error: {e}")


if __name__ == "__main__":
    test_alert = {
        "rule.name": "test_slack_integration",
        "source.ip": "203.0.113.99",
        "severity": "critical",
        "mitre.technique": ["T1110.001"],
        "mitre.tactic": ["Credential Access"],
        "description": "This is a test alert to verify Slack webhook integration works correctly.",
    }
    send_slack_alert(test_alert)