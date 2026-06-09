"""
Exercise 1 — Incident Triage Playbook (Phishing Alert)

Simulates an XSOAR-style playbook that automates phishing alert triage.
Steps:
  1. Enrich sender email (threat intel lookup)
  2. Classify severity (critical / high / medium)
  3. Auto-close (medium) or escalate (high/critical) to analyst
  4. Generate war room summary

Senior branch: if attachment_hash is present, check hash reputation
before classifying severity and adjust accordingly.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EmailEnrichment:
    reputation_score: int  # 0–100, lower = worse
    known_malicious: bool
    source: str = "Mock Threat Intel"


@dataclass
class HashEnrichment:
    is_malicious: bool
    risk_score: int  # 0–100
    detections: int  # number of AV detections
    source: str = "Mock Hash Reputation Service"


@dataclass
class PhishingAlert:
    sender_email: str
    subject: str
    attachment_hash: Optional[str] = None
    email_enrichment: Optional[EmailEnrichment] = None
    hash_enrichment: Optional[HashEnrichment] = None
    severity: Optional[str] = None
    action_taken: Optional[str] = None
    war_room_summary: Optional[str] = None


# ---------------------------------------------------------------------------
# Mock threat intel services
# ---------------------------------------------------------------------------

MOCK_SENDER_DB: dict[str, EmailEnrichment] = {
    "ceo@legitcorp.com": EmailEnrichment(reputation_score=85, known_malicious=False),
    "billing@suspicious-domain.xyz": EmailEnrichment(reputation_score=55, known_malicious=False),
    "admin@phishing-kit.ru": EmailEnrichment(reputation_score=10, known_malicious=True),
}

MOCK_HASH_DB: dict[str, HashEnrichment] = {
    "d41d8cd98f00b204e9800998ecf8427e": HashEnrichment(is_malicious=False, risk_score=5, detections=0),
    "e99a18c428cb38d5f260853678922e03": HashEnrichment(is_malicious=True, risk_score=95, detections=58),
    "abc123def45678900000000000000000": HashEnrichment(is_malicious=False, risk_score=72, detections=12),
}


def enrich_sender(sender_email: str) -> EmailEnrichment:
    """Step 1 — Query threat intel source for sender reputation."""
    if sender_email in MOCK_SENDER_DB:
        return MOCK_SENDER_DB[sender_email]
    # Default: unknown sender gets neutral score
    return EmailEnrichment(reputation_score=50, known_malicious=False, source="Default (unknown sender)")


def check_hash_reputation(attachment_hash: str) -> HashEnrichment:
    """Senior branch — Check hash against reputation service."""
    if attachment_hash in MOCK_HASH_DB:
        return MOCK_HASH_DB[attachment_hash]
    return HashEnrichment(is_malicious=False, risk_score=30, detections=2, source="Default (unknown hash)")


# ---------------------------------------------------------------------------
# Step 2 — Severity classification
# ---------------------------------------------------------------------------

def classify_severity(email_enrichment: EmailEnrichment,
                      hash_enrichment: Optional[HashEnrichment] = None) -> str:
    """
    Classify severity based on enrichment data.

    Base rules (from sender reputation):
      critical  if reputation_score < 20 or known_malicious
      high      if reputation_score < 50
      medium    otherwise

    Attachment hash override (Senior branch):
      If hash is malicious  -> force Critical
      If hash risk_score >= 70 -> bump one level (medium->high, high->critical)
    """
    # Base classification from sender
    if email_enrichment.known_malicious or email_enrichment.reputation_score < 20:
        severity = "critical"
    elif email_enrichment.reputation_score < 50:
        severity = "high"
    else:
        severity = "medium"

    # Hash override
    if hash_enrichment is not None:
        if hash_enrichment.is_malicious:
            severity = "critical"
        elif hash_enrichment.risk_score >= 70:
            bump = {"medium": "high", "high": "critical", "critical": "critical"}
            severity = bump[severity]

    return severity


# ---------------------------------------------------------------------------
# Step 3 — Auto-close or escalate
# ---------------------------------------------------------------------------

@dataclass
class Task:
    assigned_to: str = "analyst"
    title: str = ""
    description: str = ""
    priority: str = ""


def auto_close_or_escalate(alert: PhishingAlert) -> str:
    """
    medium -> close with written justification
    high / critical -> create task assigned to analyst
    """
    if alert.severity == "medium":
        justification = (
            f"Auto-closed: sender '{alert.sender_email}' has reputation score "
            f"{alert.email_enrichment.reputation_score}/100 and is not known malicious. "
            f"Subject: '{alert.subject}'. No elevated indicators found. "
            f"Classification: MEDIUM — does not require analyst review."
        )
        if alert.hash_enrichment:
            justification += (
                f" Attachment hash risk score: {alert.hash_enrichment.risk_score}/100, "
                f"detections: {alert.hash_enrichment.detections}."
            )
        alert.action_taken = f"CLOSED — {justification}"
        return alert.action_taken

    # High or Critical -> escalate
    task = Task(
        assigned_to="analyst",
        title=f"[{alert.severity.upper()}] Phishing triage: {alert.subject}",
        description=(
            f"Sender: {alert.sender_email}\n"
            f"Reputation score: {alert.email_enrichment.reputation_score}/100\n"
            f"Known malicious sender: {alert.email_enrichment.known_malicious}\n"
        ),
        priority=alert.severity,
    )
    if alert.hash_enrichment:
        task.description += (
            f"Attachment hash: {alert.attachment_hash}\n"
            f"Hash risk score: {alert.hash_enrichment.risk_score}/100\n"
            f"Hash detections: {alert.hash_enrichment.detections}\n"
            f"Hash malicious: {alert.hash_enrichment.is_malicious}\n"
        )
    alert.action_taken = f"ESCALATED — Task created for analyst: '{task.title}'"
    return alert.action_taken


# ---------------------------------------------------------------------------
# Step 4 — War room summary
# ---------------------------------------------------------------------------

def generate_war_room_summary(alert: PhishingAlert) -> str:
    """Generate a structured war room entry."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"## Phishing Triage Summary — {now}",
        "",
        f"**Sender:** {alert.sender_email}",
        f"**Subject:** {alert.subject}",
        "",
        "### Sender Enrichment",
        f"- Reputation score: {alert.email_enrichment.reputation_score}/100",
        f"- Known malicious: {alert.email_enrichment.known_malicious}",
        f"- Source: {alert.email_enrichment.source}",
    ]
    if alert.hash_enrichment:
        lines += [
            "",
            "### Attachment Hash Enrichment",
            f"- Hash: {alert.attachment_hash}",
            f"- Risk score: {alert.hash_enrichment.risk_score}/100",
            f"- AV detections: {alert.hash_enrichment.detections}",
            f"- Malicious: {alert.hash_enrichment.is_malicious}",
            f"- Source: {alert.hash_enrichment.source}",
        ]
    lines += [
        "",
        "### Classification & Action",
        f"- **Severity: {alert.severity.upper()}**",
        f"- Action: {alert.action_taken}",
    ]
    alert.war_room_summary = "\n".join(lines)
    return alert.war_room_summary


# ---------------------------------------------------------------------------
# Main playbook orchestrator
# ---------------------------------------------------------------------------

def run_playbook(sender_email: str, subject: str,
                 attachment_hash: Optional[str] = None) -> PhishingAlert:
    """Execute the full phishing triage playbook."""
    alert = PhishingAlert(sender_email=sender_email, subject=subject,
                          attachment_hash=attachment_hash)

    # Step 1: Enrich sender
    alert.email_enrichment = enrich_sender(sender_email)

    # Step 1b (Senior): enrich hash if present
    if attachment_hash:
        alert.hash_enrichment = check_hash_reputation(attachment_hash)

    # Step 2: Classify severity
    alert.severity = classify_severity(alert.email_enrichment, alert.hash_enrichment)

    # Step 3: Auto-close or escalate
    auto_close_or_escalate(alert)

    # Step 4: War room summary
    generate_war_room_summary(alert)

    return alert


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    scenarios = [
        ("ceo@legitcorp.com", "Q3 Budget Review", None),
        ("admin@phishing-kit.ru", "Urgent: Verify Your Account", "e99a18c428cb38d5f260853678922e03"),
        ("billing@suspicious-domain.xyz", "Invoice #4821 Attached", "abc123def45678900000000000000000"),
    ]
    for sender, subj, hash_val in scenarios:
        result = run_playbook(sender, subj, hash_val)
        print(result.war_room_summary)
        print("=" * 70)
