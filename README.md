# Incident Triage Playbook

Python-based playbook that automates the triage of a phishing alert through four sequential steps: sender enrichment, severity classification, auto-close/escalation decision, and war room summary generation. Includes a conditional branch for attachment hash reputation checking.

## Design Decisions

### Architecture

- **Modular step functions**: Each triage step is a standalone function (`enrich_sender`, `classify_severity`, `auto_close_or_escalate`, `generate_war_room_summary`). This mirrors how XSOAR playbooks chain tasks — each step is independently testable and replaceable.
- **Dataclass for alert context**: A `PhishingAlert` dataclass carries state between steps. In XSOAR this would be the incident context; here it's a typed container that prevents key-name drift across steps.
- **Mock threat intel services**: `enrich_sender` and `check_hash_reputation` return mock data with a consistent interface. In production, swap these for real API calls (VirusTotal, AbuseIPDB, etc.) without changing the playbook flow.

### Severity Classification Logic

| Condition                                      | Severity |
|------------------------------------------------|----------|
| `reputation_score < 20` OR `known_malicious`   | Critical |
| `reputation_score < 50`                        | High     |
| Everything else                                | Medium   |

**Attachment hash override (Senior branch):** If an `attachment_hash` is provided, its reputation is checked *before* classification. If the hash is known malicious (`is_malicious = True`), severity is forced to **Critical** regardless of sender reputation. If the hash is suspicious (`risk_score >= 70`), severity is bumped by one level (Medium -> High, High -> Critical).

### Auto-close / Escalate

- **Medium**: Incident is closed automatically with a written justification summarizing why it's low-risk.
- **High / Critical**: A task is created and assigned to an analyst. The task includes all enrichment data so the analyst has full context immediately.

### War Room Summary

Every triage produces a structured war room entry with:
- All enrichment data (sender reputation, hash reputation if applicable)
- Final severity classification
- Action taken (closed or escalated)
- Timestamp

## Project Structure

```
exercise-1-phishing-triage/
├── README.md
├── playbook.py          # Main playbook + mock services
└── test_playbook.py     # Unit tests for severity classification
```

## Setup & Usage

### Prerequisites

- Python 3.9+ (uses dataclasses, type hints)

### Run the playbook

```bash
cd exercise-1-phishing-triage
python playbook.py
```

Runs demo scenarios (low-risk sender, malicious sender with hash, suspicious sender with bump hash) and prints war room summaries.

### Run tests

```bash
python -m pytest exercise-1-phishing-triage/test_playbook.py -v
```

17 tests covering base classification rules, hash override logic, boundary values, and end-to-end playbook integration.

## Mapping to XSOAR

| Playbook concept           | XSOAR equivalent                            |
|----------------------------|---------------------------------------------|
| `PhishingAlert` dataclass  | Incident context (`ctx`)                    |
| `enrich_sender()`          | "Enrich Email" task (integration command)   |
| `check_hash_reputation()`  | "File Reputation" task (integration command)|
| `classify_severity()`      | Conditional task with severity thresholds   |
| `auto_close_or_escalate()` | "Close Incident" / "New Task" automation    |
| `generate_war_room_summary()` | "War Room Entry" task (markdown note)    |
