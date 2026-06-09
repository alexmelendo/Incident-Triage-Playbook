"""Unit tests for the phishing triage playbook — severity classification logic."""

import unittest
from playbook import (
    EmailEnrichment,
    HashEnrichment,
    classify_severity,
    run_playbook,
)


class TestSeverityClassification(unittest.TestCase):
    """Validate the severity classification rules."""

    # --- Base rules (sender only, no hash) ---

    def test_critical_when_known_malicious(self):
        env = EmailEnrichment(reputation_score=90, known_malicious=True)
        self.assertEqual(classify_severity(env), "critical")

    def test_critical_when_score_below_20(self):
        env = EmailEnrichment(reputation_score=15, known_malicious=False)
        self.assertEqual(classify_severity(env), "critical")

    def test_critical_when_score_exactly_19(self):
        env = EmailEnrichment(reputation_score=19, known_malicious=False)
        self.assertEqual(classify_severity(env), "critical")

    def test_high_when_score_below_50(self):
        env = EmailEnrichment(reputation_score=35, known_malicious=False)
        self.assertEqual(classify_severity(env), "high")

    def test_high_when_score_exactly_49(self):
        env = EmailEnrichment(reputation_score=49, known_malicious=False)
        self.assertEqual(classify_severity(env), "high")

    def test_medium_when_score_50_or_above(self):
        env = EmailEnrichment(reputation_score=50, known_malicious=False)
        self.assertEqual(classify_severity(env), "medium")

    def test_medium_when_high_score(self):
        env = EmailEnrichment(reputation_score=85, known_malicious=False)
        self.assertEqual(classify_severity(env), "medium")

    # --- Hash override (Senior branch) ---

    def test_hash_malicious_forces_critical(self):
        """Malicious hash overrides any sender score to critical."""
        env = EmailEnrichment(reputation_score=90, known_malicious=False)
        hsh = HashEnrichment(is_malicious=True, risk_score=95, detections=50)
        self.assertEqual(classify_severity(env, hsh), "critical")

    def test_hash_malicious_forces_critical_even_for_bad_sender(self):
        """Double-negative: bad sender + malicious hash = critical (not higher)."""
        env = EmailEnrichment(reputation_score=5, known_malicious=True)
        hsh = HashEnrichment(is_malicious=True, risk_score=99, detections=60)
        self.assertEqual(classify_severity(env, hsh), "critical")

    def test_hash_suspicious_bumps_medium_to_high(self):
        env = EmailEnrichment(reputation_score=80, known_malicious=False)
        hsh = HashEnrichment(is_malicious=False, risk_score=72, detections=10)
        self.assertEqual(classify_severity(env, hsh), "high")

    def test_hash_suspicious_bumps_high_to_critical(self):
        env = EmailEnrichment(reputation_score=40, known_malicious=False)
        hsh = HashEnrichment(is_malicious=False, risk_score=85, detections=20)
        self.assertEqual(classify_severity(env, hsh), "critical")

    def test_hash_low_risk_does_not_change_severity(self):
        """A clean hash should not alter the base classification."""
        env = EmailEnrichment(reputation_score=80, known_malicious=False)
        hsh = HashEnrichment(is_malicious=False, risk_score=10, detections=0)
        self.assertEqual(classify_severity(env, hsh), "medium")

    def test_hash_risk_exactly_70_bumps(self):
        """Boundary: risk_score == 70 should trigger the bump."""
        env = EmailEnrichment(reputation_score=80, known_malicious=False)
        hsh = HashEnrichment(is_malicious=False, risk_score=70, detections=8)
        self.assertEqual(classify_severity(env, hsh), "high")

    def test_hash_risk_69_does_not_bump(self):
        """Boundary: risk_score == 69 should NOT trigger the bump."""
        env = EmailEnrichment(reputation_score=80, known_malicious=False)
        hsh = HashEnrichment(is_malicious=False, risk_score=69, detections=7)
        self.assertEqual(classify_severity(env, hsh), "medium")


class TestPlaybookIntegration(unittest.TestCase):
    """End-to-end playbook runs produce correct severity and action."""

    def test_medium_auto_closed(self):
        alert = run_playbook("ceo@legitcorp.com", "Q3 Budget Review")
        self.assertEqual(alert.severity, "medium")
        self.assertIn("CLOSED", alert.action_taken)
        self.assertIn("war_room_summary", alert.__dict__)

    def test_critical_escalated(self):
        alert = run_playbook("admin@phishing-kit.ru", "Verify Account",
                             "e99a18c428cb38d5f260853678922e03")
        self.assertEqual(alert.severity, "critical")
        self.assertIn("ESCALATED", alert.action_taken)

    def test_hash_bump_changes_outcome(self):
        """Sender is medium-risk but suspicious hash bumps to high -> escalated."""
        alert = run_playbook("billing@suspicious-domain.xyz", "Invoice",
                             "abc123def45678900000000000000000")
        self.assertEqual(alert.severity, "high")
        self.assertIn("ESCALATED", alert.action_taken)


if __name__ == "__main__":
    unittest.main()
