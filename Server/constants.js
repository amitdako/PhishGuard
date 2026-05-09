const Verdict = Object.freeze({
  PASS: "PASS",
  REVIEW: "REVIEW",
  QUARANTINE: "QUARANTINE",
  BLOCK: "BLOCK",
});

const Severity = Object.freeze({
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
});

const VERDICT_THRESHOLDS = Object.freeze({
  BLOCK: 90,
  QUARANTINE: 60,
  REVIEW: 30,
});

const CORRELATION_BONUSES = Object.freeze({
  PHISHING_INTENT: 40,
  CREDENTIAL_HARVESTING: 30,
});

const SEVERITY_WEIGHTS = Object.freeze({
  [Severity.LOW]: 10,
  [Severity.MEDIUM]: 30,
  [Severity.HIGH]: 70,
  [Severity.CRITICAL]: 100,
});

module.exports = {
  Verdict,
  Severity,
  VERDICT_THRESHOLDS,
  CORRELATION_BONUSES,
  SEVERITY_WEIGHTS,
};
