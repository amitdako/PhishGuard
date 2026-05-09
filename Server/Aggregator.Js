const {
  Verdict,
  Severity,
  VERDICT_THRESHOLDS,
  CORRELATION_BONUSES,
  SEVERITY_WEIGHTS,
} = require("./constants");

// חישוב הציון הסופי
const calculateBaseScore = (signals) => {
  let score = 0;
  let positiveDeduction = 0;

  signals.forEach((signal) => {
    const weight = SEVERITY_WEIGHTS[signal.severity] || 0;
    const confidence = signal.confidence || 1.0;
    const impact = weight * confidence;

    if (signal.isPositiveSignal) {
      // אנחנו מחסירים סכום קבוע וקטן (למשל 3 נקודות) על כל סימן חיובי
      // ולא מכפילים במשקל ה-LOW המלא.
      positiveDeduction += 3 * confidence;
    } else {
      score += impact;
    }
  });

  // אנחנו מגבילים את ה"הנחה" הכוללת למקסימום 15 נקודות,
  const maxDeduction = 15;
  score -= Math.min(positiveDeduction, maxDeduction);

  return Math.max(0, score); // הציון לא יכול לרדת מתחת ל-0
};
/**
 * Aggregates reports from all analyzers, applies cross-signal correlation,
 * and generates the final risk assessment.
 */
const aggregateRisk = (reports) => {
  const { authReport, attachmentReport, linkReport, contentReport } = reports;

  const allSignals = [
    ...(authReport?.signals || []),
    ...(attachmentReport?.signals || []),
    ...(linkReport?.signals || []),
    ...(contentReport?.signals || []),
  ]; // מערך של כל החשדות שקיבלנו

  let finalRiskScore = calculateBaseScore(allSignals);

  const hasAuthFailure = allSignals.some(
    // האם יש משהו במייל שלא עבר את הבדיקות האלו
    (s) => s.type === "DMARC_FAILURE" || s.type === "SPF_FAILURE",
  );
  const hasSuspiciousLinks =
    (linkReport?.riskScore || 0) >= VERDICT_THRESHOLDS.QUARANTINE; //האם הייתה חריגה בלינקים?

  // כאן השם שונה בדיוק כמו שרצית!
  const hasSuspiciousText =
    (contentReport?.riskScore || 0) >= VERDICT_THRESHOLDS.REVIEW; // האם הייתה חריגה בתוכן?

  const hasDangerousAttachments =
    (attachmentReport?.riskScore || 0) >= VERDICT_THRESHOLDS.QUARANTINE; // האם הייתה חריגה בקבצים?

  // האם יש תוכן זדוני והשולח לא אמין אז בסבירות גבוהה מאוד זה פישינג
  if (hasAuthFailure && hasSuspiciousText) {
    finalRiskScore += CORRELATION_BONUSES.PHISHING_INTENT;
    allSignals.push({
      type: "CORRELATION_PHISHING_INTENT",
      category: "CORRELATION",
      severity: Severity.CRITICAL,
      confidence: 0.95,
      isPositiveSignal: false,
      reason:
        "Authentication failure combined with social engineering indicators.",
    });
  }

  //אם יש תוכן חשוד וקישורים חשודים אז בסיכוי גבוה זדוני
  if (hasSuspiciousText && hasSuspiciousLinks) {
    finalRiskScore += CORRELATION_BONUSES.CREDENTIAL_HARVESTING;
    allSignals.push({
      type: "CORRELATION_CREDENTIAL_HARVESTING",
      category: "CORRELATION",
      severity: Severity.HIGH,
      confidence: 0.9,
      isPositiveSignal: false,
      reason: "Social engineering combined with suspicious URLs.",
    });
  }

  const isHardBlock = [
    attachmentReport,
    linkReport,
    contentReport,
    authReport,
  ].some((report) => report?.verdict === Verdict.BLOCK); // אם מחלקה אחת לפחות החליטה לחסום הציון 100 בהכרח

  if (isHardBlock) {
    finalRiskScore = Math.max(finalRiskScore, 100);
  }

  finalRiskScore = Math.max(0, Math.min(Math.round(finalRiskScore), 100));

  //קובע המלצה סופית
  let finalVerdict = Verdict.PASS;
  if (finalRiskScore >= VERDICT_THRESHOLDS.BLOCK) {
    finalVerdict = Verdict.BLOCK;
  } else if (finalRiskScore >= VERDICT_THRESHOLDS.QUARANTINE) {
    finalVerdict = Verdict.QUARANTINE;
  } else if (finalRiskScore >= VERDICT_THRESHOLDS.REVIEW) {
    finalVerdict = Verdict.REVIEW;
  }

  return {
    scannedAt: Date.now(),
    summary: {
      verdict: finalVerdict,
      riskScore: finalRiskScore,
      totalThreatsFound: allSignals.filter((s) => !s.isPositiveSignal).length,
    },
    indicators: {
      authenticationFailed: hasAuthFailure,
      containsMalware: hasDangerousAttachments,
      isPhishing: hasSuspiciousText || hasSuspiciousLinks,
    },
    detailedSignals: allSignals,
  };
};

module.exports = { aggregateRisk };
