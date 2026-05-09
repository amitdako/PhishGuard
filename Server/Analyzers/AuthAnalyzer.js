const {
  Severity,
  Verdict,
  VERDICT_THRESHOLDS,
  SEVERITY_WEIGHTS,
} = require("../constants");

// אלו כל הערכים ששרתים חוקיים יכולים להחזיר.
const VALID_RESULTS = new Set([
  "pass",
  "fail",
  "softfail",
  "neutral",
  "none",
  "temperror",
  "permerror",
  "bestguesspass",
]);

// פונקצייה שמחלצת את כל המידע.
function parseAuthResults(rawHeader) {
  // אם המחרוזת גדולה מדי/ לא התקבלה מחרוזת/ זו לא מחרוזת שגיאה.
  if (!rawHeader || typeof rawHeader !== "string" || rawHeader.length > 10000) {
    return { parsed: false };
  }

  // ניקוי ירידות שורה ורווחים
  const unfolded = rawHeader
    .replace(/\r?\n|\r/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();

  // פונקצייה שמחלצת את הערך המתאים לשדה שנרצה לבדוק.
  const extract = (protocol) => {
    const regex = new RegExp(`\\b${protocol}=([a-z0-9]+)\\b`);
    const match = unfolded.match(regex);
    // בודק גם אם מצא התאמה, וגם אם ההתאמה היא מילה חוקית בפרוטוקול
    return match && VALID_RESULTS.has(match[1]) ? match[1] : "unknown";
  };

  //חילוץ מדיניות ה-
  // DMARC (p=reject / quarantine / none)
  const dmarcPolicyMatch = unfolded.match(/\bp=(reject|quarantine|none)\b/); // p = policy.

  return {
    parsed: true,
    spf: extract("spf"), // האם מותר לו לשלוח מייל בשם הדומיין?
    dkim: extract("dkim"), //האם החותמת הדיגיטלית השתנתה בשליחה?
    dmarc: extract("dmarc"), // בודק אם אחד מהם קרה וגם הדומיין זהה לשולח.
    arc: extract("arc"), // מציין האם המייל הועבר ממקור אחר אמין, כלומר אם מקור אחר שלח לי מייל ממקום אחר אבל הוא העיד שהוא קיבל מייל אמין.
    dmarcPolicy: dmarcPolicyMatch ? dmarcPolicyMatch[1] : "unknown",
  };
}

// פונקציה שמנתחת את המידע.
const analyzeAuth = (authResultsHeader) => {
  const scanReport = {
    verdict: Verdict.PASS,
    riskScore: 0,
    totalSignals: 0,
    signals: [],
    scannedAt: Date.now(),
  };

  const parsedAuth = parseAuthResults(authResultsHeader); // מקבל את כל הערכים הרלוונטים.

  if (!parsedAuth.parsed) return scanReport; // אין הדר ולכן אין מה לנתח.

  // ניתוח DMARC
  if (parsedAuth.dmarc === "fail") {
    const isReject = parsedAuth.dmarcPolicy === "reject"; // אם כן זה אומר שהדומיין הזהיר מזה.
    scanReport.signals.push({
      type: "DMARC_FAILURE",
      severity: isReject ? Severity.CRITICAL : Severity.HIGH,
      confidence: 1.0,
      isPositiveSignal: false,
      reason: `DMARC failed${isReject ? " with explicit p=reject policy. Extremely high spoofing risk." : "."}`,
    });
  } else if (parsedAuth.dmarc === "pass") {
    scanReport.signals.push({
      type: "DMARC_PASS",
      severity: Severity.LOW,
      confidence: 1.0,
      isPositiveSignal: true,
      reason: "DMARC verified.",
    });
  }

  // ניתוח SPF.
  if (parsedAuth.spf === "fail") {
    const isArcPass = parsedAuth.arc === "pass";
    scanReport.signals.push({
      type: "SPF_FAILURE",
      // אם arc
      //  עבר, זה כנראה מייל שהועבר, לכן נוריד משמעותית את רמת הסיכון!
      severity: isArcPass ? Severity.LOW : Severity.HIGH,
      confidence: isArcPass ? 0.4 : 0.95,
      isPositiveSignal: false,
      reason: isArcPass
        ? "SPF failed, but ARC passed. This usually indicates a legitimate forwarded email."
        : "SPF check failed. Sending IP is unauthorized.",
    });
  } else if (["permerror", "temperror"].includes(parsedAuth.spf)) {
    //לא ניתו לקריאה או שיש שגיאה בקבלת המידע
    // מקרה בו אין גישה לרשימת הדומינים המורשים או שיש שגיאה ברשימה, ככל הנראה תקלה טכנית.
    scanReport.signals.push({
      type: "SPF_MISCONFIGURATION",
      severity: Severity.MEDIUM,
      confidence: 0.8,
      isPositiveSignal: false,
      reason: `SPF returned ${parsedAuth.spf}. This indicates a DNS setup issue, not necessarily spoofing.`,
    });
  } else if (parsedAuth.spf === "pass") {
    // תקין
    scanReport.signals.push({
      type: "SPF_PASS",
      severity: Severity.LOW,
      confidence: 1.0,
      isPositiveSignal: true,
      reason: "SPF verified.",
    });
  }

  // ניתוח DKIM
  if (parsedAuth.dkim === "fail") {
    scanReport.signals.push({
      type: "DKIM_FAILURE",
      severity: Severity.HIGH,
      confidence: 0.95,
      isPositiveSignal: false,
      reason:
        "DKIM signature is invalid (tampered content or forged signature).",
    });
  } else if (parsedAuth.dkim === "pass") {
    scanReport.signals.push({
      type: "DKIM_PASS",
      severity: Severity.LOW,
      confidence: 1.0,
      isPositiveSignal: true,
      reason: "DKIM verified.",
    });
  } else if (parsedAuth.dkim === "unknown") {
    // אין לנו ידע.
    scanReport.signals.push({
      type: "DKIM_UNKNOWN",
      severity: Severity.LOW,
      confidence: 0.3,
      isPositiveSignal: false,
      reason: "DKIM status is unknown or missing.",
    });
  }

  let cumulativeRiskScore = 0;
  scanReport.signals.forEach((sig) => {
    if (!sig.isPositiveSignal) {
      cumulativeRiskScore +=
        (SEVERITY_WEIGHTS[sig.severity] || 0) * sig.confidence;
    }
  });

  scanReport.riskScore = Math.min(Math.round(cumulativeRiskScore), 100);
  scanReport.totalSignals = scanReport.signals.length;

  if (scanReport.riskScore >= VERDICT_THRESHOLDS.BLOCK) {
    scanReport.verdict = Verdict.BLOCK;
  } else if (scanReport.riskScore >= VERDICT_THRESHOLDS.QUARANTINE) {
    scanReport.verdict = Verdict.QUARANTINE;
  } else if (scanReport.riskScore >= VERDICT_THRESHOLDS.REVIEW) {
    scanReport.verdict = Verdict.REVIEW;
  }

  return scanReport;
};

module.exports = { analyzeAuth, parseAuthResults };
