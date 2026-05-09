const {
  Severity,
  Verdict,
  VERDICT_THRESHOLDS,
  SEVERITY_WEIGHTS,
} = require("../constants");

// מילון של מילים חשודות
const URGENCY_KEYWORDS = [
  //תחושת דחיפות
  "urgent",
  "immediate action",
  "within 24 hours",
  "account suspended",
  "verify your account",
  "validate your account",
  "final warning",
  "will be locked",
];

const EXTORTION_KEYWORDS = [
  // סחיטה
  "recorded you",
  "webcam",
  "masturbating",
  "porn",
  "hacked your device",
  "pay me",
  "bitcoin",
  "btc wallet",
  "crypto wallet",
  "transfer strictly",
];

const FINANCIAL_FRAUD_KEYWORDS = [
  //הונאה כספית
  "wire transfer",
  "gift card",
  "itunes card",
  "steam card",
  "bank details",
  "urgent favor",
  "are you at your desk",
  "unpaid invoice",
];

// ביטוי רגולרי בסיסי לזיהוי כתובות ארנק ביטקוין
// תוקן: הוסף דגל 'i' כדי להתעלם מאותיות קטנות/גדולות לאחר הנרמול
const BITCOIN_REGEX =
  /\b([13][a-km-z0-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})\b/i;

//יצירת הודעה על אירוע
const createSignal = (ruleId, data, scanTimestamp) => ({
  ...data,
  triggeredBy: ruleId,
  timestamp: scanTimestamp,
  isPositiveSignal: false,
});

// פונקציה שסופרת כמה פעמים מילים מתוך רשימה מופיעות בטקסט
const countMatches = (text, keywordList) => {
  let count = 0;
  keywordList.forEach((word) => {
    if (text.includes(word.toLowerCase())) {
      count++;
    }
  });
  return count;
};

//חוקים שיש לבדוק
const rules = [
  {
    id: "URGENCY_AND_FEAR_RULE",
    run: (text) => {
      const matches = countMatches(text, URGENCY_KEYWORDS);
      if (matches >= 2) {
        return {
          type: "URGENCY_MANIPULATION",
          category: "SOCIAL_ENGINEERING",
          severity: Severity.MEDIUM,
          confidence: 0.8,
          reason: `Found ${matches} phrases indicating artificial urgency or account threats.`,
        };
      }
      return null;
    },
  },
  {
    id: "EXTORTION_BLACKMAIL_RULE",
    run: (text) => {
      const matches = countMatches(text, EXTORTION_KEYWORDS);
      const hasBitcoinWallet = BITCOIN_REGEX.test(text);

      // אם יש גם מילות סחיטה וגם ארנק ביטקוין, זה בוודאות סחיטה
      if (matches >= 2 && hasBitcoinWallet) {
        return {
          type: "EXTORTION_ATTEMPT",
          category: "THREAT",
          severity: Severity.CRITICAL, // שודרג ל-CRITICAL
          confidence: 1.0, // ביטחון 100%
          reason:
            "Detected a combination of extortion keywords and a cryptocurrency wallet address.",
        };
      } else if (matches >= 3) {
        return {
          type: "POSSIBLE_BLACKMAIL",
          category: "THREAT",
          severity: Severity.CRITICAL, // שודרג ל-CRITICAL
          confidence: 0.9,
          reason:
            "Text contains multiple words associated with webcam/password blackmail.",
        };
      }
      return null;
    },
  },
  {
    id: "BEC_FRAUD_RULE",
    run: (text) => {
      // הונאה , למשל מייל מזויף מהבוס שמבקש כסף
      const matches = countMatches(text, FINANCIAL_FRAUD_KEYWORDS);
      if (matches >= 2) {
        return {
          type: "FINANCIAL_FRAUD_REQUEST",
          category: "SOCIAL_ENGINEERING",
          severity: Severity.HIGH,
          confidence: 0.8,
          reason:
            "Detected language commonly used in Business Email Compromise (BEC) or gift card scams.",
        };
      }
      return null;
    },
  },
];

//פונקציה ראשית
const analyzeContent = (emailBody) => {
  const scanReport = {
    // אתחול
    verdict: Verdict.PASS,
    riskScore: 0,
    totalSignals: 0,
    signals: [],
    scannedAt: Date.now(),
  };

  if (!emailBody || typeof emailBody !== "string" || emailBody.trim() === "") {
    return scanReport;
  }

  // מורידים רווחים והופכים לאותיות קטנות
  const normalizedBody = emailBody.replace(/\s+/g, " ").toLowerCase();

  let cumulativeRiskScore = 0;

  // הפעלת מנועי החיפוש
  for (const rule of rules) {
    const result = rule.run(normalizedBody);
    if (result) {
      const signal = createSignal(rule.id, result, scanReport.scannedAt);
      scanReport.signals.push(signal);
      cumulativeRiskScore +=
        (SEVERITY_WEIGHTS[result.severity] || 0) * result.confidence; // מוסיף לציון
    }
  }

  scanReport.riskScore = Math.min(Math.round(cumulativeRiskScore), 100); //מנרמל ל100 את הציון שיצא
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

module.exports = { analyzeContent };
