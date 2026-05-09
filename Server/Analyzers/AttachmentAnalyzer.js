const {
  Severity,
  Verdict,
  VERDICT_THRESHOLDS,
  SEVERITY_WEIGHTS,
} = require("../constants");

const ALLOWED_EXTENSIONS = new Set([
  ".pdf",
  ".jpg",
  ".jpeg",
  ".png",
  ".docx",
  ".xlsx",
  ".pptx",
  ".txt",
  ".csv",
]);

const DANGEROUS_EXTENSIONS = new Set([
  ".exe",
  ".bat",
  ".cmd",
  ".vbs",
  ".js",
  ".ps1",
  ".wsf",
  ".sh",
  ".jar",
  ".msi",
  ".scr",
]);

const ARCHIVE_EXTENSIONS = new Set([
  ".zip",
  ".rar",
  ".7z",
  ".iso",
  ".tar",
  ".gz",
]);

// תוספת למניעת הברחת דפי פישינג
const WEB_EXTENSIONS = new Set([".html", ".htm", ".shtml", ".svg"]);

const EXECUTABLE_MIMES = new Set([
  //רשימה של סיומות של קבצי הרצה על המחשב
  "application/x-msdownload",
  "application/x-dosexec",
  "application/x-executable",
]);
const GENERIC_MIMES = new Set(["application/octet-stream"]); //סיומת כללית שמייצגת קובץ שלא יודעים מה הוא

// מילון שאומר למה אני מצפים שהסיומת האמיתית תהיה עבור כל סיומת שרשומה.
const EXPECTED_MIME_BY_EXTENSION = {
  ".pdf": ["application/pdf"],
  ".jpg": ["image/jpeg"],
  ".jpeg": ["image/jpeg"],
  ".png": ["image/png"],
  ".txt": ["text/plain"],
  ".docx": [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
  ],
  ".xlsx": [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
  ],
  ".pptx": [
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-powerpoint",
  ],
};

// הגבלת עומסים למניעת קריסת שרת (DoS)
const MAX_TOTAL_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_ATTACHMENTS_COUNT = 50;

//בודקים האם שם הקובץ מכיל כמה שפות, אם כן זה חשוד.
const isMixedScript = (filename) => {
  let scriptCount = 0;
  if (/[a-zA-Z]/.test(filename)) scriptCount++;
  if (/[\u0400-\u04FF]/.test(filename)) scriptCount++; // Cyrillic
  if (/[\u0590-\u05FF]/.test(filename)) scriptCount++; // Hebrew
  if (/[\u0600-\u06FF]/.test(filename)) scriptCount++; // Arabic
  return scriptCount > 1;
};

// יצירת הודעה על השגיאה
const createSignal = (file, ruleId, data, scanTimestamp, index) => ({
  ...data,
  triggeredBy: ruleId,
  attachmentIndex: index,
  filename: file.filename,
  timestamp: scanTimestamp,
  isPositiveSignal: false,
});

//רשימת חוקים שמבוטאים כפונקציות שצריך לבדוק על כל קובץ
const rules = [
  {
    id: "FILENAME_LENGTH_RULE", // אורך שם ארוך מדי
    run: (file) =>
      file.filename.length > 255
        ? {
            type: "EXCESSIVE_FILENAME_LENGTH",
            category: "ANOMALY",
            severity: Severity.HIGH,
            confidence: 1.0,
            reason: "Filename exceeds 255 characters.",
          }
        : null,
  },
  {
    id: "EVASION_CHARACTERS_RULE",
    run: (file) => {
      if (file.filename.includes("\0") || file.filename.includes("%00")) {
        //מחפשים תווים שאומרים לחתוך את הטקסט
        return {
          type: "NULL_BYTE_INJECTION",
          category: "EVASION",
          severity: Severity.CRITICAL,
          confidence: 1.0,
          reason: "Null byte detected.",
        };
      }
      if (file.filename.includes("\u202E")) {
        // מחפשים תו שאומר להפוך את כיוון הקריאה
        return {
          type: "RTLO_SPOOFING",
          category: "SPOOFING",
          severity: Severity.CRITICAL,
          confidence: 1.0,
          reason: "Right-To-Left Override character detected.",
        };
      }
      return null;
    },
  },
  {
    id: "MIXED_SCRIPT_RULE",
    run: (file) =>
      isMixedScript(file.filename) // בודקים אם יש ערבוב של שפות בשם.
        ? {
            type: "MIXED_SCRIPT_SPOOFING",
            category: "SPOOFING",
            severity: Severity.LOW,
            confidence: 0.85,
            reason: "Filename mixes different alphabets.",
          }
        : null,
  },
  {
    id: "DOUBLE_EXTENSION_RULE",
    run: (file, parts, ext) => {
      // בודק האם יש שני סיומות כך שהראשונה לגיטימית והשניה לא וכך מטעים
      const prevExt = parts.length > 2 ? `.${parts[parts.length - 2]}` : null;
      if (
        prevExt &&
        ALLOWED_EXTENSIONS.has(prevExt) &&
        DANGEROUS_EXTENSIONS.has(ext)
      ) {
        return {
          type: "DOUBLE_EXTENSION_SPOOF",
          category: "SPOOFING",
          severity: Severity.CRITICAL,
          confidence: 0.95,
          reason: `Hide dangerous ext (${ext}) behind safe one (${prevExt}).`,
        };
      }
      return null;
    },
  },
  {
    id: "FILE_TYPE_RULE", // בדיקה פשוטה שבודקת את הסיומת ומחזירה רמת סיכון
    run: (file, parts, ext) => {
      if (DANGEROUS_EXTENSIONS.has(ext))
        return {
          type: "DANGEROUS_FILE",
          category: "EXECUTION",
          severity: Severity.HIGH,
          confidence: 1.0,
          reason: `Dangerous type: ${ext}`,
        };
      // קובץ הרצה
      if (ARCHIVE_EXTENSIONS.has(ext))
        return {
          type: "COMPRESSED_ARCHIVE",
          category: "EVASION",
          severity: Severity.MEDIUM,
          confidence: 0.8,
          reason: "Compressed archive detected. Inspection required.",
        };
      // דברים כמו HTML
      if (WEB_EXTENSIONS.has(ext))
        return {
          type: "HTML_SMUGGLING_RISK",
          category: "EVASION",
          severity: Severity.HIGH, // הגדרנו כ-HIGH כי זה וקטור תקיפה חזק
          confidence: 0.85,
          reason:
            "Web file attached. High risk of HTML smuggling or local phishing.",
        };
      if (!ALLOWED_EXTENSIONS.has(ext) && ext !== "")
        return {
          type: "UNCOMMON_EXTENSION",
          category: "ANOMALY",
          severity: Severity.LOW,
          confidence: 0.6,
          reason: `Extension ${ext} not on allowlist.`,
        };
      return null;
    },
  },
  {
    id: "MIME_MASQUERADE_RULE", // האם רשום סיומת של קובץ רגיל ובפועל היא של תוכנת הרצה
    run: (file, parts, ext) =>
      EXECUTABLE_MIMES.has(file.mimeType) && !DANGEROUS_EXTENSIONS.has(ext)
        ? {
            type: "EXECUTABLE_MASQUERADE",
            category: "SPOOFING",
            severity: Severity.CRITICAL,
            confidence: 0.95,
            reason:
              "File metadata indicates executable, but extension does not.",
          }
        : null,
  },
  {
    id: "MIME_DICTIONARY_RULE", // האם הסיומת שרשומה היא האמיתית
    run: (file, parts, ext) => {
      const expectedMimes = EXPECTED_MIME_BY_EXTENSION[ext];
      if (
        expectedMimes &&
        !GENERIC_MIMES.has(file.mimeType) &&
        !expectedMimes.includes(file.mimeType)
      ) {
        return {
          type: "MIME_SPOOFING",
          category: "SPOOFING",
          severity: Severity.HIGH,
          confidence: 0.9,
          reason: `MIME type ${file.mimeType} invalid for ${ext}.`,
        };
      }
      return null;
    },
  },
];

const analyzeAttachments = (attachments) => {
  const scanReport = {
    //אתחול של סריקה ריקה
    verdict: Verdict.PASS,
    riskScore: 0,
    totalSignals: 0,
    signals: [],
    scannedAt: Date.now(),
  };

  if (!attachments || !Array.isArray(attachments) || attachments.length === 0) {
    return scanReport;
  }

  // מניעת עומס קבצים
  if (attachments.length > MAX_ATTACHMENTS_COUNT) {
    scanReport.signals.push(
      createSignal(
        { filename: "SYSTEM" },
        "SYSTEM_LIMIT_RULE",
        {
          type: "EXCESSIVE_ATTACHMENTS",
          category: "ANOMALY",
          severity: Severity.CRITICAL,
          confidence: 1.0,
          reason: "Too many attachments. DoS risk.",
        },
        scanReport.scannedAt,
        -1,
      ),
    );
    scanReport.riskScore = 100;
    scanReport.verdict = Verdict.BLOCK;
    return scanReport;
  }

  let cumulativeRiskScore = 0;
  let totalPayloadSize = 0;

  //  סריקת כל קובץ
  attachments.forEach((att, index) => {
    const filename = (att.filename || "")
      .replace(/\s+/g, " ")
      .trim()
      .toLocaleLowerCase("en-US"); //// מוחקים רווחים ודברים מיותרים
    const mimeType = (att.mimeType || "").toLowerCase();
    const size = att.size || 0;
    totalPayloadSize += size;

    if (!filename) return;

    const parts = filename.split(".");
    const extension = parts.length > 1 ? `.${parts[parts.length - 1]}` : "";
    const fileContext = { filename, mimeType, size };

    // הפעלת מנוע החוקים
    for (const rule of rules) {
      const result = rule.run(fileContext, parts, extension);
      if (result) {
        const signal = createSignal(
          fileContext,
          rule.id,
          result,
          scanReport.scannedAt,
          index,
        );
        scanReport.signals.push(signal);

        // הוספה לציון המצטבר (חומרה * ביטחון)
        cumulativeRiskScore +=
          (SEVERITY_WEIGHTS[result.severity] || 0) * result.confidence;
      }
    }
  });

  // מניעת עומס בזכרון
  if (totalPayloadSize > MAX_TOTAL_SIZE_BYTES) {
    scanReport.signals.push(
      createSignal(
        { filename: "SYSTEM" },
        "SYSTEM_LIMIT_RULE",
        {
          type: "EXCESSIVE_PAYLOAD_SIZE",
          category: "ANOMALY",
          severity: Severity.HIGH,
          confidence: 1.0,
          reason: "Total attachment size exceeds maximum allowed limit.",
        },
        scanReport.scannedAt,
        -1,
      ),
    );
    cumulativeRiskScore += SEVERITY_WEIGHTS[Severity.HIGH] * 1.0;
  }

  // קביעת ציון משוקלל
  scanReport.riskScore = Math.min(Math.round(cumulativeRiskScore), 100); // מנרמל את הציון לגג של 100
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

module.exports = { analyzeAttachments };
