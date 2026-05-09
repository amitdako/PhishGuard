const { URL } = require("url");
const net = require("net"); // מודל לבדיקות רשת.
const {
  Severity,
  Verdict,
  VERDICT_THRESHOLDS,
  SEVERITY_WEIGHTS,
} = require("../constants");

// פונקציה שמטפלת במקרים שבהם גוגל או שירותים אחרים עוטפים את הלינק הזדוני
function unwrapUrl(url) {
  try {
    const parsed = new URL(url);
    // פרמטרים נפוצים שבהם מתחבא הלינק האמיתי
    const redirectParams = ["q", "url", "u", "target"];

    // אם זה דומיין של גוגל (חיפוש או הפניה)
    if (parsed.hostname.includes("google.com")) {
      for (const param of redirectParams) {
        const target = parsed.searchParams.get(param);
        if (target && target.startsWith("http")) {
          console.log(`🔍 Unwrapped hidden URL: ${target}`);
          return target;
        }
      }
    }
  } catch (e) {
    return url;
  }
  return url;
}
//ניתוח הלינקים
const analyzeLinks = async (links) => {
  const scanReport = {
    // אתחול דוח
    verdict: Verdict.PASS,
    riskScore: 0,
    totalSignals: 0,
    signals: [],
    scannedAt: Date.now(),
  };

  if (!links || !Array.isArray(links) || links.length === 0) {
    return scanReport;
  }

  // מוודא שלא נעבוד פעמיים על אותו קישור ומגביל ל100
  const limitedLinks = links.slice(0, 100);
  const linkMap = new Map();
  limitedLinks.forEach((l) => {
    if (!linkMap.has(l.url)) linkMap.set(l.url, l); // l זה האובייקט של הקישור והטקסט
  });

  const uniqueUrls = Array.from(linkMap.keys());

  const analysisPromises = uniqueUrls.map(async (url) => {
    const linkData = linkMap.get(url);
    // מוציאים את הלינק האמיתי לפני הניתוח
    const realUrl = unwrapUrl(url);
    return performDeepLinkAnalysis(realUrl, linkData.displayText);
  });

  const results = await Promise.allSettled(analysisPromises); // מחכים שהבדיקות יסתיימו

  // איסוף תוצאות מוצלחות בלבד
  let allDetections = results
    .filter((r) => r.status === "fulfilled")
    .flatMap((r) => r.value); // הערך זה מערך האזהרות

  // בודקים עם הרשימה השחורה של גוגל)
  const safeBrowsingResults = await checkSafeBrowsingWithTimeout(
    uniqueUrls.map((u) => unwrapUrl(u)),
  );

  // איחוד כל הסיגנלים שנמצאו
  scanReport.signals = [...allDetections, ...safeBrowsingResults];
  scanReport.totalSignals = scanReport.signals.length;

  // חישוב ציון סיכון מצטבר
  let cumulativeRiskScore = 0;
  scanReport.signals.forEach((sig) => {
    cumulativeRiskScore +=
      (SEVERITY_WEIGHTS[sig.severity] || 0) * (sig.confidence || 1.0);
  });

  // נרמול הציון וקביעת פסק דין
  scanReport.riskScore = Math.min(Math.round(cumulativeRiskScore), 100);

  if (scanReport.riskScore >= VERDICT_THRESHOLDS.BLOCK) {
    scanReport.verdict = Verdict.BLOCK;
  } else if (scanReport.riskScore >= VERDICT_THRESHOLDS.QUARANTINE) {
    scanReport.verdict = Verdict.QUARANTINE;
  } else if (scanReport.riskScore >= VERDICT_THRESHOLDS.REVIEW) {
    scanReport.verdict = Verdict.REVIEW;
  }

  return scanReport;
};
// מבצע ניתוח מלא על לינק
async function performDeepLinkAnalysis(url, displayText) {
  const signals = [];
  let parsed;

  const cleanUrl = url.trim().replace(/\.+$/, "");
  if (cleanUrl.length > 2048) {
    return [
      {
        type: "EXCESSIVE_URL_LENGTH",
        severity: Severity.MEDIUM,
        confidence: 1.0,
        isPositiveSignal: false,
        reason: "URL length exceeds safe limits.",
      },
    ];
  }

  try {
    parsed = new URL(cleanUrl);
  } catch (e) {
    return [
      {
        type: "INVALID_URL_FORMAT",
        severity: Severity.MEDIUM,
        confidence: 1.0,
        isPositiveSignal: false,
        reason: "URL parser failed to read the link.",
      },
    ];
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();

  // בדיקת פרוטוקול חריג (לא מתחיל ב-http)
  if (!protocol.startsWith("http")) {
    signals.push({
      type: "UNUSUAL_PROTOCOL",
      severity: Severity.HIGH,
      confidence: 1.0,
      isPositiveSignal: false,
      reason: `Unusual protocol detected (${protocol.replace(":", "")}). Attackers use this to bypass web filters or trigger direct downloads.`,
    });

    // עוצרים כאן ומחזירים את ההתראה, כי שאר הבדיקות מיועדות לאתרי אינטרנט בלבד
    return signals;
  }

  // מפת מותגים ודומיינים לגיטימיים
  const BRAND_DOMAINS = {
    apple: [
      "apple.com",
      "icloud.com",
      "itunes.com",
      "apple-support.com",
      "me.com",
    ],
    google: [
      "google.com",
      "gstatic.com",
      "googleusercontent.com",
      "googleapis.com",
      "youtube.com",
    ],
    amazon: ["amazon.com", "aws.amazon.com", "media-amazon.com"],
    microsoft: ["microsoft.com", "office.com", "outlook.com", "live.com"],
    paypal: ["paypal.com", "paypalobjects.com"],
    mongodb: ["mongodb.com", "mongodb.net"],
    leetcode: ["leetcode.com"],
  };

  // בודקים את הפרוטוקול
  if (protocol === "http:") {
    signals.push({
      type: "UNSECURE_CONNECTION",
      severity: Severity.LOW,
      confidence: 1.0,
      isPositiveSignal: false,
      reason: "Link uses unencrypted HTTP instead of HTTPS.",
    });
  }

  // בודקים אם מדובר בIP
  if (net.isIP(hostname)) {
    signals.push({
      type: "IP_BASED_URL",
      evidence: hostname,
      severity: Severity.HIGH,
      confidence: 1.0,
      isPositiveSignal: false,
      reason: "The link points directly to an IP address instead of a domain.",
    });
  }

  // בודק סיומות דומיין חשודות
  const suspiciousTLDs = [".xyz", ".top", ".zip", ".work", ".click", ".link"];
  if (suspiciousTLDs.some((tld) => hostname.endsWith(tld))) {
    signals.push({
      type: "SUSPICIOUS_TLD",
      severity: Severity.MEDIUM,
      confidence: 0.85,
      isPositiveSignal: false,
      reason: `Suspicious top-level domain (.${hostname.split(".").pop()}) detected.`,
    });
  }

  // לוגיקת בדיקת מותגים (Brand Spoofing)
  let brandDetected = null;
  const brands = Object.keys(BRAND_DOMAINS);
  for (const brand of brands) {
    if (hostname.includes(brand)) {
      brandDetected = brand;
      break;
    }
  }

  if (brandDetected) {
    const allowedDomains = BRAND_DOMAINS[brandDetected];
    const isLegit = allowedDomains.some((domain) => hostname.endsWith(domain));
    if (!isLegit) {
      signals.push({
        type: "BRAND_SPOOFING",
        severity: Severity.HIGH,
        confidence: 0.9,
        isPositiveSignal: false,
        reason: `URL mentions "${brandDetected}" but points to "${hostname}", which is not verified.`,
      });
    }
  }

  // בודק אם הטקסט מכיל אותיות משפות אחרות (Homograph)
  if (hostname.includes("xn--") || isMixedScript(hostname)) {
    signals.push({
      type: "HOMOGRAPH_ATTACK",
      evidence: hostname,
      severity: Severity.CRITICAL,
      confidence: 0.95,
      isPositiveSignal: false,
      reason: "Potential domain spoofing detected via mixed character sets.",
    });
  }

  // בודק אי-התאמה בין טקסט לכתובת
  if (displayText && isDomainMismatch(displayText, hostname)) {
    signals.push({
      type: "DOMAIN_MISMATCH",
      evidence: { display: displayText, actual: hostname },
      severity: Severity.HIGH,
      confidence: 0.9,
      isPositiveSignal: false,
      reason: `Link text mimics a domain ("${displayText}") but points to "${hostname}".`,
    });
  }

  return signals;
}
//אי התאמה בין הקישור לטקסט
function isDomainMismatch(display, actualHostname) {
  const displayClean = display.toLowerCase().trim();
  const actualClean = actualHostname.toLowerCase().trim().replace("www.", "");

  // בדיקת "נראה כמו דומיין"
  const looksLikeDomain = /^[a-z0-9-]+\.[a-z0-9.-]+$/i.test(
    displayClean.replace("https://", "").replace("http://", "").split("/")[0],
  );
  if (!looksLikeDomain) return false;

  const displayDomain = displayClean
    .replace("https://", "")
    .replace("http://", "")
    .replace("www.", "")
    .split("/")[0];

  const isExactMatch = actualClean === displayDomain;
  const isSubdomain = actualClean.endsWith("." + displayDomain);

  return !isExactMatch && !isSubdomain;
}
// אותיות מכמה שפות שונות
function isMixedScript(hostname) {
  const hasLatin = /[a-z]/i.test(hostname);
  const hasCyrillic = /[\u0400-\u04FF]/.test(hostname);
  const hasHebrew = /[\u0590-\u05FF]/.test(hostname);
  return (
    (hasLatin && hasCyrillic) ||
    (hasLatin && hasHebrew) ||
    (hasCyrillic && hasHebrew)
  );
}
//בדיקה עם הרשימה השחורה של גוגל
async function checkSafeBrowsingWithTimeout(urls) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3500);

  try {
    const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
    if (!API_KEY) return [];

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
    const body = {
      client: { clientId: "upwind-amit", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map((url) => ({ url })),
      },
    };

    const response = await fetch(endpoint, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
    });

    const data = await response.json();
    if (data.matches) {
      return data.matches.map((match) => ({
        type: "BLACKLISTED_URL",
        severity: Severity.CRITICAL,
        confidence: 1.0,
        isPositiveSignal: false,
        reason: `Flagged by Google as ${match.threatType}`,
      }));
    }
    return [];
  } catch (e) {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { analyzeLinks };
