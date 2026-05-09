require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { analyzeAuth } = require("./Analyzers/AuthAnalyzer");
const { analyzeLinks } = require("./Analyzers/LinkAnalyzer");
const { analyzeAttachments } = require("./Analyzers/AttachmentAnalyzer");
const { analyzeContent } = require("./Analyzers/ContentAnalyzer");
const { aggregateRisk } = require("./Aggregator");

const app = express();
const PORT = process.env.PORT || 3000; // למי יש גישה?

app.use(cors()); //
app.use(express.json({ limit: "1mb" }));

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
}); // בודקים אם השרת חי וער

app.post("/api/analyze", async (req, res) => {
  // אסינכרוני כי יש לחכות לפעולות לפני שממשיכים.
  console.log("Incoming links:", JSON.stringify(req.body.links, null, 2));
  try {
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "Invalid request body" });
    } // מוודאים שיש באמת תוכן.

    const { headers = {}, body = "", links = [], attachments = [] } = req.body;

    const [authReport, linkReport, attachmentReport, contentReport] =
      await Promise.all([
        analyzeAuth(headers?.["authentication-results"] || ""),
        analyzeLinks(links),
        analyzeAttachments(attachments),
        analyzeContent(body),
      ]); // מנתחים את כל הנתונים.

    // מסכמים את התוצאות ומקבלים ניתוח סופי
    const finalAnalysis = aggregateRisk({
      authReport,
      linkReport,
      attachmentReport,
      contentReport,
    });
    console.log(
      "🚀 Final output going to Google:",
      JSON.stringify(finalAnalysis, null, 2),
    );
    return res.json(finalAnalysis); // מחזירים את הניתוח שהגענו אליו.
  } catch (error) {
    console.error("CRITICAL_SERVER_ERROR:", error); //מדפיסים רק לי את השגיאה, מטעמי אבטחה
    console.log(
      "🚀 Final output going to Google:",
      JSON.stringify(finalAnalysis, null, 2),
    );
    return res.status(500).json({
      error: "Internal Server Error",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Analysis Server running on http://localhost:${PORT}`); // מתחילים להאזין לבקשות שמגיעות מהשרת.
});
