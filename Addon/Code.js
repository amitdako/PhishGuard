const SERVER_URL = "https://YOUR_NGROK_URL.ngrok-free.app/api/analyze"; // אנא עדכנו את הקישור שלכם לפני שאתם מריצים
const MAX_BODY_LENGTH = 50000; // הגבלת גודל למניעת עומס

// הפונקציה הראשית שגוגל מפעילה כשפותחים מייל
function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var cache = CacheService.getUserCache();
  var cachedResult = cache.get(messageId); // נועד למנוע מצב שנכנסו למייל פעמיים והוא צריך לחשב שוב.
  if (cachedResult) {
    return createAnalysisCard(JSON.parse(cachedResult));
  }

  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken); // נותן גישה רק למייל הנוכחי
  var message = GmailApp.getMessageById(messageId);

  var safeBodyText = message.getPlainBody().slice(0, MAX_BODY_LENGTH);
  var rawContent = message.getRawContent(); // מייל גולמי כולל הדרס

  // חילוץ כותרת ה-Authentication
  const authMatch = rawContent.match(
    /^Authentication-Results:(.*(?:\r?\n[ \t].+)*)/im,
  );
  const authHeader = authMatch ? authMatch[1].replace(/\r?\n\s+/g, " ") : "";

  // חבילת המידע  שנשלחת לשרת
  var emailData = {
    headers: { "authentication-results": authHeader },
    body: safeBodyText,
    links: extractLinks(safeBodyText),
    attachments: extractAttachmentMetadata(message.getAttachments()),
  };

  // שליחה לשרת
  var analysis = callPhishGuardServer(emailData);

  // שמירה ב-Cache ל-10 דקות
  if (!analysis.error && analysis.summary) {
    cache.put(messageId, JSON.stringify(analysis), 600);
  }

  return createAnalysisCard(analysis);
}

//חילוץ לינקים
function extractLinks(text) {
  var links = [];
  var seenUrls = {}; // אובייקט עזר למניעת כפילויות
  // מחפשים לינקים מורכבים שיש להם דיספלי טקסט שונה.
  var complexRegex = /([^>\n\r]{2,50})\s*<([a-zA-Z0-9]+:\/\/[^\s>]+)>/gi;
  var match;

  while ((match = complexRegex.exec(text)) !== null) {
    // כל עוד מוצאים עוד התאמה רצים
    var url = match[2].trim(); // כתובת אמיתית

    //האם כבר ראינו את הכתובת הזו?
    if (!seenUrls[url]) {
      var display = match[1].trim(); //טקסט מוצג
      if (display.split(" ").length > 4) display = "Link";

      links.push({
        url: url,
        displayText: display,
      });
      seenUrls[url] = true; // מסמנים שראינו כדי לא להוסיף שוב
    }
  }

  //חיפוש לינקים פשוטים בלי דיספלי טקסט
  var simpleRegex = /([a-zA-Z0-9]+:\/\/[^\s<]+)/gi;
  var simpleMatch;
  while ((simpleMatch = simpleRegex.exec(text)) !== null) {
    var simpleUrl = simpleMatch[1].trim();
    // בודקים שלא בדקנו אותו כבר
    if (!seenUrls[simpleUrl]) {
      links.push({
        url: simpleUrl,
        displayText: simpleUrl,
      });
      seenUrls[simpleUrl] = true;
    }
  }

  return links;
}

// משיכת מידע על הקבצים
function extractAttachmentMetadata(attachments) {
  return attachments.map(function (att) {
    return {
      filename: att.getName(),
      mimeType: att.getContentType(),
      size: att.getSize(),
    };
  });
}

// תקשורת אל מול השרת
function callPhishGuardServer(data) {
  console.log("Sending request to: " + SERVER_URL);
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(data),
    muteHttpExceptions: true, // לא להתרסק, רק להחזיר שגיאה
    followRedirects: false,
  };

  try {
    var response = UrlFetchApp.fetch(SERVER_URL, options);
    var responseCode = response.getResponseCode();

    if (responseCode !== 200) {
      return { error: true, message: "Server error: " + responseCode };
    }

    return JSON.parse(response.getContentText());
  } catch (err) {
    console.error("Connection error: " + err.toString());
    return { error: true, message: "Connection failed" };
  }
}

// יצירת דף מידע שיוצג
function createAnalysisCard(result) {
  if (result.error) {
    // אם חזרה שגיאה
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("❌ Connection Error"))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            "PhishGuard could not reach the analysis server.",
          ),
        ),
      )
      .build();
  }

  if (!result || !result.summary) {
    // לא חזר מידע
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("❌ Data Format Error"))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            "Received unexpected response from server. Check logs.",
          ),
        ),
      )
      .build();
  }

  var verdict = result.summary.verdict;
  var score = result.summary.riskScore;

  var statusEmoji = "✅";
  if (verdict === "BLOCK") statusEmoji = "🚨 Dangerous:";
  else if (verdict === "QUARANTINE" || verdict === "REVIEW")
    statusEmoji = "⚠️ Suspicious:";

  var section = CardService.newCardSection().setHeader(
    "Risk Score: " + score + "/100",
  );

  var threatsAdded = false;

  if (result.detailedSignals && result.detailedSignals.length > 0) {
    result.detailedSignals.forEach(function (signal) {
      if (!signal.isPositiveSignal) {
        var icon =
          signal.severity === "CRITICAL" || signal.severity === "HIGH"
            ? "🚩 "
            : "🔹 ";
        section.addWidget(
          CardService.newTextParagraph().setText(icon + signal.reason),
        );
        threatsAdded = true;
      }
    });
  }

  if (!threatsAdded) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        "✅ All checks passed smoothly. No threats found.",
      ),
    );
  }

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader().setTitle(statusEmoji + " " + verdict),
    )
    .addSection(section)
    .build();
}
