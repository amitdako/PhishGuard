# PhishGuard 🛡️

PhishGuard is a lightweight, decoupled Gmail Add-on designed to analyze incoming emails and provide users with a clear, explainable maliciousness score. Rather than just silently blocking emails, it empowers users with a "Risk Score" and actionable insights (Verdict & Reasoning) to understand exactly why an email was flagged.

## Tech Stack

- **Frontend:** Google Workspace Apps Script
- **Backend:** Node.js, Express.js (Custom Middleware Architecture)
- **Security Integrations:** Google Safe Browsing API, Custom NLP & Regex Engines

---

## Architecture & Design Decisions

The solution is divided into two decoupled components to ensure lightweight client-side execution and heavy lifting on the server. I chose a **Push Model** where the Add-on extracts the data and sends it to the server, rather than granting the backend OAuth permissions to fetch emails directly via Google APIs.

- **Frontend (Gmail Add-on):** Built with Google Workspace Apps Script. It safely extracts data from the currently opened email (headers, body, links, attachments), pushes the payload to the server, and renders the final UI cards.
- **Backend (Node.js):** A stateless REST API utilizing robust middleware to route and process the email components through dedicated Analyzer modules.

This architectural trade-off was driven by several key considerations:

- **Principle of Least Privilege:** The Add-on only requests access to the _currently opened_ email. A server-pull approach would require sweeping permissions to the user's entire inbox, creating unnecessary friction and trust barriers.
- **Zero-Secret Architecture:** The backend does not store OAuth refresh tokens. This eliminates a massive attack surface, as there is no central database of credentials for an attacker to compromise.
- **Statelessness & Scalability:** The backend acts purely as a compute engine. Because it holds no persistent state or sessions, it is highly scalable and ready for Serverless deployment.
- **The Security Trade-off:** Because the backend receives data pushed from the client, it must treat the payload as highly untrusted. To mitigate injection and exploitation risks, I implemented strict input validation, payload size limits (to prevent DoS), and input sanitization prior to analysis.

---

## Project Structure

A quick overview of the repository to help you navigate the codebase:

```text
├── Add-on/
│   ├── Code.gs               # Main Google Apps Script logic (UI & API calls)
│   └── appsscript.json       # Add-on manifest and permissions
│
├── Server/
│   ├── Analyzers/            # Modular detection engines
│   │   ├── AuthAnalyzer.js   # Parses DMARC/SPF/DKIM/ARC headers
│   │   ├── ContentAnalyzer.js# NLP threshold-based social engineering detection
│   │   ├── LinkAnalyzer.js   # URL unwrapping and domain spoofing checks
│   │   └── AttachmentAnalyzer.js # Extension, MIME type, and anomaly scanning
│   ├── Aggregator.js         # Core correlation engine calculating the final Risk Score
│   ├── constants.js          # Shared severity weights and thresholds
│   └── server.js             # Express.js server and API routes
│
└── README.md
```
