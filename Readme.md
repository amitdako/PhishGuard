# PhishGuard 🛡️

PhishGuard is a lightweight, decoupled Gmail Add-on designed to analyze incoming emails and provide users with a clear, explainable maliciousness score. Rather than just silently blocking emails, it empowers users with a "Risk Score" and actionable insights (Verdict & Reasoning) to understand exactly why an email was flagged.

## Tech Stack

- **Frontend:** Google Workspace Apps Script
- **Backend:** Node.js, Express.js
- **Security Integrations:** Google Safe Browsing API, Custom NLP & Regex Engines

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

## Core Features & Detection Engines

Rather than relying on a single point of failure, PhishGuard routes email data through specialized analyzers and aggregates the results:

The Correlation Engine (Aggregator): The heart of the system. It weights signals from different analyzers to calculate a final Risk Score. For example, a suspicious financial request might flag a REVIEW status, but if combined with an SPF failure, the correlation engine escalates it to a hard BLOCK.

URL Unwrapping: Defeats common evasion techniques by resolving and unwrapping redirected URLs (e.g., Google search redirects) before scanning them against the Safe Browsing API.

Homograph & Mixed-Script Detection: Identifies domain spoofing and malicious attachments by detecting Cyrillic/Latin character mixing in file names and links.

HTML Smuggling Prevention: Flags .html and .svg attachments, recognizing them as modern vectors for bypassing network filters to drop local payloads.

## Trade-offs & Future Work

Building this within a limited timeframe required prioritizing core architecture and deterministic security rules over experimental features. If I were to take this project to production, I would focus on the following enhancements:

AI-Powered Content Analysis (LLM Integration):

Current State: The ContentAnalyzer uses a threshold-based NLP ruleset (Regex/Keyword arrays) to detect Social Engineering and BEC (Business Email Compromise). It is extremely fast and cost-effective.

Future State: Integrate a lightweight LLM API to analyze the contextual intent of the email body. This would significantly reduce false positives when dealing with subtle psychological manipulation or highly targeted spear-phishing, where traditional keywords fail.

Persistent Threat Intelligence (Database):

Integrate a database (e.g., MongoDB) to log malicious hashes and URLs over time, creating an internal cache that speeds up future analyses without repeatedly querying external APIs.

## Getting Started (Local Development)

To run this project locally and connect it to your Gmail account, follow these steps:

Prerequisites

- Node.js (v16 or higher)
- ngrok (to expose the local backend to Google Apps Script)
- A Google Cloud project with the Safe Browsing API enabled.

### 1. Backend Setup

1. Navigate to the Server directory:
   cd Server

2. Install the required dependencies:
   npm install

3. Create a .env file in the root of the Server directory and add your configuration:
   GOOGLE_SAFE_BROWSING_KEY=your_api_key_here
   PORT=3000

4. Start the Node.js server:
   npm start

5. In a separate terminal window, start ngrok to expose your local port:
   ngrok http 3000

(Keep the terminal open and copy the generated HTTPS URL, e.g., https://xyz.ngrok-free.app)

### 2. Frontend (Gmail Add-on) Setup

1. Go to Google Apps Script and create a new project.
2. Copy the contents of Add-on/Code.gs into the script editor.
3. Open the Project Settings (gear icon) and check the box for "Show 'appsscript.json' manifest file in editor".
4. Go back to the editor, open appsscript.json, and paste the contents from Add-on/appsscript.json.
5. In Code.gs, locate the API endpoint variable (SERVER_URL) and update it with your active ngrok HTTPS URL.
6. Save the project, then click Deploy > Test deployments.
7. Select "Gmail" as the application, click Install, and grant the necessary permissions.
8. Open your Gmail, click on any email, and open the PhishGuard add-on from the right-hand side panel to see it in action!
