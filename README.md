# AI Phishing Email Investigator

**IBM SkillsBuild Capstone Project**

A professional cybersecurity web application that uses **Google Gemini AI** to investigate suspicious emails, identify phishing indicators, evaluate email security risks, and generate structured investigation reports.

---

## Features

- **AI-Powered Email Analysis** — Submits email data to an OpenAI-compatible API for structured phishing investigation
- **12-Section Investigation Reports** — Executive summary, sender analysis, social engineering detection, URL analysis, header analysis, evidence classification, risk assessment, and recommendations
- **Risk & Confidence Assessment** — Separate LOW / MEDIUM / HIGH / CRITICAL risk levels and LOW / MEDIUM / HIGH confidence levels
- **Evidence Categorization** — Distinguishes confirmed observations, suspicious indicators, and unverified assumptions
- **Investigation History** — Saves all results to localStorage with view, delete, and clear functionality
- **Authentication Analysis** — SPF, DKIM, and DMARC evaluation when results are provided
- **Professional Cybersecurity UI** — Dark navy dashboard with sidebar navigation, responsive layout
- **Secure Architecture** — API credentials stored server-side only, never exposed to the browser

---

## Project Structure

```
CAPSTONE_IBMXHACKTIV8/
├── index.html              # Frontend HTML — all pages
├── style.css               # Cybersecurity dashboard stylesheet
├── script.js               # Frontend logic — navigation, forms, rendering
├── server.js               # Node.js/Express backend — API proxy
├── package.json            # Node.js dependencies
├── .env.example            # Environment variable template
├── prompts/
│   └── system-prompt.md    # AI system prompt with investigation rules
└── README.md               # This file
```

---

## Prerequisites

- **Node.js** v18 or later
- A **Google Gemini API key** — obtain for free at [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

---

## Installation

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Copy the example environment file:

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Open `.env` and fill in your Gemini credentials:

```env
GEMINI_API_KEY=your-gemini-api-key-here
GEMINI_MODEL=gemini-2.0-flash
PORT=3000
```

| Variable | Description | Default |
|---|---|---|
| `GEMINI_API_KEY` | Your Google Gemini API key (from AI Studio) | *(required)* |
| `GEMINI_MODEL` | Gemini model to use | `gemini-2.0-flash` |
| `PORT` | Server port | `3000` |

**Getting a Gemini API Key:**
1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Sign in with your Google account
3. Click **Create API key**
4. Copy the key and paste it as `GEMINI_API_KEY` in your `.env` file

---

## Running the Application

### Start the Backend Server

```bash
npm start
```

You should see:

```
============================================================
  AI Phishing Email Investigator
  IBM SkillsBuild Capstone Project
============================================================
  Server running at: http://localhost:3000
  API configured:    YES ✓
  Model:             gpt-4o
  Base URL:          https://api.openai.com/v1
============================================================
```

### Open the Frontend

Open your browser and navigate to:

```
http://localhost:3000
```

The Express server serves the frontend (`index.html`, `style.css`, `script.js`) as static files, so no separate frontend server is needed.

---

## Usage

### Performing an Investigation

1. Navigate to the **Investigate** page from the sidebar
2. Fill in the required fields:
   - Sender Name
   - Sender Email Address
   - Email Subject
   - Email Body
3. Optionally provide:
   - Suspicious URL (paste as plain text — not clicked)
   - SPF / DKIM / DMARC authentication results
   - Raw email headers
4. Click **Analyze Email**
5. Wait for the AI analysis (typically 10–30 seconds)
6. Review the structured investigation report

### Viewing History

- Navigate to **History** to see all previous investigations
- Click **View** to open a full report in a modal
- Click **Delete** to remove individual records
- Click **Clear All History** to remove all records

---

## API Endpoints

### `POST /api/analyze`

Submits email data for AI analysis.

**Request Body:**
```json
{
  "senderName": "Security Team",
  "senderEmail": "security@example.com",
  "subject": "Urgent! Account suspended",
  "emailBody": "...",
  "url": "http://suspicious-link.example/login",
  "rawHeaders": "From: ...\nReply-To: ...",
  "spfResult": "FAIL",
  "dkimResult": "NONE",
  "dmarcResult": "FAIL"
}
```

**Response (success):**
```json
{
  "success": true,
  "result": {
    "executiveSummary": "...",
    "riskLevel": "HIGH",
    "confidenceLevel": "MEDIUM",
    "threatClassification": "Potential Phishing",
    ...
  }
}
```

**Response (error):**
```json
{
  "error": "Error message describing the problem.",
  "type": "CONFIG_ERROR | AUTH_ERROR | RATE_LIMIT | TIMEOUT | ..."
}
```

### `GET /api/health`

Returns API configuration status.

```json
{
  "status": "ok",
  "apiConfigured": true,
  "provider": "Google Gemini",
  "model": "gemini-2.0-flash",
  "timestamp": "2026-11-23T06:00:00.000Z"
}
```

---

## Architecture

```
Browser (Frontend)              Server (Backend)               Google Gemini
─────────────────               ────────────────               ─────────────
index.html                      server.js                      Gemini API
style.css        ──HTTP──►      Express                        (AI Studio /
script.js        POST /api/analyze                              Google Cloud)
                 ◄──JSON──      • Validates input
                                • Loads system prompt
                 localStorage   • @google/genai SDK ──HTTPS──► generateContent
                 (history)      • Parses JSON       ◄──JSON──
                                • Returns result
```

**Key architectural decisions:**

- The `GEMINI_API_KEY` is stored in a `.env` file and loaded server-side only. It is never sent to the browser.
- Email content is treated as untrusted input. The backend sanitizes all fields before forwarding to Gemini.
- `responseMimeType: 'application/json'` instructs Gemini to return structured JSON directly.
- The system prompt is passed as `config.systemInstruction` and the user message as `contents`.
- The frontend communicates exclusively with the local Express backend, never directly with Gemini.

---

## Security Considerations

- API credentials are stored in environment variables — never in frontend code
- Request body size is limited to 50kb to prevent abuse
- All user inputs are sanitized (trimmed, null bytes removed) before processing
- Submitted URLs are never opened, executed, or resolved
- The frontend escapes all rendered content to prevent XSS
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`) are set on all responses

---

## Investigation Accuracy Notes

This application follows strict accuracy rules:

- HTTP usage, unusual domain names, and domain mismatches are treated as contextual indicators, not standalone proof of phishing
- URLs are analyzed structurally only — no DNS lookups, reputation checks, or URL visits are performed
- Authentication results are analyzed only when user-provided — no independent verification is claimed
- Reserved domains (e.g., `example.com`) are treated as documentation placeholders, not active infrastructure
- Risk level and confidence level are assessed independently
- Related indicators are consolidated to prevent double-counting

---

## Implemented Features

| Feature | Status |
|---|---|
| Dashboard with statistics | ✅ Implemented |
| Email investigation form with validation | ✅ Implemented |
| AI-powered analysis via backend API | ✅ Implemented (requires API key) |
| 12-section structured investigation report | ✅ Implemented |
| Risk and confidence level display | ✅ Implemented |
| Investigation history (localStorage) | ✅ Implemented |
| History modal viewer | ✅ Implemented |
| Delete / clear history | ✅ Implemented |
| About page | ✅ Implemented |
| API health check indicator | ✅ Implemented |
| Responsive layout (desktop/tablet/mobile) | ✅ Implemented |
| Input sanitization and validation | ✅ Implemented (frontend + backend) |

## Features Requiring API Configuration

| Feature | Requirement |
|---|---|
| AI email analysis | Valid `GEMINI_API_KEY` in `.env` |
| Model selection | Set `GEMINI_MODEL` in `.env` (default: `gemini-2.0-flash`) |

Without API configuration, the dashboard, history, and all UI features remain fully functional. Only the AI analysis submission will return a configuration error.

---

## Supported Gemini Models

| Model | Notes |
|---|---|
| `gemini-3.5-flash` | Recommended — fast, capable, strong JSON output |
| `gemini-3.6-flash` | Alternative flash option |
| `gemini-3.5-flash-lite` | Lightweight, lower cost |

---

## License

MIT — IBM SkillsBuild Capstone Project
