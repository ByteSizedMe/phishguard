# PhishGuard

PhishGuard is a backend security service that analyses URLs for phishing and malicious activity.

It combines structural URL analysis, typosquatting detection, external reputation checks, explainable risk scoring, API key authentication, rate limiting, and persistent analysis history — returning granular, per-signal reasoning rather than a black-box verdict.

Built with **Node.js · Express · TypeScript · PostgreSQL**

---

## Features

| Feature | Description |
|---|---|
| URL risk analysis | 15+ structural and behavioural signals analysed per URL |
| Explainable scoring | Per-signal breakdown with points — not just a verdict |
| Typosquatting detection | Damerau-Levenshtein distance, homoglyph, IDN, prefix/suffix mutations |
| Reputation checks | Google Safe Browsing + URLhaus integration |
| Batch analysis | Up to 20 URLs per request, processed in parallel |
| API key authentication | Bearer token auth, bcrypt-hashed storage |
| Rate limiting | 100 requests per 15-minute window per IP |
| Analysis history | Per-key persistent history in PostgreSQL |

---

## Risk Scoring

PhishGuard produces a numerical risk score from individual signals, each contributing a weighted point value. The final score maps to a risk level:

| Score | Risk Level |
|------:|---|
| 0 – 7 | Low |
| 8 – 14 | Suspicious |
| 15 – 22 | High |
| 23+ | Very High |

Every response includes the signals that fired, their messages, and their point contributions — making results auditable and debuggable.

---

## Signals

### Structural Analysis

| Signal | Description |
|---|---|
| IP address hostname | URL uses a raw IP instead of a domain name |
| Suspicious TLD | Domain uses a TLD associated with abuse (`.tk`, `.xyz`, `.zip` etc.) |
| Excessive URL length | URL or hostname exceeds normal length thresholds |
| High subdomain count | Unusually deep subdomain hierarchy |
| Suspicious keywords | Phishing-related terms in hostname or pathname |
| High digit count | Unusual number of digits in hostname |
| High entropy | Hostname character distribution consistent with generated domains |
| Encoded characters | Unusual URL encoding in path, query, or credentials |
| Double encoding | Evasion attempt via `%25xx` double-encoding |
| Punycode / IDN | Internationalised domain name that may use homoglyph characters |
| At symbol | Credential-style `@` in URL obscuring actual destination |
| Redirect parameters | Query parameters pointing to external destinations |

### Typosquatting Detection

Domains are compared against a dataset of legitimate domains using:

| Technique | Description |
|---|---|
| Damerau-Levenshtein distance | Catches insertions, deletions, substitutions, transpositions |
| Homoglyph normalisation | Detects Cyrillic/Greek characters substituted for Latin equivalents |
| Digit substitution | Detects `0→o`, `1→l`, `3→e` and similar visual substitutions |
| IDN / Punycode detection | Catches internationalised domain homograph attacks |
| Prefix / suffix mutation | Detects `paypal-login.com`, `secure-google.com` patterns |
| TLD variation | Detects `paypal.xyz`, `google.tk` suspicious TLD swaps |

### Reputation Checks

| Provider | Coverage |
|---|---|
| Google Safe Browsing | Phishing, malware, social engineering, unwanted software — URL and host-level via suffix/prefix matching |
| URLhaus | Exact malicious URL match + host-level association check with shared-infrastructure suppression |

URLhaus host matches are informational only (0 points) unless the host is non-Tranco with active online malicious URLs, to prevent false positives on shared infrastructure like GitHub or Google Docs.

---

## API Reference

### Authentication

All protected endpoints require a Bearer token:

```http
Authorization: Bearer YOUR_API_KEY
```

### Endpoints

#### `POST /api/keys` — Generate API Key

Generates a new API key. The raw key is returned once and not stored — save it securely.

> **Note:** In v1 this endpoint is intended for controlled internal use. Public key provisioning requires additional authorisation logic.

**Response:**

```json
{
  "apiKey": "YOUR_API_KEY"
}
```

---

#### `POST /api/analyze` — Analyse URLs

Analyses between 1 and 20 URLs and returns a risk assessment for each.

**Headers:**

```http
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Request:**

```json
{
  "urls": [
    "https://www.google.com",
    "https://paypa1-login.xyz/verify/account"
  ]
}
```

**Response — clean URL:**

```json
{
  "url": "https://www.google.com",
  "score": 0,
  "level": "Low",
  "signals": []
}
```

**Response — suspicious URL:**

```json
{
  "url": "https://paypa1-login.xyz/verify/account",
  "score": 31,
  "level": "Very High",
  "signals": [
    {
      "feature": "typosquatting",
      "message": "Domain is similar to paypal.com (substitution, digit substitution)",
      "points": 15
    },
    {
      "feature": "suspiciousTld",
      "message": "URL contains suspicious TLD",
      "points": 3
    },
    {
      "feature": "hostnameSuspiciousKeywords",
      "message": "Hostname contains suspicious keywords",
      "points": 3
    },
    {
      "feature": "pathnameSuspiciousKeywords",
      "message": "Pathname contains suspicious keywords",
      "points": 1
    }
  ]
}
```

**Validation errors:**

| Condition | Status | Error |
|---|---|---|
| Missing `urls` field | `400` | `URLs are required` |
| `urls` is not an array | `400` | `URLs must be an array` |
| Empty array | `400` | `URL list is empty` |
| Non-string URL | `400` | `Every URL must be a string` |
| Empty string URL | `400` | `URL cannot be empty` |
| More than 20 URLs | `400` | `Batch limit is 20 URLs` |
| Rate limit exceeded | `429` | `Too Many Requests` |

---

#### `GET /api/history` — Analysis History

Returns all analyses associated with the authenticated API key.

**Headers:**

```http
Authorization: Bearer YOUR_API_KEY
```

**Response:**

```json
[
  {
    "url": "https://example.com",
    "score": 2,
    "level": "Low",
    "analyzed_at": "2026-08-30T10:00:00Z"
  }
]
```

History is scoped to the authenticated key — one key cannot access another key's history.

---

## Architecture

```
Client
  |
  | HTTPS
  v
+------------------+
|   Express API    |
|  Auth · Limits   |
+------------------+
         |
   +-----+-----+
   |     |     |
   v     v     v
 URL  Typo- Reputa-
 Ana- squat- tion
 lyzer  ting  Checks
   |     |     |
   +-----+-----+
         |
         v
   Risk Scoring
         |
         v
    PostgreSQL
   +-----+-----+
   |           |
   v           v
API Keys  Analysis
          History
```

---

## Technology Stack

| Technology | Purpose |
|---|---|
| TypeScript | Application language |
| Node.js | Runtime |
| Express | HTTP API framework |
| PostgreSQL | Persistent storage |
| pg | PostgreSQL driver |
| bcrypt | API key hashing |
| Axios | External HTTP requests |
| tldts | Domain and TLD parsing |
| express-rate-limit | Rate limiting |
| Google Safe Browsing API | URL reputation |
| URLhaus API | Malicious URL reputation |

---

## Project Structure

```
PhishGuard/
├── src/
│   ├── data/
│   │   └── legitimate-domains.ts     — Brand/domain dataset for typosquatting
│   │
│   ├── middleware/
│   │   └── api-key.middleware.ts     — Bearer token authentication
│   │
│   ├── routes/
│   │   ├── analyze.routes.ts         — POST /api/analyze
│   │   ├── api-key.routes.ts         — POST /api/keys
│   │   └── history.routes.ts         — GET /api/history
│   │
│   ├── services/
│   │   ├── analysis-history.service.ts
│   │   ├── api-key.service.ts
│   │   ├── database.ts
│   │   ├── risk-scoring.service.ts
│   │   ├── typosquatting.service.ts
│   │   └── url-analyzer.service.ts
│   │
│   ├── types/
│   │   └── express.d.ts
│   │
│   └── server.ts
│
├── .env.example
├── .gitignore
├── package.json
└── tsconfig.json
```

---

## Setup

### Prerequisites

- Node.js (LTS)
- npm
- PostgreSQL
- Google Safe Browsing API key ([obtain here](https://developers.google.com/safe-browsing/v4/get-started))
- URLhaus Auth Key ([obtain here](https://auth.abuse.ch/))

### Installation

```bash
git clone YOUR_REPOSITORY_URL
cd PhishGuard
npm install
```

### Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Required variables:

```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/phishguard
GOOGLE_SAFE_BROWSING_API_KEY=YOUR_KEY
URLHAUS_AUTH_KEY=YOUR_KEY
PORT=3000
```

> Never commit `.env` or API keys to source control.

### Database Setup

```sql
CREATE DATABASE phishguard;

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analysis_history (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    api_key_id INTEGER NOT NULL REFERENCES api_keys(id)
);
```

### Running

```bash
# Build
npm run build

# Start
npm start
```

Server runs at `http://localhost:3000` by default.

---

## Security Design

| Practice | Implementation |
|---|---|
| API key generation | Cryptographically secure random bytes |
| API key storage | bcrypt hash only — raw key never stored |
| Authentication | Bearer token on all protected endpoints |
| History isolation | Analysis history scoped per API key |
| Rate limiting | IP-based, 100 req / 15 min |
| Input validation | All request payloads validated before processing |
| Secret management | All credentials via environment variables |
| Reputation API access | Server-side only — credentials never exposed to clients |

---

## Limitations

PhishGuard is a risk analysis tool, not a guarantee of safety. Detection has inherent limitations:

- Newly registered malicious domains may not appear in reputation databases
- Legitimate services can be abused to host malicious content (shared hosting)
- Attackers rotate URLs and infrastructure rapidly
- URL structure alone cannot determine intent with certainty
- External reputation providers have their own coverage gaps

Risk scores are **indicators**, not absolute classifications.

---

## Status

**PhishGuard v1** — core backend complete.

Includes URL analysis, explainable risk scoring, typosquatting detection, Google Safe Browsing and URLhaus integration, batch analysis, API key authentication, PostgreSQL persistence, per-key history, and rate limiting.

Deployment in progress.

---

## License

Personal and educational use.
