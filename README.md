# PhishGuard

PhishGuard is a backend security service that analyses URLs for phishing and malicious activity.

It combines structural URL analysis, typosquatting detection, external reputation checks, explainable risk scoring, API key authentication, rate limiting, and persistent analysis history — returning granular, per-signal reasoning rather than a black-box verdict.

Built with **Node.js · Express · TypeScript · PostgreSQL**

**Live API:** https://phishguard-d1bp.onrender.com  
**GitHub:** https://github.com/ByteSizedMe/PhishGuard

---

## Features

| Feature | Description |
|---|---|
| URL risk analysis | 15+ structural and behavioural signals analysed per URL |
| Explainable scoring | Per-signal breakdown with points — not just a verdict |
| Typosquatting detection | Damerau-Levenshtein distance, homoglyph, IDN, prefix/suffix mutations |
| Reputation checks | Google Safe Browsing + URLhaus integration |
| Batch analysis | Up to 20 URLs per request, processed in parallel |
| API key authentication | Bearer token authentication with bcrypt-hashed storage |
| Self-service API key generation | Browser-based key generation protected by Cloudflare Turnstile and IP-based rate limiting |
| Rate limiting | 100 analysis requests per 15-minute window per IP; 3 API key generation attempts per hour per IP |
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

Protected endpoints require a Bearer token:

```http
Authorization: Bearer YOUR_API_KEY
```

API keys are cryptographically generated and stored server-side only as bcrypt hashes. The raw API key is returned only when it is generated and must be stored securely by the user.

### Getting an API Key

PhishGuard provides self-service API key generation.

Open:

```text
GET /get-key
```

Complete the Cloudflare Turnstile verification and generate an API key.

The raw API key is displayed only at generation time. Store it securely before using it with the protected API endpoints.

Use the generated key as a Bearer token:

```http
Authorization: Bearer YOUR_API_KEY
```

---

### Endpoints

#### `POST /api/keys` — Generate API Key

Generates a new PhishGuard API key.

API key generation uses Cloudflare Turnstile to reduce automated abuse and is protected by an IP-based rate limit of 3 generation attempts per hour.

**Request:**

```http
Content-Type: application/json
```

```json
{
  "turnstileToken": "TURNSTILE_TOKEN"
}
```

The Turnstile token is generated by the browser-based key generation page at `/get-key`.

**Response:**

```json
{
  "apiKey": "YOUR_API_KEY",
  "message": "API key generated successfully. Store it securely."
}
```

The raw API key is returned only when generated and is not stored directly by PhishGuard. Store it securely after generation.

**Key generation page:**

```text
GET /get-key
```

The page renders the Cloudflare Turnstile widget and submits the resulting token to `POST /api/keys`.

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
  "score": 22,
  "level": "High",
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

History is scoped to the authenticated API key. One key cannot access another key's history.

---

#### `GET /` — API Status

Returns basic information about the deployed API.

**Response:**

```json
{
  "name": "PhishGuard API",
  "status": "online",
  "message": "Phishing and malicious URL analysis API",
  "endpoints": {
    "analyze": "POST /api/analyze",
    "history": "GET /api/history",
    "apiKeys": "POST /api/keys",
    "getKey": "GET /get-key"
  }
}
```

---

## Architecture

```text
                         Internet
                            |
                            v
                    +----------------+
                    |  Render Server |
                    |  Express API   |
                    +----------------+
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
          URL Analysis  Authentication  Rate Limiting
              |             |             |
              v             v             v
        Typosquatting    API Keys     IP-based limits
              |             |
              v             |
       Reputation Checks    |
        |             |     |
        v             v     |
  Google Safe      URLhaus  |
   Browsing               |
        \             /   |
         \           /    |
          v         v     v
          Risk Scoring
               |
               v
        Supabase PostgreSQL
          |            |
          v            v
       API Keys    Analysis History


        API KEY GENERATION
               |
               v
        Browser /get-key
               |
               v
        Cloudflare Turnstile
               |
               v
          POST /api/keys
               |
               v
       Generate + bcrypt hash
               |
               v
        Supabase PostgreSQL
```

PhishGuard is deployed as a Render web service with persistent PostgreSQL storage hosted on Supabase.

External reputation checks are performed server-side using Google Safe Browsing and URLhaus.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| TypeScript | Application language |
| Node.js | Runtime |
| Express | HTTP API framework |
| PostgreSQL | Persistent storage |
| Supabase | Hosted PostgreSQL infrastructure |
| pg | PostgreSQL driver |
| bcrypt | API key hashing |
| Axios | External HTTP requests |
| tldts | Domain and TLD parsing |
| express-rate-limit | Rate limiting |
| Cloudflare Turnstile | Bot protection for API key generation |
| Google Safe Browsing API | URL reputation |
| URLhaus API | Malicious URL reputation |
| Render | API deployment |

---

## Project Structure

```text
PhishGuard/
├── src/
│   ├── data/
│   │   └── legitimate-domains.ts     — Brand/domain dataset for typosquatting
│   │
│   ├── middleware/
│   │   ├── api-key.middleware.ts     — Bearer token authentication
│   │   └── key-generation-rate-limit.middleware.ts
│   │
│   ├── routes/
│   │   ├── analyze.routes.ts         — POST /api/analyze
│   │   ├── api-key.routes.ts         — POST /api/keys
│   │   ├── history.routes.ts         — GET /api/history
│   │   └── key-page.routes.ts        — GET /get-key
│   │
│   ├── services/
│   │   ├── analysis-history.service.ts
│   │   ├── api-key.service.ts
│   │   ├── database.ts
│   │   ├── risk-scoring.service.ts
│   │   ├── turnstile.service.ts
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
- Cloudflare Turnstile credentials

### Installation

```bash
git clone https://github.com/ByteSizedMe/PhishGuard.git
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
TURNSTILE_SITE_KEY=YOUR_SITE_KEY
TURNSTILE_SECRET_KEY=YOUR_SECRET_KEY
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
| Key provisioning | Self-service generation protected by Cloudflare Turnstile |
| Key-generation rate limiting | 3 API key generation attempts per hour per IP |
| Authentication | Bearer token on all protected endpoints |
| History isolation | Analysis history scoped per API key |
| Rate limiting | IP-based, 100 requests / 15 min |
| Input validation | All request payloads validated before processing |
| Secret management | All credentials via environment variables |
| Reputation API access | Server-side only — credentials never exposed to clients |

---

## Deployment

PhishGuard is deployed as a production REST API on Render.

| Component | Service |
|---|---|
| Application | Render Web Service |
| Database | Supabase PostgreSQL |
| URL reputation | Google Safe Browsing |
| Malware reputation | URLhaus |
| Bot protection | Cloudflare Turnstile |
| Live API | https://phishguard-d1bp.onrender.com |

The deployed API has been tested externally using independent client applications, including self-service API key generation, API authentication, URL analysis, rate limiting, and per-key history isolation.

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

**PhishGuard v1 — deployed and operational.**

Includes URL analysis, explainable risk scoring, typosquatting detection, Google Safe Browsing and URLhaus integration, batch analysis, API key authentication, self-service API key generation with Cloudflare Turnstile protection, PostgreSQL persistence, per-key history, rate limiting, and production deployment.

---

## License

Personal and educational use.
