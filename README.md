# SSL Certificate Watcher & AI Agent Core 🛡️

A state-of-the-art automatons auditor designed to parse public x509 SSL parameters, class certificate risk boundaries, and instantiate elite, LLM-driven incident tickets to resolve certificate expiry dangers before handshakes fail.

Built specifically for high-stakes technical interviews, full-stack assessments, and automated infrastructure visibility rounds, this repo contains the complete, production-ready codebase for both **Python FastAPI + SQLite** (for offline submissions and standalone runs) and **Node Express + React** (for real-time active container execution).

---

## 📁 Repository Structure

```tree
.
├── backend/                     # Standalone Python FastAPI Engine
│   ├── main.py                  # API gateways & report creators
│   ├── database.py              # SQLite structure definition (domains, scans, tickets)
│   ├── ssl_scanner.py           # Sockets-based TLS cert parser
│   ├── ai_agent.py              # Groq (Llama3) chat integration
│   └── models.py                # Pydantic schema validation structures
│
├── frontend/                    # Traditional Vanilla HTML/CSS/JS Layout
│   ├── index.html               # Enterprise glassmorphism view
│   ├── style.css                # Glowing animations & custom grids
│   └── app.js                   # State synchronizations & Chart.js plots
│
├── src/                         # React SPA source (Dev Dashboard)
│   ├── App.tsx                  # Dashboard container components
│   ├── index.css                # Typography & theme rules overrides
│   └── main.tsx                 # Client compiler mount
│
├── .env.example                 # Secrets documentation
├── server.ts                    # Node Full-Stack Express Server (active runtime)
├── requirements.txt             # Python requirements list
├── package.json                 # Node dependencies configuration
└── README.md                    # Core architectural workbook documentation
```

---

## ⚡ Quick Start - Python FastAPI Stack

### Prerequisite Setup
Ensure Python 3.10+ is installed on your local computer block.

1. **Clone & Target Workspace**
   ```bash
   cd ssl_certificate_expiry_watcher
   ```

2. **Establish Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Document Access Tokens**
   Generate or retrieve a Groq API key and configure your local environments config:
   ```bash
   # On macOS/Linux
   export GROQ_API_KEY="your_groq_api_token_here"
   
   # On Windows PowerShell
   $env:GROQ_API_KEY="your_groq_api_token_here"
   ```

5. **Excite Microservice Start**
   ```bash
   uvicorn backend.main:app --port 8000 --reload
   ```
   Open `http://localhost:8000/docs` to visualize your interactive Swagger REST specifications!

6. **Deploy Frontend Web Interfaces**
   Serve the `frontend/` folder using Python's static compiler or any simple web server:
   ```bash
   python -m http.server 3000
   ```
   Navigate browsers to `http://localhost:3000` to interact with your secure HTML5 dashboard.

---

## 💻 Quick Start - Node JS Stack

Our active Docker container runs a high-performance Express & React framework. Should you want to compile and play inside this environment:

1. **Install Packages**
   ```bash
   npm install
   ```

2. **Launch Dev Server**
   ```bash
   npm run dev
   ```
   Vite routes resource loaders instantly across live preview containers on Port 3000.

---

## ⚙️ How SSL Socket Audits Resolve TLS Expiries

### 📋 Single Ingress Hostname Scans

To maintain robust, interview-ready readability and architectural simplicity, the system utilizes a single consolidated input mechanism:
* **Manual Input Textarea**: Enter domain targets directly, one per line (e.g. `google.com`, `github.com`).
* **Validation & Deduplication**: The system trims inputs, parses hostnames, eliminates duplicates and blank lines, validates the proper DNS hostname format, and launches on-demand socket scan processes instantly.

### 1. The Threat Model
SSL/TLS certificate expiration isn't just a simple administration warning. When a cert lapses:
* **HSTS Rejection**: Modern browsers utilizing HTTP Strict Transport Security (HSTS) completely block users from bypassing the security landing page. The user gets a hard, unskippable `"Your connection is not private"` overlay.
* **API Breakage**: Microservices communicating over HTTPS immediately drop sessions, stopping payments, checkout processes, and database logs synchronously.
* **Automated DNS Scanning**: Ingress routes are scanned. Unrenewed endpoints can occasionally expose routing networks to hijacking.

### 2. Sockets Tunnel Audits
While regular curls or `urllib` calls fetch pages over heavy browser protocols, our core executes low-level socket connections. It binds a raw TCP socket to the host on port 443, then wraps the stream inside standard Python or Node TLS handshakes, returning full raw binary ASN1 certificates. This approach is highly robust because it bypasses heavy HTTP overhead, allowing the scanner to parse expired, self-signed, or untrusted certs without crashing.

### 3. Risk Classification Framework
* 🔴 **CRITICAL Risk** (Days Remaining &le; 7): Represents extreme threat of immediate service boundary shut-offs. AI Agents immediate construct incidents on Priority 1 schedules.
* 🟡 **WARNING Risk** (Days Remaining &le; 30): Represents active renewal boundaries. Work tickets are filed to allow sysadmins to schedule CSR key binds in regular maintenance windows.
* 🟢 **HEALTHY status** (Days Remaining &gt; 30): Certificates present certified algorithms under acceptable operational times.

---

## 🤖 Deep Dive: AI Mediation Agent Actions

The AI agent (integrated with Llama3-8b via Groq or Gemini-3.5 via server-side loaders) executes targeted technical tasks:
1. **Threat Translation**: Reads cryptographic subject tags and quantifies why an expiring DigiCert or Let's Encrypt bundle disrupts down-market integrations.
2. **Business Impact Modeling**: Calculates commercial and metric-related fallout if a given service goes dark.
3. **Action Plans**: Generates verbatim shell scripts for RSA key generation, SSL path binds, intermediate chain completions, and NGINX reload calls.

---

## 🎓 Technical Interview Q&A Workbook

Be fully prepared to address engineering evaluation panels during Elimination Rounds with these curated conceptual defenses:

### Q1: "Why use raw sockets instead of fetching with standard HTTP libraries like requests/axios?"
> **Defense:**
> "HTTP request libraries are designed to validate trust paths and expect successful status codes. If a certificate is already expired or utilizes an untrusted self-signed root, standard HTTP requests will simply fail and throw validation errors, hiding the underlying certificate metadata. Raw sockets let us connect over TCP Port 443, wrap in TLS to grab the raw binary ASN1 certificate (even if untrusted or expired), and parse fields (dates, issuers, CN) safely."

### Q2: "Describe the table structures and relationship maps within your SQL design."
> **Defense:**
> "The database utilizes an elegant, normalized SQLite schema composed of three connected tables:
> * `domains`: Resolves DNS host strings and maps to auto-identifying PK integers.
> * `scan_results`: Maps to `id` via `domain_id` foreign key. Evaluates current issuer, exact expiration date, and calculates remaining unexpired days.
> * `tickets`: Anchored through foreign key relationships. Houses the AI-generated titles, priorities, and step-by-step shell instructions to mitigate service loops."

### Q3: "How does HSTS influence certificate lapse resolution timing?"
> **Defense:**
> "HSTS headers instruct browsers that the site must exclusively load over verified secure HTTPS connections. If a certificate lapses, browsers refuse to render the document, completely cutting off bypass opportunities to standard users. This raises the urgency of renew-by-date thresholds, rendering manual spreadsheets obsolete and prioritizing automated socket scans."
