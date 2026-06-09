import express from "express";
import path from "path";
import fs from "fs";
import tls from "tls";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

const app = express();
const PORT = 3000;

app.use(express.json());

// Local Database File Setup
const DB_PATH = path.join(process.cwd(), "local_db.json");

interface Domain {
  id: number;
  hostname: string;
  created_at: string;
}

interface ScanResult {
  id: number;
  domain_id: number;
  hostname: string;
  issuer: string;
  expiry_date: string;
  days_remaining: number;
  status: string;
  last_scan: string;
}

interface Ticket {
  id: number;
  domain_id: number;
  hostname: string;
  expiry_date: string;
  days_remaining: number;
  issuer: string;
  ticket_title: string;
  priority: string;
  description: string;
  business_impact: string;
  recommended_action: string;
  created_at: string;
}

interface DatabaseSchema {
  domains: Domain[];
  scan_results: ScanResult[];
  tickets: Ticket[];
}

function initDb(): DatabaseSchema {
  if (!fs.existsSync(DB_PATH)) {
    const initial: DatabaseSchema = { domains: [], scan_results: [], tickets: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    const content = fs.readFileSync(DB_PATH, "utf-8");
    return JSON.parse(content);
  } catch (e) {
    return { domains: [], scan_results: [], tickets: [] };
  }
}

function saveDb(data: DatabaseSchema) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Ensure database loads safely
initDb();

// Demo Mode variables & structured override parameters
let demoModeActive = false;

const DEMO_DOMAINS: Domain[] = [
  { id: 10001, hostname: "google.com", created_at: new Date().toISOString() },
  { id: 10002, hostname: "github.com", created_at: new Date().toISOString() },
  { id: 10003, hostname: "amazon.com", created_at: new Date().toISOString() }
];

const DEMO_RESULTS: ScanResult[] = [
  {
    id: 20001,
    domain_id: 10001,
    hostname: "google.com",
    issuer: "GTS CA 1C3",
    expiry_date: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
    days_remaining: 5,
    status: "CRITICAL",
    last_scan: new Date().toISOString()
  },
  {
    id: 20002,
    domain_id: 10002,
    hostname: "github.com",
    issuer: "DigiCert TLS RSA SHA256 2020 CA1",
    expiry_date: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
    days_remaining: 20,
    status: "WARNING",
    last_scan: new Date().toISOString()
  },
  {
    id: 20003,
    domain_id: 10003,
    hostname: "amazon.com",
    issuer: "Amazon Science CA",
    expiry_date: new Date(Date.now() + 162 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
    days_remaining: 162,
    status: "HEALTHY",
    last_scan: new Date().toISOString()
  }
];

const DEMO_TICKETS: Ticket[] = [
  {
    id: 30001,
    domain_id: 10001,
    hostname: "google.com",
    expiry_date: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
    days_remaining: 5,
    issuer: "GTS CA 1C3",
    ticket_title: "INC-RESOLVE-AI: Immediate Certificate Action Required - GOOGLE.COM",
    priority: "CRITICAL",
    description: "Audited domain [google.com] is presenting an SSL/TLS certificate issued by GTS CA 1C3 which will expire in 5 days (CRITICAL). Unrenewed parameters will result in immediate client handshakes aborts and absolute browser lockout via HSTS rules.",
    business_impact: "HSTS browser validation rejection preventing consumers accessing any sub-route on this root. Disruption to secure search ingestion endpoints and Google identity services.",
    recommended_action: "1. Log into your Certificate Authority portal.\n2. Re-verify the domain ownership.\n3. Pull down completed public domain certificate bundle.\n4. Bind files onto TLS load balancers and refresh proxy processes immediately.",
    created_at: new Date().toISOString()
  },
  {
    id: 30002,
    domain_id: 10002,
    hostname: "github.com",
    expiry_date: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
    days_remaining: 20,
    issuer: "DigiCert TLS RSA SHA256 2020 CA1",
    ticket_title: "INC-RESOLVE-AI: Scheduled Certificate Renewal Roadmap - GITHUB.COM",
    priority: "HIGH",
    description: "Audited domain [github.com] is presenting an SSL/TLS certificate issued by DigiCert which will expire in 20 days. Normal lifecycle rules mandate replacement and deployment verification inside a 30-day window.",
    business_impact: "Imminent disruption to webhook push networks and developers authenticating git-over-HTTPS. Code integration and continuous deployment pipelines will stall once trust chains drop.",
    recommended_action: "1. Generate a 2048-bit RSA Private Key & complete a valid CSR.\n2. Upload CSR details to DigiCert portal.\n3. Test the intermediate chain bindings on standard staging routing hooks.\n4. Roll out certificates during the upcoming scheduled maintenance window.",
    created_at: new Date().toISOString()
  }
];

// Setup Gemini AI Client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

// SSL Scanning util
function scanSSL(hostname: string): Promise<any> {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname, // Enables SNI matching
        rejectUnauthorized: false, // Don't reject invalid certs - we want to audit expired/broken ones too!
      },
      () => {
        resolved = true;
        const cert = socket.getPeerCertificate(true);
        socket.destroy();
        if (!cert || !Object.keys(cert).length) {
          return reject(new Error("Peer target returned empty certificate attributes"));
        }
        resolve({
          success: true,
          issuer: cert.issuer.O || cert.issuer.CN || "Unknown Authority",
          expiryDate: cert.valid_to ? new Date(cert.valid_to).toISOString().split("T")[0] : "Unknown",
          validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString().split("T")[0] : "Unknown",
          commonName: cert.subject.CN || "N/A",
          organization: cert.subject.O || "N/A",
        });
      }
    );

    socket.on("error", (err) => {
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });

    socket.setTimeout(6500);
    socket.on("timeout", () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        reject(new Error("Connection Handshake timeout over 443"));
      }
    });
  });
}

// Generate Remediation Report with Gemini AI
async function generateRemediationTicket(
  hostname: string,
  expiryDate: string,
  daysRemaining: number,
  issuer: string
) {
  const priority = daysRemaining <= 7 ? "CRITICAL" : "HIGH";
  const fallback = {
    ticket_title: `INC-RESOLVE-AI: Immediate Certificate Action Required - ${hostname.toUpperCase()}`,
    priority: priority,
    description: `Audited domain [${hostname}] is presenting an SSL/TLS certificate issued by '${issuer}' which will expire in ${daysRemaining} days (${expiryDate}). Unrenewed parameters will result in immediate client handshakes aborts.`,
    business_impact: `HSTS browser validation rejection preventing consumers accessing any sub-route on this root. Disruption to API integration endpoints leading to checkout/payment gateway drops. Immediate negative search authority scoring.`,
    recommended_action: `1. Generate a 2048-bit RSA Certificate Signing Request (CSR) on host server.\n2. Upload CSR details to Certificate Authority (CA) registration hub.\n3. Pull down completed public domain certificate bundle along with intermediate validation chains.\n4. Bind files onto TLS endpoints and execute check scans.`,
  };

  if (!process.env.GEMINI_API_KEY) {
    return fallback;
  }

  const prompt = `
  You are an expert Cybersecurity Engineer. Format a complete enterprise resolution incident ticket for an expiring SSL certificate.
  
  Target URL/Host: ${hostname}
  Issuer: ${issuer}
  Expiry Date: ${expiryDate}
  Days Remaining: ${daysRemaining} days remaining
  Urgency Status: ${priority}
  
  Format your reply strictly as a valid JSON object matching the keys below. No markdown wrappers. Just raw JSON.
  {
    "ticket_title": "Clean INC ticket prefix and domain summary",
    "priority": "CRITICAL or HIGH matching the determined state",
    "description": "Scientific threat report regarding current certificate parameters and algorithms",
    "business_impact": "Direct operational risk detailing what occurs to customers, search placements, and compliance audit frameworks if expired",
    "recommended_action": "Numbered step-by-step renewal action instructions including private key configs, CSR commands, and path bindings"
  }
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });

    const parsed = JSON.parse(response.text || "{}");
    return {
      ticket_title: parsed.ticket_title || fallback.ticket_title,
      priority: parsed.priority || fallback.priority,
      description: parsed.description || fallback.description,
      business_impact: parsed.business_impact || fallback.business_impact,
      recommended_action: parsed.recommended_action || fallback.recommended_action,
    };
  } catch (e) {
    console.error("Gemini failed generating ticket details, falling back:", e);
    return fallback;
  }
}

// ---------------- REST API ENDPOINTS ----------------

// Route 1: Register Domain
app.post("/api/domains", (req, res) => {
  const { hostname } = req.body;
  const cleaned = hostname?.trim().toLowerCase();
  if (!cleaned) {
    return res.status(400).json({ error: "Hostname is required" });
  }

  const db = initDb();
  const existing = db.domains.find((d) => d.hostname === cleaned);
  if (existing) {
    return res.json(existing);
  }

  const newDomain: Domain = {
    id: db.domains.length > 0 ? Math.max(...db.domains.map((d) => d.id)) + 1 : 1,
    hostname: cleaned,
    created_at: new Date().toISOString(),
  };

  db.domains.push(newDomain);
  saveDb(db);
  res.status(201).json(newDomain);
});

// GET Demo Mode status
app.get("/api/demo-mode", (req, res) => {
  res.json({ active: demoModeActive });
});

// POST Demo Mode status
app.post("/api/demo-mode", (req, res) => {
  const { active } = req.body;
  demoModeActive = !!active;
  res.json({ active: demoModeActive });
});

// Route 2: Get Domain Registries
app.get("/api/domains", (req, res) => {
  if (demoModeActive) {
    return res.json(DEMO_DOMAINS);
  }
  const db = initDb();
  res.json(db.domains);
});

// Route 3: Delete Registered Domain
app.delete("/api/domains/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const db = initDb();

  db.domains = db.domains.filter((d) => d.id !== id);
  db.scan_results = db.scan_results.filter((r) => r.domain_id !== id);
  db.tickets = db.tickets.filter((t) => t.domain_id !== id);

  saveDb(db);
  res.json({ success: true, message: "Records matching the domain ID purged" });
});

// Route 4: Scan and register hostnames list
app.post("/api/scan-hostnames", async (req, res) => {
  const { hostnames } = req.body;
  if (!hostnames || !Array.isArray(hostnames)) {
    return res.status(400).json({ error: "Hostnames is required and must be an array" });
  }

  if (demoModeActive) {
    return res.json({
      success: true,
      scanned_count: DEMO_DOMAINS.length,
      results: DEMO_RESULTS,
      failures: []
    });
  }

  const db = initDb();
  const scanned: ScanResult[] = [];
  const failures: any[] = [];

  for (const rawHost of hostnames) {
    const cleaned = rawHost?.trim().toLowerCase();
    if (!cleaned) continue;

    // Register domain if not present
    let domain = db.domains.find((d) => d.hostname === cleaned);
    if (!domain) {
      domain = {
        id: db.domains.length > 0 ? Math.max(...db.domains.map((d) => d.id)) + 1 : 1,
        hostname: cleaned,
        created_at: new Date().toISOString(),
      };
      db.domains.push(domain);
    }

    // Scan
    try {
      const scanData = await scanSSL(domain.hostname);
      const expiryTime = new Date(scanData.expiryDate).getTime();
      const rightNow = new Date().getTime();
      const daysRemaining = Math.ceil((expiryTime - rightNow) / (1000 * 60 * 60 * 24));

      let status = "HEALTHY";
      if (daysRemaining <= 7) status = "CRITICAL";
      else if (daysRemaining <= 30) status = "WARNING";

      db.scan_results = db.scan_results.filter((r) => r.domain_id !== domain.id);
      const newScan: ScanResult = {
        id: db.scan_results.length > 0 ? Math.max(...db.scan_results.map((r) => r.id)) + 1 : 1,
        domain_id: domain.id,
        hostname: domain.hostname,
        issuer: scanData.issuer,
        expiry_date: scanData.expiryDate,
        days_remaining: daysRemaining,
        status: status,
        last_scan: new Date().toISOString(),
      };
      db.scan_results.push(newScan);
      scanned.push(newScan);

      if (status !== "HEALTHY") {
        db.tickets = db.tickets.filter((t) => t.domain_id !== domain.id);
        const aiTicket = await generateRemediationTicket(
          domain.hostname,
          scanData.expiryDate,
          daysRemaining,
          scanData.issuer
        );

        db.tickets.push({
          id: db.tickets.length > 0 ? Math.max(...db.tickets.map((t) => t.id)) + 1 : 1,
          domain_id: domain.id,
          hostname: domain.hostname,
          expiry_date: scanData.expiryDate,
          days_remaining: daysRemaining,
          issuer: scanData.issuer,
          ticket_title: aiTicket.ticket_title,
          priority: aiTicket.priority,
          description: aiTicket.description,
          business_impact: aiTicket.business_impact,
          recommended_action: aiTicket.recommended_action,
          created_at: new Date().toISOString(),
        });
      }
    } catch (e: any) {
      failures.push({ hostname: cleaned, reason: e.message });
    }
  }

  saveDb(db);
  res.json({
    success: true,
    scanned_count: hostnames.length,
    results: db.scan_results,
    failures: failures
  });
});

// Route 5: Scan Single Domain
app.post("/api/scan/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  if (demoModeActive) {
    const matched = DEMO_RESULTS.find((r) => r.domain_id === id || r.id === id);
    if (matched) {
      return res.json(matched);
    }
    const demoDom = DEMO_DOMAINS.find((d) => d.id === id);
    const hostname = demoDom ? demoDom.hostname : "demo-target.com";
    return res.json({
      id: 20000 + id,
      domain_id: id,
      hostname: hostname,
      issuer: "Demo GTS Authority",
      expiry_date: new Date(Date.now() + 162 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
      days_remaining: 162,
      status: "HEALTHY",
      last_scan: new Date().toISOString()
    });
  }

  const db = initDb();
  const domain = db.domains.find((d) => d.id === id);
  if (!domain) {
    return res.status(404).json({ error: "Registered domain target was not found" });
  }

  try {
    const scanData = await scanSSL(domain.hostname);
    const dateToday = new Date().getTime();
    const expiryTime = new Date(scanData.expiryDate).getTime();
    
    // Calculate precise days remaining
    const daysRemaining = Math.ceil((expiryTime - dateToday) / (1000 * 60 * 60 * 24));
    
    let status = "HEALTHY";
    if (daysRemaining <= 7) status = "CRITICAL";
    else if (daysRemaining <= 30) status = "WARNING";

    // Save scan result
    db.scan_results = db.scan_results.filter((r) => r.domain_id !== id);
    const newScan: ScanResult = {
      id: db.scan_results.length > 0 ? Math.max(...db.scan_results.map((r) => r.id)) + 1 : 1,
      domain_id: id,
      hostname: domain.hostname,
      issuer: scanData.issuer,
      expiry_date: scanData.expiryDate,
      days_remaining: daysRemaining,
      status: status,
      last_scan: new Date().toISOString(),
    };
    db.scan_results.push(newScan);

    // If critical/warning, trigger AI remediation ticker
    if (status !== "HEALTHY") {
      db.tickets = db.tickets.filter((t) => t.domain_id !== id);
      const aiTicket = await generateRemediationTicket(
        domain.hostname,
        scanData.expiryDate,
        daysRemaining,
        scanData.issuer
      );

      db.tickets.push({
        id: db.tickets.length > 0 ? Math.max(...db.tickets.map((t) => t.id)) + 1 : 1,
        domain_id: id,
        hostname: domain.hostname,
        expiry_date: scanData.expiryDate,
        days_remaining: daysRemaining,
        issuer: scanData.issuer,
        ticket_title: aiTicket.ticket_title,
        priority: aiTicket.priority,
        description: aiTicket.description,
        business_impact: aiTicket.business_impact,
        recommended_action: aiTicket.recommended_action,
        created_at: new Date().toISOString(),
      });
    }

    saveDb(db);
    res.json(newScan);
  } catch (e: any) {
    console.error(`Local scan failed for ${domain.hostname}:`, e);
    res.status(502).json({ error: `Connection failed for ${domain.hostname}: ${e.message}` });
  }
});

// Route 6: Scan All Domains
app.post("/api/scan-all", async (req, res) => {
  if (demoModeActive) {
    return res.json({
      success: true,
      scanned_count: DEMO_DOMAINS.length,
      results: DEMO_RESULTS,
      failures: []
    });
  }

  const db = initDb();
  if (db.domains.length === 0) {
    return res.json({ success: true, scanned_count: 0, results: [] });
  }

  let scannedCount = 0;
  const failures: any[] = [];

  for (const domain of db.domains) {
    try {
      const scanData = await scanSSL(domain.hostname);
      const expiryTime = new Date(scanData.expiryDate).getTime();
      const rightNow = new Date().getTime();
      const daysRemaining = Math.ceil((expiryTime - rightNow) / (1000 * 60 * 60 * 24));

      let status = "HEALTHY";
      if (daysRemaining <= 7) status = "CRITICAL";
      else if (daysRemaining <= 30) status = "WARNING";

      db.scan_results = db.scan_results.filter((r) => r.domain_id !== domain.id);
      db.scan_results.push({
        id: db.scan_results.length > 0 ? Math.max(...db.scan_results.map((r) => r.id)) + 1 : 1,
        domain_id: domain.id,
        hostname: domain.hostname,
        issuer: scanData.issuer,
        expiry_date: scanData.expiryDate,
        days_remaining: daysRemaining,
        status: status,
        last_scan: new Date().toISOString(),
      });

      if (status !== "HEALTHY") {
        db.tickets = db.tickets.filter((t) => t.domain_id !== domain.id);
        const aiTicket = await generateRemediationTicket(
          domain.hostname,
          scanData.expiryDate,
          daysRemaining,
          scanData.issuer
        );

        db.tickets.push({
          id: db.tickets.length > 0 ? Math.max(...db.tickets.map((t) => t.id)) + 1 : 1,
          domain_id: domain.id,
          hostname: domain.hostname,
          expiry_date: scanData.expiryDate,
          days_remaining: daysRemaining,
          issuer: scanData.issuer,
          ticket_title: aiTicket.ticket_title,
          priority: aiTicket.priority,
          description: aiTicket.description,
          business_impact: aiTicket.business_impact,
          recommended_action: aiTicket.recommended_action,
          created_at: new Date().toISOString(),
        });
      }
      scannedCount++;
    } catch (e: any) {
      failures.push({ hostname: domain.hostname, reason: e.message });
    }
  }

  saveDb(db);
  res.json({
    success: true,
    scanned_count: scannedCount,
    results: db.scan_results,
    failures: failures,
  });
});

// Route 7: Get Audited Scan Results
app.get("/api/results", (req, res) => {
  if (demoModeActive) {
    return res.json(DEMO_RESULTS);
  }
  const db = initDb();
  res.json(db.scan_results);
});

// Route 8: Get Incident Resolution Tickets
app.get("/api/tickets", (req, res) => {
  if (demoModeActive) {
    return res.json(DEMO_TICKETS);
  }
  const db = initDb();
  res.json(db.tickets);
});

// Route 9: Export and Download ranked_certs.csv
app.get("/api/export/csv", (req, res) => {
  const resultsToExport = demoModeActive ? DEMO_RESULTS : initDb().scan_results;
  const sorted = [...resultsToExport].sort((a, b) => a.days_remaining - b.days_remaining);

  let csvContent = "hostname,expiry_date,days_left,status,issuer,owner\n";
  sorted.forEach((r) => {
    csvContent += `"${r.hostname}","${r.expiry_date}",${r.days_remaining},"${r.status}","${r.issuer}","Infrastructure Team"\n`;
  });

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=ranked_certs.csv");
  res.send(csvContent);
});

// Route 10: Export and Download AI generated renewal_tasks.md
app.get("/api/export/markdown", (req, res) => {
  const ticketsToExport = demoModeActive ? DEMO_TICKETS : initDb().tickets;
  const sorted = [...ticketsToExport].sort((a, b) => a.days_remaining - b.days_remaining);

  let md = "# SSL Certificate Expiry Watcher - Renewal Tasks Workbook\n";
  md += `**Generated On**: \`${new Date().toISOString().replace("T", " ").substring(0, 19)} UTC\`\n`;
  if (demoModeActive) {
    md += "⚠️ **DEMO MODE SEEDED PLAN**\n\n";
  }
  md += "Active action plans generated by the security agent to mitigate TLS service drops.\n\n";
  md += "=".repeat(60) + "\n\n";

  if (sorted.length === 0) {
    md += "## Status Report: No Active Threat Tickets\nAll monitored domains present healthy certificates expiring over 30 days out. No remediation items reported.\n";
  } else {
    sorted.forEach((t) => {
      md += `## [${t.priority}] Hostname: ${t.hostname}\n`;
      md += `- **Certificate Issuer**: \`${t.issuer}\`\n`;
      md += `- **Scheduled Expiry**: \`${t.expiry_date}\`\n`;
      md += `- **Days Until Handshake Breakout**: \`${t.days_remaining} days\`\n`;
      md += `- **Incident Remediation Priority**: \`${t.priority}\`\n`;
      md += `- **Assigned Handler**: \`[Systems Engineer / Cyber Security Admin]\`\n\n`;
      md += `### Incident Risk Assessment\n${t.description}\n\n`;
      md += `### Business Continuity Impact\n${t.business_impact}\n\n`;
      md += `### Mandatory Operational Actions\n${t.recommended_action}\n\n`;
      md += "=".repeat(40) + "\n\n";
    });
  }

  res.setHeader("Content-Type", "text/markdown");
  res.setHeader("Content-Disposition", "attachment; filename=renewal_tasks.md");
  res.send(md);
});

// Serve assets based on environment
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);

    app.use("*", async (req, res, next) => {
      const url = req.originalUrl;
      try {
        let template = fs.readFileSync(
          path.resolve(process.cwd(), "index.html"),
          "utf-8"
        );
        template = await vite.transformIndexHtml(url, template);
        res.status(200).set({ "Content-Type": "text/html" }).end(template);
      } catch (e) {
        vite.ssrFixStacktrace(e as Error);
        next(e);
      }
    });
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server executing live on http://localhost:${PORT}`);
  });
}

startServer();
