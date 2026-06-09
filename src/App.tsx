/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Database, 
  Download, 
  FileText, 
  PlusCircle, 
  RefreshCw, 
  Trash2, 
  Clock,
  Terminal,
  Activity,
  User,
  ExternalLink
} from "lucide-react";

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

interface Toast {
  id: string;
  message: string;
  type: "success" | "warning" | "info" | "error";
}

export default function App() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [tickets, setTickets] = useState<Ticket[]>([]);
  
  const [manualInput, setManualInput] = useState<string>("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [demoMode, setDemoMode] = useState<boolean>(false);

  // Sync state
  useEffect(() => {
    fetchDemoMode();
    refreshAllData();
  }, []);

  const fetchDemoMode = async () => {
    try {
      const res = await fetch("/api/demo-mode");
      if (res.ok) {
        const data = await res.json();
        setDemoMode(data.active);
      }
    } catch (e) {
      console.error("Failed fetching demo mode status", e);
    }
  };

  const handleToggleDemoMode = async (nextVal: boolean) => {
    setDemoMode(nextVal);
    try {
      const res = await fetch("/api/demo-mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: nextVal })
      });
      if (res.ok) {
        const data = await res.json();
        setDemoMode(data.active);
        addToast(
          data.active 
            ? "🧪 Demo Mode enabled. Pre-seeded mock endpoints activated." 
            : "Demo Mode disabled. Returning to live configuration.", 
          "success"
        );
        refreshAllData();
      }
    } catch (e: any) {
      addToast("Failed communicating configuration change: " + e.message, "error");
    }
  };

  const addToast = (message: string, type: "success" | "warning" | "info" | "error" = "info") => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  };

  const refreshAllData = async () => {
    try {
      const [domainsRes, resultsRes, ticketsRes] = await Promise.all([
        fetch("/api/domains"),
        fetch("/api/results"),
        fetch("/api/tickets")
      ]);

      if (domainsRes.ok) setDomains(await domainsRes.json());
      if (resultsRes.ok) setResults(await resultsRes.json());
      if (ticketsRes.ok) setTickets(await ticketsRes.json());
    } catch (e: any) {
      addToast("Failed synchronizing local database records: " + e.message, "error");
    }
  };

  // Scan all manually entered domains
  const handleScanAllDomains = async () => {
    setValidationErrors([]);
    const trimmed = manualInput.trim();
    if (!trimmed) {
      setValidationErrors(["Empty input: Please enter at least one hostname."]);
      return;
    }

    // Split lines and filter blank
    const lines = trimmed.split("\n").map((l) => l.trim());
    const nonBlank = lines.filter((l) => l.length > 0 && !l.startsWith("#"));
    
    if (nonBlank.length === 0) {
      setValidationErrors(["Empty input: Please enter at least one hostname."]);
      return;
    }

    // Remove duplicates
    const uniqueHosts: string[] = Array.from(new Set(nonBlank));

    // Validate hostname format
    const domainRegex = /^(?:[a-z0-0](?:[a-z0-0-]{0,61}[a-z0-0])?\.)+[a-z]{2,18}$/i;
    const invalidHosts: string[] = [];
    const validHosts: string[] = [];

    uniqueHosts.forEach((host: string) => {
      if (domainRegex.test(host)) {
        validHosts.push(host);
      } else {
        invalidHosts.push(host);
      }
    });

    if (invalidHosts.length > 0) {
      setValidationErrors(invalidHosts.map((h) => `Malformed domain: "${h}" is not a valid hostname format.`));
    }

    if (validHosts.length === 0) {
      addToast("Failed: No valid hostnames were entered to scan.", "error");
      return;
    }

    setIsAuditing(true);
    addToast(`Triggering TCP 443 socket connection audits for ${validHosts.length} domain(s)...`, "info");

    try {
      const res = await fetch("/api/scan-hostnames", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostnames: validHosts }),
      });

      if (res.ok) {
        const outcome = await res.json();
        addToast(`Successfully audited ${outcome.scanned_count || validHosts.length} domain(s).`, "success");
        if (outcome.failures && outcome.failures.length > 0) {
          addToast(`Failed resolving host SSLs for ${outcome.failures.length} target records.`, "warning");
        }
        refreshAllData();
      } else {
        const errorData = await res.json();
        addToast(errorData.error || "Audit resolution sequence error.", "error");
      }
    } catch (e: any) {
      addToast("Audit action failed: " + e.message, "error");
    } finally {
      setIsAuditing(false);
    }
  };

  // Audit single domain
  const handleTriggerSingleAudit = async (id: number, hostname: string) => {
    setSelectedScanId(id);
    addToast(`Opening SSL socket query to ${hostname}...`, "info");

    try {
      const res = await fetch(`/api/scan/${id}`, { method: "POST" });
      if (res.ok) {
        addToast(`Verified SSL structure of ${hostname}`, "success");
        refreshAllData();
      } else {
        const err = await res.json();
        addToast(err.error || `Failed verifying ${hostname}`, "error");
      }
    } catch (e: any) {
      addToast("Audit verification error: " + e.message, "error");
    } finally {
      setSelectedScanId(null);
    }
  };

  // Erase domain target
  const handleEraseDomain = async (id: number, hostname: string) => {
    if (!confirm(`Confirm absolute database expunge for domain [${hostname}] and historical ticket histories?`)) {
      return;
    }

    try {
      const res = await fetch(`/api/domains/${id}`, { method: "DELETE" });
      if (res.ok) {
        addToast(`Successfully removed domain reference keys for ${hostname}`, "success");
        refreshAllData();
      } else {
        addToast("Database refused delete directive.", "error");
      }
    } catch (e: any) {
      addToast("Failed db communication: " + e.message, "error");
    }
  };

  // Download utilities
  const handleExportCsv = () => {
    if (results.length === 0) {
      addToast("Scan domain records before generating CSV exports.", "warning");
      return;
    }
    window.open("/api/export/csv", "_blank");
  };

  const handleExportMarkdown = () => {
    const expiredCount = results.filter((r) => r.status !== "HEALTHY").length;
    if (expiredCount === 0) {
      addToast("No targets inside Critical/Warning states. Playbook generation targets are idle.", "warning");
      return;
    }
    window.open("/api/export/markdown", "_blank");
  };

  // UI Metrics Math
  const criticalCertsCount = results.filter((r) => r.status === "CRITICAL").length;
  const warningCertsCount = results.filter((r) => r.status === "WARNING").length;
  const healthyCertsCount = results.filter((r) => r.status === "HEALTHY").length;
  const pendingScanCount = domains.length - results.length;

  // Custom Pie Chart SVG Calculations
  const totalScanned = results.length;
  const criticalPct = totalScanned > 0 ? (criticalCertsCount / totalScanned) * 100 : 0;
  const warningPct = totalScanned > 0 ? (warningCertsCount / totalScanned) * 100 : 0;
  const healthyPct = totalScanned > 0 ? (healthyCertsCount / totalScanned) * 100 : 0;

  // Render SVG Ring sectors
  const getDoughnutSlices = () => {
    if (totalScanned === 0) {
      return <circle cx="50" cy="50" r="35" fill="none" stroke="#374151" strokeWidth="8" />;
    }

    let accumulatedPct = 0;
    const slices = [];

    // Slice 1: Critical (Red)
    if (criticalPct > 0) {
      const dashArray = `${(criticalPct * 220) / 100} 220`;
      slices.push(
        <circle
          key="crit"
          cx="50"
          cy="50"
          r="35"
          fill="none"
          stroke="#ef4444"
          strokeWidth="8"
          strokeDasharray={dashArray}
          strokeDashoffset="0"
          transform="rotate(-90 50 50)"
          className="transition-all duration-500 ease-out"
        />
      );
      accumulatedPct += criticalPct;
    }

    // Slice 2: Warning (Yellow)
    if (warningPct > 0) {
      const dashArray = `${(warningPct * 220) / 100} 220`;
      const dashOffset = -((accumulatedPct * 220) / 100);
      slices.push(
        <circle
          key="warn"
          cx="50"
          cy="50"
          r="35"
          fill="none"
          stroke="#f59e0b"
          strokeWidth="8"
          strokeDasharray={dashArray}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 50 50)"
          className="transition-all duration-500 ease-out"
        />
      );
      accumulatedPct += warningPct;
    }

    // Slice 3: Healthy (Green)
    if (healthyPct > 0) {
      const dashArray = `${(healthyPct * 220) / 100} 220`;
      const dashOffset = -((accumulatedPct * 220) / 100);
      slices.push(
        <circle
          key="health"
          cx="50"
          cy="50"
          r="35"
          fill="none"
          stroke="#10b981"
          strokeWidth="8"
          strokeDasharray={dashArray}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 50 50)"
          className="transition-all duration-500 ease-out"
        />
      );
    }

    return slices;
  };

  return (
    <div className="bg-slate-950 text-white min-h-screen relative font-sans-custom overflow-hidden pb-16">
      
      {/* Background radial effects */}
      <div className="absolute top-0 left-0 w-full h-[600px] pointer-events-none z-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-blue-600/5 blur-[120px]" />
        <div className="absolute top-80 -right-40 w-[500px] h-[500px] rounded-full bg-indigo-500/5 blur-[100px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        
        {/* HEADER BRAND */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-10 pb-6 border-b border-white/5">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="p-2.5 bg-blue-500/10 rounded-xl text-blue-500 border border-blue-500/10 shadow-[0_0_15px_rgba(59,130,246,0.1)]">
                <Shield className="h-7 w-7" />
              </span>
              <div>
                <h1 className="text-2xl sm:text-3xl font-bold font-display tracking-tight text-white flex items-center gap-2">
                  SSL Certificate Expiry Watcher
                </h1>
                <p className="text-xs font-mono text-blue-400/80">AI Remediations Command Center</p>
              </div>
            </div>
          </div>
          
          <div className="flex flex-wrap items-center gap-3">
            {/* Demo Mode Toggle Switch */}
            <div className="flex items-center gap-2.5 bg-slate-900 border border-white/5 py-1.5 px-3 rounded-lg shadow-inner">
              <span className="text-[11px] font-mono font-semibold tracking-wider text-slate-300 uppercase">Demo Mode</span>
              <button
                id="demo-mode-toggle"
                onClick={() => handleToggleDemoMode(!demoMode)}
                className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  demoMode ? "bg-amber-400" : "bg-slate-700"
                }`}
                aria-label="Toggle Demo Mode"
              >
                <span
                  className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    demoMode ? "translate-x-5" : "translate-x-0"
                  }`}
                />
              </button>
            </div>

            <button
              onClick={handleExportCsv}
              className="bg-slate-900 hover:bg-slate-800 hover:border-slate-700 active:scale-[0.98] transition-all border border-white/5 text-xs text-white px-4 py-2.5 rounded-lg font-medium flex items-center gap-2"
            >
              <Download className="h-3.5 w-3.5" />
              Download CSV Report
            </button>
            <button
              onClick={handleExportMarkdown}
              className="bg-blue-600 hover:bg-blue-500 active:scale-[0.98] transition-all text-xs text-white px-4 py-2.5 rounded-lg font-medium flex items-center gap-2 shadow-[0_0_15px_rgba(37,99,235,0.2)]"
            >
              <FileText className="h-3.5 w-3.5" />
              Download AI Remediation Workbook
            </button>
          </div>
        </header>

        {/* DEMO MODE ACTIVE NOTIFICATION BADGE */}
        {demoMode && (
          <div className="mb-8 bg-amber-500/10 border border-amber-500/20 rounded-2xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 animate-pulse backdrop-blur-md">
            <div className="flex items-center gap-2 text-amber-400 text-xs sm:text-sm font-bold tracking-wider uppercase font-mono">
              <span className="flex h-2.5 w-2.5 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-400"></span>
              </span>
              <span>🧪 DEMO MODE ACTIVE</span>
            </div>
            <span className="text-xs text-slate-300 font-mono">
              High-fidelity simulated certificate layers (CRITICAL, WARNING & HEALTHY states) enabled. Live network lookups bypass active.
            </span>
          </div>
        )}

        {/* METRICS GRID */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {/* Total */}
          <div className="bg-slate-900/55 border border-white/5 p-5 rounded-2xl backdrop-blur-md relative overflow-hidden transition-all hover:scale-[1.01] hover:bg-slate-900/75">
            <p className="text-[10px] font-mono tracking-wider text-slate-400 uppercase">Monitored Domains</p>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-white">{domains.length}</span>
              <span className="text-[10px] font-mono text-slate-500 uppercase">registered</span>
            </div>
            <Database className="absolute right-4 top-4 h-8 w-8 text-slate-700/30" />
          </div>

          {/* Critical */}
          <div className="bg-slate-900/55 border border-rose-500/10 p-5 rounded-2xl backdrop-blur-md relative overflow-hidden transition-all hover:scale-[1.01] hover:bg-slate-900/70">
            <p className="text-[10px] font-mono tracking-wider text-rose-400 uppercase">Critical Threat</p>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-rose-500">{criticalCertsCount}</span>
              <span className="text-[10px] font-mono text-rose-400/80 uppercase">&le; 7 Days</span>
            </div>
            <AlertTriangle className="absolute right-4 top-4 h-8 w-8 text-rose-500/10" />
          </div>

          {/* Warning */}
          <div className="bg-slate-900/55 border border-amber-500/10 p-5 rounded-2xl backdrop-blur-md relative overflow-hidden transition-all hover:scale-[1.01] hover:bg-slate-900/70">
            <p className="text-[10px] font-mono tracking-wider text-amber-400 uppercase">Warning Expiring</p>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-amber-400">{warningCertsCount}</span>
              <span className="text-[10px] font-mono text-amber-400/80 uppercase">&le; 30 Days</span>
            </div>
            <Clock className="absolute right-4 top-4 h-8 w-8 text-amber-500/10" />
          </div>

          {/* Healthy */}
          <div className="bg-slate-900/55 border border-emerald-500/10 p-5 rounded-2xl backdrop-blur-md relative overflow-hidden transition-all hover:scale-[1.01] hover:bg-slate-900/70">
            <p className="text-[10px] font-mono tracking-wider text-emerald-400 uppercase">Secure Certs</p>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-emerald-500">{healthyCertsCount}</span>
              <span className="text-[10px] font-mono text-emerald-400/80 uppercase">&gt; 30 Days</span>
            </div>
            <CheckCircle className="absolute right-4 top-4 h-8 w-8 text-emerald-500/10" />
          </div>
        </section>

        {/* INPUTS AND GUIDE REGISTRY */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          
          {/* ASSET INGRESS REGISTER */}
          <div className="lg:col-span-2 bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <PlusCircle className="h-5 w-5 text-blue-500" />
                <h2 className="text-sm font-bold font-display tracking-tight text-white uppercase">Enter Hostnames</h2>
              </div>
              
              <div className="space-y-1">
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block font-bold">Enter Hostnames (one per line)</label>
                <textarea
                  value={manualInput}
                  onChange={(e) => {
                    setManualInput(e.target.value);
                    if (validationErrors.length > 0) {
                      setValidationErrors([]);
                    }
                  }}
                  rows={6}
                  className="w-full bg-slate-950 border border-white/5 rounded-xl p-3 text-xs font-mono focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 text-left"
                  placeholder="google.com&#10;github.com&#10;amazon.com&#10;cloudflare.com&#10;microsoft.com"
                />
              </div>

              {/* Show validation errors */}
              {validationErrors.length > 0 && (
                <div id="validation-errors" className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-3 space-y-1">
                  <p className="text-[10px] font-mono text-rose-400 font-bold uppercase tracking-wider">Validation Errors:</p>
                  <ul className="list-disc list-inside space-y-0.5">
                    {validationErrors.slice(0, 5).map((err, idx) => (
                      <li key={idx} className="text-[11px] font-mono text-rose-300">{err}</li>
                    ))}
                    {validationErrors.length > 5 && (
                      <li className="text-[11px] font-mono text-rose-300">...and {validationErrors.length - 5} more errors.</li>
                    )}
                  </ul>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end pt-4 border-t border-white/5 mt-4">
              <button
                id="scan-all-domains-btn"
                onClick={handleScanAllDomains}
                disabled={isAuditing}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs text-white px-6 py-2.5 rounded-lg font-bold flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.15)] transition-all active:scale-[0.98]"
              >
                {isAuditing ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Scanning All Domains...
                  </>
                ) : (
                  <>
                    <Activity className="h-4 w-4" />
                    Scan All Domains
                  </>
                )}
              </button>
            </div>
          </div>

          {/* SYSTEM CALIBRATION DIAGNOSTICS */}
          <div className="bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl flex flex-col justify-between">
            <div className="space-y-4">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest border-b border-white/5 pb-2">
                Audit Threshold Rules
              </h3>
              
              <div className="space-y-3">
                <div className="flex items-start gap-2.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_10px_#ef4444] shrink-0 mt-1" />
                  <div>
                    <h4 className="font-bold text-slate-200">Critical (&le; 7 Days)</h4>
                    <p className="text-[10px] text-slate-400 mt-0.5">Hands shakes are close to immediate failure points. Urgent priority flags triggered.</p>
                  </div>
                </div>
                
                <div className="flex items-start gap-2.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_10px_#f59e0b] shrink-0 mt-1" />
                  <div>
                    <h4 className="font-bold text-slate-200">Warning (&le; 30 Days)</h4>
                    <p className="text-[10px] text-slate-400 mt-0.5">Certificate renewal is due. Automated renewal roadmap checklists formulated.</p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981] shrink-0 mt-1" />
                  <div>
                    <h4 className="font-bold text-slate-200">Healthy (&gt; 30 Days)</h4>
                    <p className="text-[10px] text-slate-400 mt-0.5">Handshakes present certified cipher security parameters on server binds.</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-white/5 flex items-center gap-2 text-[10px] font-mono text-slate-500">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
              Database Engine: persistent JSON and SQLite active
            </div>
          </div>
        </section>

        {/* RESULTS TABLE */}
        <section className="bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl mb-8">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
            <h2 className="text-sm font-bold font-display uppercase tracking-wider">Monitored Domains Registry</h2>
            <span className="text-[10px] font-mono bg-slate-950/60 border border-white/5 text-slate-400 px-3 py-1 rounded-full">
              {domains.length} Domain entries in registry
            </span>
          </div>

          <div className="overflow-x-auto border border-white/5 rounded-xl max-h-[380px]">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-950 text-slate-400 text-[10px] font-mono border-b border-white/5 select-none">
                  <th className="p-4 uppercase tracking-widest text-[9px]">Target Hostname</th>
                  <th className="p-4 uppercase tracking-widest text-[9px]">Certificate Issuer CA</th>
                  <th className="p-4 uppercase tracking-widest text-[9px]">Expiry Date Scheduled</th>
                  <th className="p-4 uppercase tracking-widest text-[9px]">Days Remaining</th>
                  <th className="p-4 uppercase tracking-widest text-[9px]">Alert Level</th>
                  <th className="p-4 uppercase tracking-widest text-[9px] text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-xs text-slate-200">
                {domains.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500 italic">
                      Domain list empty. Formulate DNS asset hostnames lists using the workspace ingress modules.
                    </td>
                  </tr>
                ) : (
                  domains.map((dom) => {
                    const scan = results.find((r) => r.domain_id === dom.id);
                    const isScanningThis = selectedScanId === dom.id;

                    return (
                      <tr key={dom.id} className="hover:bg-white/[0.01] transition-colors">
                        <td className="p-4 font-bold text-white tracking-wide">{dom.hostname}</td>
                        <td className="p-4 text-slate-400 font-mono text-[11px]">
                          {scan ? scan.issuer : <span className="text-slate-600 italic">Pending Scan</span>}
                        </td>
                        <td className="p-4 text-slate-400 font-mono text-[11px]">
                          {scan ? scan.expiry_date : <span className="text-slate-600 italic">Pending Scan</span>}
                        </td>
                        <td className="p-4 font-mono font-bold text-[11px]">
                          {scan ? (
                            scan.status === "CRITICAL" ? (
                              <span className="text-rose-500">{scan.days_remaining} days</span>
                            ) : scan.status === "WARNING" ? (
                              <span className="text-amber-400">{scan.days_remaining} days</span>
                            ) : (
                              <span className="text-emerald-400">{scan.days_remaining} days</span>
                            )
                          ) : (
                            <span className="text-slate-600">Pending Scan</span>
                          )}
                        </td>
                        <td className="p-4">
                          {scan ? (
                            scan.status === "CRITICAL" ? (
                              <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-rose-500/10 text-rose-500 border border-rose-500/20 rounded">CRITICAL</span>
                            ) : scan.status === "WARNING" ? (
                              <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 rounded">WARNING</span>
                            ) : (
                              <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded">HEALTHY</span>
                            )
                          ) : (
                            <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-slate-800 text-slate-500 rounded border border-white/5">UNAUDITED</span>
                          )}
                        </td>
                        <td className="p-4 text-right space-x-2">
                          <button
                            onClick={() => handleTriggerSingleAudit(dom.id, dom.hostname)}
                            disabled={isScanningThis}
                            className="bg-blue-600/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/10 px-2.5 py-1 rounded-md text-[10px] font-medium transition-all"
                          >
                            {isScanningThis ? "Querying..." : "Run Audit"}
                          </button>
                          <button
                            onClick={() => handleEraseDomain(dom.id, dom.hostname)}
                            className="bg-red-500/10 hover:bg-red-500/20 text-rose-500 border border-rose-500/10 px-2.5 py-1 rounded-md text-[10px] font-medium transition-all"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* VISUAL ANALYTICS PANEL */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          
          {/* DONUT REPRESENTATION */}
          <div className="bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl flex flex-col items-center justify-between min-h-[300px]">
            <div className="w-full flex justify-between items-start mb-4">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">Risk Segment Distribute</h3>
              <span className="text-[10px] font-mono text-slate-500">{totalScanned} Audited</span>
            </div>
            
            <div className="flex flex-col sm:flex-row items-center gap-8 w-full justify-center">
              {/* Doughnut Ring */}
              <div className="relative w-40 h-40">
                <svg viewBox="0 0 100 100" className="w-full h-full transform -rotate-90">
                  {getDoughnutSlices()}
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-black text-white">{totalScanned}</span>
                  <span className="text-[9px] font-mono uppercase tracking-widest text-slate-500">Scanned</span>
                </div>
              </div>

              {/* Legend details */}
              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                  <span className="text-slate-300">Critical: {criticalCertsCount} ({criticalPct.toFixed(0)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                  <span className="text-slate-300 font-medium">Warning: {warningCertsCount} ({warningPct.toFixed(0)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                  <span className="text-slate-300">Healthy: {healthyCertsCount} ({healthyPct.toFixed(0)}%)</span>
                </div>
              </div>
            </div>
            <div />
          </div>

          {/* DYNAMIC SVG BAR GRAPH */}
          <div className="bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl flex flex-col justify-between min-h-[300px]">
            <div className="w-full flex justify-between items-start mb-6">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">Handshake Days Margin Index</h3>
              <span className="text-[10px] font-mono text-slate-500">Unexpired Days</span>
            </div>

            <div className="flex-1 flex flex-col justify-center space-y-4">
              {results.slice(0, 5).map((r) => {
                const maxVal = Math.max(...results.map((re) => re.days_remaining));
                const fraction = maxVal > 0 ? (r.days_remaining / maxVal) * 100 : 0;
                const barColor = r.status === "CRITICAL" ? "bg-rose-500" : r.status === "WARNING" ? "bg-amber-500" : "bg-emerald-500";
                
                return (
                  <div key={r.id} className="space-y-1">
                    <div className="flex justify-between items-center text-[10px] font-mono">
                      <span className="text-slate-200 font-bold truncate max-w-[150px]">{r.hostname}</span>
                      <span className="text-slate-400">{r.days_remaining} days remaining</span>
                    </div>
                    
                    <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-white/5">
                      <div 
                        className={`h-full ${barColor} transition-all duration-700 ease-out`} 
                        style={{ width: `${Math.max(4, fraction)}%` }} 
                      />
                    </div>
                  </div>
                );
              })}

              {results.length === 0 && (
                <div className="text-center text-xs text-slate-500 italic py-8">
                  Audit targets to generate visual analytics.
                </div>
              )}
            </div>
          </div>
        </section>

        {/* AI REMEDIATION ASSENT TICKETS */}
        <section className="bg-slate-900/55 border border-white/5 p-6 rounded-2xl backdrop-blur-md shadow-xl">
          <div className="space-y-2 mb-6">
            <h2 className="text-sm font-bold font-display uppercase tracking-wider flex items-center gap-2">
              <Terminal className="h-5 w-5 text-blue-500 animate-pulse" />
              AI remediation Incident Resolution Tickets
            </h2>
            <p className="text-slate-400 text-xs">
              Llama3 and Gemini models automatically parse expiring infrastructure entities and draft step-by-step renewal work plans.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {tickets.length === 0 ? (
              <div className="md:col-span-2 border border-dashed border-white/5 p-10 rounded-2xl text-center text-slate-500 italic">
                No tickets filed. Remediation worksheets trigger when domains resolve within WARNING (&le; 30 days) parameters.
              </div>
            ) : (
              tickets.map((ticket) => (
                <div key={ticket.id} className="bg-slate-950 border border-white/5 p-5 rounded-2xl flex flex-col justify-between hover:border-blue-500/20 transition-all duration-300">
                  <div className="space-y-4">
                    {/* Badge */}
                    <div className="flex items-center justify-between border-b border-white/5 pb-3">
                      <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-400">HOST: {ticket.hostname}</span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${
                        ticket.priority === "CRITICAL" ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      }`}>
                        {ticket.priority} RESPONSE
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white font-display tracking-tight leading-snug">{ticket.ticket_title}</h3>

                    {/* Threat Details */}
                    <div className="space-y-1">
                      <p className="text-[9px] font-mono uppercase tracking-widest text-slate-500">Security Assessment</p>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans">{ticket.description}</p>
                    </div>

                    {/* Threat Details */}
                    <div className="space-y-1">
                      <p className="text-[9px] font-mono uppercase tracking-widest text-rose-400">Business Continuity Threat</p>
                      <p className="text-xs text-rose-300/80 leading-relaxed font-sans">{ticket.business_impact}</p>
                    </div>

                    {/* Action Step codes */}
                    <div className="space-y-1 bg-slate-900 border border-white/5 p-3 rounded-lg">
                      <p className="text-[9px] font-mono uppercase tracking-widest text-blue-400 flex items-center gap-1">🔧 Remediation Guide Walkthrough</p>
                      <p className="text-[11px] text-slate-300 whitespace-pre-line leading-relaxed font-mono">{ticket.recommended_action}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between border-t border-white/5 pt-3 mt-4 text-[9px] font-mono text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> Expiry: {ticket.expiry_date}
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" /> IT Admin Goal
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {/* REACT TOASTER */}
      <div className="fixed bottom-6 right-6 z-50 space-y-2 pointer-events-none max-w-sm w-full">
        {toasts.map((toast) => {
          let themeClasses = "border-blue-500/20 text-blue-400 bg-slate-900";
          if (toast.type === "success") themeClasses = "border-emerald-500/20 text-emerald-400 bg-emerald-950/90";
          if (toast.type === "warning") themeClasses = "border-amber-500/20 text-amber-400 bg-amber-950/90";
          if (toast.type === "error") themeClasses = "border-rose-500/20 text-rose-400 bg-rose-950/90";

          return (
            <div 
              key={toast.id} 
              className={`p-4 border ${themeClasses} rounded-xl shadow-2xl backdrop-blur-md pointer-events-auto flex items-center gap-3 transition-all duration-300 transform translate-y-0`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse shrink-0" />
              <p className="text-xs font-mono leading-relaxed">{toast.message}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
