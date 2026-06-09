/**
 * SSL Certificate Expiry Watcher - Frontend Controller (Vanilla ES6)
 * Synchronizes list actions, triggers socket scans, and charts security risk profiles.
 */

// Application State Store
let domainsState = [];
let resultsState = [];
let ticketsState = [];

// Chart.js Instances
let riskPieChartInstance = null;
let daysBarChartInstance = null;

// Initializer on Dom Load
document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

async function initApp() {
    setupEventListeners();
    initCharts();
    await refreshAllData();
}

// Global Event Binds
function setupEventListeners() {
    // Register Domains Action
    document.getElementById("add-domains-btn").addEventListener("click", addManualDomains);
    
    // File Upload Monitor
    const fileInput = document.getElementById("file-upload-input");
    fileInput.addEventListener("change", handleFileUpload);
    
    // Execute Broad Audit Scans Action
    document.getElementById("scan-all-btn").addEventListener("click", triggerBulkAudits);
    
    // Report Downloads Action
    document.getElementById("download-csv-btn").addEventListener("click", downloadCsvReport);
    document.getElementById("download-md-btn").addEventListener("click", downloadMarkdownReport);
}

// Fetch all states from local DB
async function refreshAllData() {
    try {
        await Promise.all([
            fetchDomains(),
            fetchScanResults(),
            fetchIncidentTickets()
        ]);
        renderDashboard();
        updateCharts();
    } catch (err) {
        showToast("Error refreshing live database stats: " + err.message, "error");
    }
}

// API Calls
async function fetchDomains() {
    const res = await fetch("/api/domains");
    if (res.ok) {
        domainsState = await res.json();
    }
}

async function fetchScanResults() {
    const res = await fetch("/api/results");
    if (res.ok) {
        resultsState = await res.json();
    }
}

async function fetchIncidentTickets() {
    const res = await fetch("/api/tickets");
    if (res.ok) {
        ticketsState = await res.json();
    }
}

// Domestic DB domain creation
async function addManualDomains() {
    const textInput = document.getElementById("manual-hostnames-input");
    const val = textInput.value.trim();
    if (!val) {
        showToast("Target input values cannot be blank", "warning");
        return;
    }
    
    const lines = val.split("\n").map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith("#"));
    if (lines.length === 0) {
        showToast("No valid hostnames detected", "warning");
        return;
    }
    
    showToast(`Registering ${lines.length} domain references...`, "info");
    
    let added = 0;
    for (const host of lines) {
        try {
            const res = await fetch("/api/domains", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ hostname: host })
            });
            if (res.ok) added++;
        } catch (e) {
            console.error(e);
        }
    }
    
    textInput.value = "";
    showToast(`Successfully registered ${added} targets.`, "success");
    await refreshAllData();
}

// File system uploads handler
async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    document.getElementById("uploaded-file-name").textContent = file.name;
    
    const formData = new FormData();
    formData.append("file", file);
    
    showToast(`Parsing ${file.name} bulk sheet...`, "info");
    
    try {
        const res = await fetch("/api/upload-hostnames", {
            method: "POST",
            body: formData
        });
        
        if (res.ok) {
            const output = await res.json();
            showToast(output.message, "success");
            await refreshAllData();
        } else {
            const err = await res.json();
            showToast(err.detail || "File structure validation failed", "error");
        }
    } catch (e) {
        showToast("Error uploading DNS sheets: " + e.message, "error");
    }
}

// Executing socket scans across registered domains
async function triggerBulkAudits() {
    if (domainsState.length === 0) {
        showToast("No DNS host targets registered for audit scans. Enter targets first.", "warning");
        return;
    }
    
    showToast("Commencing live socket scans over Port 443... Please wait.", "info");
    setScanButtonLoading(true);
    
    try {
        const res = await fetch("/api/scan-all", { method: "POST" });
        if (res.ok) {
            const outcome = await res.json();
            showToast(`Audited ${outcome.scanned_count} domains successfully.`, "success");
            if (outcome.failures && outcome.failures.length > 0) {
                showToast(`Failed resolving ${outcome.failures.length} unreachable hosts.`, "warning");
            }
            await refreshAllData();
        } else {
            showToast("Bulk certificate resolution crashed.", "error");
        }
    } catch (e) {
        showToast("Audit connectivity fail: " + e.message, "error");
    } finally {
        setScanButtonLoading(false);
    }
}

// Scan individual Target ID
async function triggerSingleAudit(id, hostname) {
    showToast(`Opening socket audit connection to ${hostname}...`, "info");
    try {
        const res = await fetch(`/api/scan/${id}`, { method: "POST" });
        if (res.ok) {
            showToast(`Fully verified trust parameters of ${hostname}.`, "success");
            await refreshAllData();
        } else {
            const err = await res.json();
            showToast(err.detail || `Scan of ${hostname} failed`, "error");
        }
    } catch (e) {
        showToast("Audit failed: " + e.message, "error");
    }
}

// Expunge records
async function deleteRegisteredDomain(id, hostname) {
    if (!confirm(`Are you sure you want to expunge ${hostname} and all historical audit logs?`)) return;
    
    try {
        const res = await fetch(`/api/domains/${id}`, { method: "DELETE" });
        if (res.ok) {
            showToast(`Deleted ${hostname} registry keys.`, "success");
            await refreshAllData();
        } else {
            showToast("Expunge action declined by database.", "error");
        }
    } catch (e) {
        showToast("Database communication fail: " + e.message, "error");
    }
}

// Download actions
function downloadCsvReport() {
    if (resultsState.length === 0) {
        showToast("No active scan records available to form sheets.", "warning");
        return;
    }
    window.open("/api/export/csv", "_blank");
}

function downloadMarkdownReport() {
    const vulnerableCount = resultsState.filter(r => r.status !== "HEALTHY").length;
    if (vulnerableCount === 0) {
        showToast("No non-healthy risk targets found to populate renewal playbooks", "warning");
        return;
    }
    window.open("/api/export/markdown", "_blank");
}

// Interactive render arrays
function renderDashboard() {
    // 1. Update stats indicators count
    document.getElementById("stat-total").textContent = domainsState.length;
    document.getElementById("registered-domains-counter").textContent = `${domainsState.length} Hosts Monitored`;
    
    // Sort results, prioritizing urgencies
    const sortedResults = [...resultsState].sort((a,b) => a.days_remaining - b.days_remaining);
    
    // Calculate stats bounds
    let criticalCount = 0;
    let warningCount = 0;
    let healthyCount = 0;
    
    sortedResults.forEach(r => {
        if (r.status === "CRITICAL") criticalCount++;
        else if (r.status === "WARNING") warningCount++;
        else healthyCount++;
    });
    
    document.getElementById("stat-critical").textContent = criticalCount;
    document.getElementById("stat-warning").textContent = warningCount;
    document.getElementById("stat-healthy").textContent = healthyCount;
    
    // 2. Render Database table rows
    const tbody = document.getElementById("scan-results-tbody");
    tbody.innerHTML = "";
    
    if (domainsState.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="p-8 text-center text-gray-500 italic">
                    No DNS hostnames registered or scanned. Paste a collection above to initiate real-time socket audits.
                </td>
            </tr>
        `;
        return;
    }
    
    // Create mapping of domains to identify which have not been scanned
    const scannedMap = {};
    resultsState.forEach(r => { scannedMap[r.domain_id] = r; });
    
    domainsState.forEach(dom => {
        const scan = scannedMap[dom.id];
        let rowHtml = "";
        
        if (scan) {
            let statusBadge = "";
            let daysBadge = "";
            
            if (scan.status === "CRITICAL") {
                statusBadge = `<span class="px-2.5 py-1 text-xs font-mono font-bold bg-red-500/10 text-red-500 border border-red-500/20 rounded">CRITICAL</span>`;
                daysBadge = `<span class="text-red-500 font-bold font-mono">${scan.days_remaining} days left</span>`;
            } else if (scan.status === "WARNING") {
                statusBadge = `<span class="px-2.5 py-1 text-xs font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 rounded">WARNING</span>`;
                daysBadge = `<span class="text-amber-400 font-semibold font-mono">${scan.days_remaining} days left</span>`;
            } else {
                statusBadge = `<span class="px-2.5 py-1 text-xs font-mono font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded">HEALTHY</span>`;
                daysBadge = `<span class="text-emerald-500 font-mono">${scan.days_remaining} days left</span>`;
            }
            
            rowHtml = `
                <tr class="hover:bg-slate-900/40 transition-colors border-b border-cyber-border/40 font-sans">
                    <td class="p-4 font-bold text-white tracking-wide">${dom.hostname}</td>
                    <td class="p-4 text-xs font-mono text-gray-400">${scan.issuer}</td>
                    <td class="p-4 text-xs font-mono text-gray-400">${scan.expiry_date}</td>
                    <td class="p-4 font-mono">${daysBadge}</td>
                    <td class="p-4">${statusBadge}</td>
                    <td class="p-4 text-right space-x-2 shrink-0">
                        <button onclick="triggerSingleAudit(${dom.id}, '${dom.hostname}')" class="bg-blue-600/10 text-blue-400 border border-blue-500/20 hover:bg-blue-600/20 transition-all font-display rounded text-xs px-3 py-1.5 font-medium">Re-scan</button>
                        <button onclick="deleteRegisteredDomain(${dom.id}, '${dom.hostname}')" class="bg-rose-600/10 text-rose-500 border border-rose-500/20 hover:bg-rose-600/20 transition-all font-display rounded text-xs px-3 py-1.5 font-medium">Clear</button>
                    </td>
                </tr>
            `;
        } else {
            rowHtml = `
                <tr class="hover:bg-slate-900/40 transition-colors border-b border-cyber-border/40 font-sans bg-slate-900/10">
                    <td class="p-4 font-bold text-white tracking-wide opacity-60">${dom.hostname}</td>
                    <td class="p-4 text-xs font-mono text-gray-600 italic">Not Audited</td>
                    <td class="p-4 text-xs font-mono text-gray-600 italic">Not Audited</td>
                    <td class="p-4 text-xs font-mono text-gray-600 italic">Pending Scan</td>
                    <td class="p-4"><span class="px-2.5 py-1 text-xs font-mono font-bold bg-gray-800 text-gray-500 rounded border border-gray-700/50">PENDING</span></td>
                    <td class="p-4 text-right space-x-2 shrink-0">
                        <button onclick="triggerSingleAudit(${dom.id}, '${dom.hostname}')" class="bg-emerald-600/20 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-600/30 transition-all font-display rounded text-xs px-3 py-1.5 font-medium">Run Scan</button>
                        <button onclick="deleteRegisteredDomain(${dom.id}, '${dom.hostname}')" class="bg-rose-600/10 text-rose-500 border border-rose-500/20 hover:bg-rose-600/20 transition-all font-display rounded text-xs px-3 py-1.5 font-medium">Clear</button>
                    </td>
                </tr>
            `;
        }
        
        tbody.insertAdjacentHTML("beforeend", rowHtml);
    });
    
    // 3. Render AI remediation Incident Tickets
    const ticketWrap = document.getElementById("ai-remediation-cards");
    ticketWrap.innerHTML = "";
    
    if (ticketsState.length === 0) {
        ticketWrap.innerHTML = `
            <div class="md:col-span-2 border border-dashed border-cyber-border p-8 rounded-xl text-center text-gray-500 italic">
                No priority security tickets generated. Tickets activate when domains in WARNING or CRITICAL margins are processed.
            </div>
        `;
        return;
    }
    
    ticketsState.forEach(ticket => {
        const priorityColor = ticket.priority === "CRITICAL" ? "rose-500 border-rose-500/20" : "amber-500 border-amber-500/20";
        const priorityBadge = ticket.priority === "CRITICAL" ? "bg-rose-500/10 text-rose-500" : "bg-amber-500/10 text-amber-500";
        
        const cardHtml = `
            <div class="bg-gray-900/60 border border-cyber-border rounded-xl p-5 shadow-md flex flex-col justify-between transition-all hover:scale-[1.01] hover:border-${priorityColor}">
                <div class="space-y-4">
                    <!-- Title and badge header -->
                    <div class="flex items-center justify-between gap-3 border-b border-cyber-border pb-3">
                        <span class="text-xs font-mono font-bold tracking-wider text-white">HOST: ${ticket.hostname.toUpperCase()}</span>
                        <span class="px-2.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded ${priorityBadge}">${ticket.priority} RESPONSE</span>
                    </div>
                    
                    <!-- Ticket Title -->
                    <h4 class="text-md font-bold font-display text-white tracking-wide">${ticket.ticket_title}</h4>
                    
                    <!-- Description -->
                    <div class="space-y-1">
                        <p class="text-xs font-mono uppercase text-gray-400">Security Assessment</p>
                        <p class="text-xs text-gray-300 leading-relaxed">${ticket.description}</p>
                    </div>

                    <!-- Impact details -->
                    <div class="space-y-1">
                        <p class="text-xs font-mono uppercase text-rose-400">Business Continuity Threat</p>
                        <p class="text-xs text-rose-300/80 leading-relaxed">${ticket.business_impact}</p>
                    </div>
                    
                    <!-- Mitigation action steps -->
                    <div class="space-y-2 pt-2 bg-slate-950/40 p-3 rounded-lg border border-cyber-border/40">
                        <p class="text-xs font-mono uppercase text-blue-400 flex items-center gap-1">
                            🔧 Remediation Walkthrough Code
                        </p>
                        <div class="text-xs text-gray-300 whitespace-pre-line leading-relaxed font-sans">${ticket.recommended_action}</div>
                    </div>
                </div>
                
                <div class="flex justify-between items-center pt-4 border-t border-cyber-border mt-4 text-[10px] font-mono text-gray-500">
                    <span>Generated Expiry: ${ticket.expiry_date}</span>
                    <span>Goal: Handshake Secure</span>
                </div>
            </div>
        `;
        ticketWrap.insertAdjacentHTML("beforeend", cardHtml);
    });
}

// Chart plotting implementations via Chart.js
function initCharts() {
    // Pie Chart
    const pieCtx = document.getElementById("riskPieChart").getContext("2d");
    riskPieChartInstance = new Chart(pieCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Warning', 'Healthy'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                borderWidth: 1,
                borderColor: '#1e293b'
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Space Grotesk', size: 11 } }
                }
            },
            maintainAspectRatio: false,
            cutout: '65%'
        }
    });

    // Bar Chart
    const barCtx = document.getElementById("daysBarChart").getContext("2d");
    daysBarChartInstance = new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Remaining Handshake Days',
                data: [],
                backgroundColor: 'rgba(59, 130, 246, 0.45)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { family: 'Space Grotesk', size: 10 } }
                }
            },
            plugins: {
                legend: { display: false }
            },
            maintainAspectRatio: false
        }
    });
}

function updateCharts() {
    if (!riskPieChartInstance || !daysBarChartInstance) return;
    
    // Audit counting statuses
    let criticalCount = 0;
    let warningCount = 0;
    let healthyCount = 0;
    
    const hostnames = [];
    const daysLeft = [];
    
    // Sort results, prioritizing urgencies
    const sortedResults = [...resultsState].sort((a,b) => a.days_remaining - b.days_remaining);
    
    sortedResults.forEach(r => {
        if (r.status === "CRITICAL") criticalCount++;
        else if (r.status === "WARNING") warningCount++;
        else healthyCount++;
        
        // Take top 8 worst domains for bar metrics
        if (hostnames.length < 8) {
            hostnames.push(r.hostname);
            daysLeft.push(Math.max(0, r.days_remaining));
        }
    });
    
    // Update Pie
    riskPieChartInstance.data.datasets[0].data = [criticalCount, warningCount, healthyCount];
    riskPieChartInstance.update();
    
    // Update Bar
    daysBarChartInstance.data.labels = hostnames;
    daysBarChartInstance.data.datasets[0].data = daysLeft;
    
    // Color bar dynamically based on danger levels
    daysBarChartInstance.data.datasets[0].backgroundColor = daysLeft.map(d => {
        if (d <= 7) return 'rgba(239, 68, 68, 0.55)';
        if (d <= 30) return 'rgba(245, 158, 11, 0.55)';
        return 'rgba(16, 185, 129, 0.45)';
    });
    daysBarChartInstance.data.datasets[0].borderColor = daysLeft.map(d => {
        if (d <= 7) return '#ef4444';
        if (d <= 30) return '#f59e0b';
        return '#10b981';
    });
    daysBarChartInstance.update();
}

function setScanButtonLoading(isLoading) {
    const btn = document.getElementById("scan-all-btn");
    if (isLoading) {
        btn.disabled = true;
        btn.classList.add("opacity-50", "cursor-not-allowed");
        btn.innerHTML = `
            <svg class="animate-spin h-4 w-4 mr-1 text-white inline" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            Auditing sockets...
        `;
    } else {
        btn.disabled = false;
        btn.classList.remove("opacity-50", "cursor-not-allowed");
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 15H19" />
            </svg>
            Execute audits
        `;
    }
}

// Cybernetic Toast Notify
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    
    // Choose border colors
    let themeColor = "border-blue-500/30 text-blue-400 bg-slate-900/90";
    if (type === "success") themeColor = "border-emerald-500/30 text-emerald-400 bg-slate-900/90";
    if (type === "warning") themeColor = "border-amber-500/30 text-amber-400 bg-slate-900/90";
    if (type === "error") themeColor = "border-rose-500/30 text-rose-400 bg-slate-900/90";
    
    toast.className = `p-4 border ${themeColor} rounded-xl shadow-lg backdrop-blur-md pointer-events-auto transition-all duration-300 transform translate-y-2 opacity-0 max-w-sm flex items-center gap-3`;
    
    toast.innerHTML = `
        <span class="w-1.5 h-1.5 rounded-full bg-current animate-pulse"></span>
        <p class="text-xs font-mono flex-1 leading-snug">${message}</p>
    `;
    
    container.appendChild(toast);
    
    // Trigger transition Reflow
    setTimeout(() => {
        toast.classList.remove("translate-y-2", "opacity-0");
    }, 10);
    
    // Removals
    setTimeout(() => {
        toast.classList.add("translate-y-2", "opacity-0");
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}
