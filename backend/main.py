import os
import csv
import io
from fastapi import FastAPI, HTTPException, UploadFile, File, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from datetime import datetime

# Import modular components
from backend.database import (
    init_db, add_domain, get_domains, delete_domain,
    save_scan_result, get_results, save_ticket, get_tickets
)
from backend.ssl_scanner import scan_hostname
from backend.ai_agent import generate_remediation_ticket
from backend.models import DomainInput, BulkDomainsInput, DomainResponse, ScanResultResponse, TicketResponse

# Initialize API
app = FastAPI(title="SSL Certificate Expiry Watcher API", version="1.0.0")

# Setup CORS cross-origin configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on module loading
@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/api/domains", response_model=DomainResponse)
def create_domain(payload: DomainInput):
    hostname = payload.hostname.strip().lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname cannot be empty")
    
    result = add_domain(hostname)
    if not result["success"]:
        # Domain exists, retrieve standard domain payload
        domains = get_domains()
        for dom in domains:
            if dom["hostname"] == hostname:
                return dom
        raise HTTPException(status_code=400, detail=result.get("message", "Error adding domain"))
    
    return result

@app.get("/api/domains", response_model=List[DomainResponse])
def read_domains():
    return get_domains()

@app.delete("/api/domains/{id}")
def remove_domain(id: int):
    success = delete_domain(id)
    if not success:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"success": True, "message": "Domain and associated records successfully expunged"}

@app.post("/api/scan-hostnames")
def scan_bulk_hostnames(payload: BulkDomainsInput):
    added_count = 0
    skipped_count = 0
    domains_list = []
    
    for hostname in payload.hostnames:
        cleaned = hostname.strip().lower()
        if not cleaned:
            continue
        
        result = add_domain(cleaned)
        if result["success"]:
            added_count += 1
            domains_list.append({"id": result["id"], "hostname": cleaned})
        else:
            skipped_count += 1
            
    # Run active socket certificate evaluations for each
    for d in get_domains():
        if d["hostname"] in payload.hostnames:
            try:
                hostname = d["hostname"]
                id = d["id"]
                scan_res = scan_hostname(hostname)
                if scan_res["success"]:
                    days_left = scan_res["days_remaining"]
                    status = "CRITICAL" if days_left <= 7 else "WARNING" if days_left <= 30 else "HEALTHY"
                    save_scan_result(
                        domain_id=id,
                        issuer=scan_res["issuer"],
                        expiry_date=scan_res["expiry_date"],
                        days_remaining=days_left,
                        status=status
                    )
                    if status in ["CRITICAL", "WARNING"]:
                        ai_ticket = generate_remediation_ticket(
                            hostname=hostname,
                            expiry_date=scan_res["expiry_date"],
                            days_left=days_left,
                            issuer=scan_res["issuer"]
                        )
                        save_ticket(
                            domain_id=id,
                            ticket_title=ai_ticket["ticket_title"],
                            priority=ai_ticket["priority"],
                            description=ai_ticket["description"],
                            business_impact=ai_ticket["business_impact"],
                            recommended_action=ai_ticket["recommended_action"]
                        )
            except Exception:
                pass

    return {
        "success": True,
        "scanned_count": len(payload.hostnames),
        "results": get_results(),
        "failures": []
    }

@app.post("/api/scan/{id}", response_model=ScanResultResponse)
def scan_single_domain(id: int):
    domains = get_domains()
    target_domain = None
    for dom in domains:
        if dom["id"] == id:
            target_domain = dom
            break
            
    if not target_domain:
        raise HTTPException(status_code=404, detail="Target domain not found")
        
    hostname = target_domain["hostname"]
    scan_res = scan_hostname(hostname)
    
    if not scan_res["success"]:
        raise HTTPException(status_code=502, detail=f"SSL scan failed for {hostname}: {scan_res.get('error', 'Unknown Error')}")
        
    # Classify Risk Level
    days_left = scan_res["days_remaining"]
    if days_left <= 7:
        status = "CRITICAL"
    elif days_left <= 30:
        status = "WARNING"
    else:
        status = "HEALTHY"
        
    # Save results
    save_scan_result(
        domain_id=id,
        issuer=scan_res["issuer"],
        expiry_date=scan_res["expiry_date"],
        days_remaining=days_left,
        status=status
    )
    
    # Trigger AI Resolution Agent for non-healthy certs
    if status in ["CRITICAL", "WARNING"]:
        ai_ticket = generate_remediation_ticket(
            hostname=hostname,
            expiry_date=scan_res["expiry_date"],
            days_left=days_left,
            issuer=scan_res["issuer"]
        )
        save_ticket(
            domain_id=id,
            ticket_title=ai_ticket["ticket_title"],
            priority=ai_ticket["priority"],
            description=ai_ticket["description"],
            business_impact=ai_ticket["business_impact"],
            recommended_action=ai_ticket["recommended_action"]
        )
        
    results = get_results()
    for res in results:
        if res["domain_id"] == id:
            return res
            
    raise HTTPException(status_code=500, detail="Failsafe error obtaining stored scan outcome")

@app.post("/api/scan-all")
def scan_all_registered_domains():
    domains = get_domains()
    if not domains:
        return {"success": True, "scanned_count": 0, "results": []}
        
    scan_count = 0
    failure_domains = []
    
    for dom in domains:
        dom_id = dom["id"]
        hostname = dom["hostname"]
        scan_res = scan_hostname(hostname)
        
        if not scan_res["success"]:
            failure_domains.append({"hostname": hostname, "reason": scan_res.get("error")})
            continue
            
        days_left = scan_res["days_remaining"]
        if days_left <= 7:
            status = "CRITICAL"
        elif days_left <= 30:
            status = "WARNING"
        else:
            status = "HEALTHY"
            
        save_scan_result(
            domain_id=dom_id,
            issuer=scan_res["issuer"],
            expiry_date=scan_res["expiry_date"],
            days_remaining=days_left,
            status=status
        )
        
        # Trigger AI ticket for warning and critical threats
        if status in ["CRITICAL", "WARNING"]:
            ai_ticket = generate_remediation_ticket(
                hostname=hostname,
                expiry_date=scan_res["expiry_date"],
                days_left=days_left,
                issuer=scan_res["issuer"]
            )
            save_ticket(
                domain_id=dom_id,
                ticket_title=ai_ticket["ticket_title"],
                priority=ai_ticket["priority"],
                description=ai_ticket["description"],
                business_impact=ai_ticket["business_impact"],
                recommended_action=ai_ticket["recommended_action"]
            )
        scan_count += 1
        
    return {
        "success": True,
        "scanned_count": scan_count,
        "results": get_results(),
        "failures": failure_domains
    }

@app.get("/api/results", response_model=List[ScanResultResponse])
def fetch_scan_results():
    return get_results()

@app.get("/api/tickets", response_model=List[TicketResponse])
def fetch_incident_tickets():
    return get_tickets()

@app.get("/api/export/csv")
def export_results_to_csv():
    results = get_results()
    
    # Format of results sort by days left remaining
    sorted_results = sorted(results, key=lambda x: x["days_remaining"])
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["hostname", "expiry_date", "days_left", "status", "issuer", "owner"])
    
    for r in sorted_results:
        writer.writerow([
            r["hostname"],
            r["expiry_date"],
            r["days_remaining"],
            r["status"],
            r["issuer"],
            "Infrastructure Team"  # Generic placeholder owner
        ])
        
    csv_str = output.getvalue()
    output.close()
    
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ranked_certs.csv"}
    )

@app.get("/api/export/markdown")
def export_tickets_to_markdown():
    tickets = get_tickets()
    
    # Sort tickets by urgency
    sorted_tickets = sorted(tickets, key=lambda x: x["days_remaining"])
    
    md_content = []
    md_content.append("# SSL Certificate Expiry Watcher - Renewal Tasks Workbook")
    md_content.append(f"**Generated On**: `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC`")
    md_content.append("This document was generated automatically by the AI remediation coordinator. It contains active action tickets for expiring TLS/SSL parameters.")
    md_content.append("\n" + "=" * 50 + "\n")
    
    if not sorted_tickets:
        md_content.append("## Status Report: No Active Threat Tickets\nAll monitored domains present healthy certificates expiring over 30 days out. No remediation items reported.")
    else:
        for t in sorted_tickets:
            md_content.append(f"## [{t['priority']}] Hostname: {t['hostname']}")
            md_content.append(f"- **Certificate Issuer**: `{t['issuer']}`")
            md_content.append(f"- **Scheduled Expiry**: `{t['expiry_date']}`")
            md_content.append(f"- **Days Until Handshake Breakout**: `{t['days_remaining']} days`")
            md_content.append(f"- **Incident Remediation Priority**: `{t['priority']}`")
            md_content.append(f"- **Renewal Due Date Goal**: {datetime.strptime(t['expiry_date'], '%Y-%m-%d').strftime('%Y-%m-%d')} (Renew *at least* 10 days before expiry)")
            md_content.append(f"- **Assigned Handler Account**: `[IT Engineer / Infrastructure Architect]`")
            md_content.append("\n### Incident Risk Assessment")
            md_content.append(t["description"])
            md_content.append("\n### Direct Business & Customer Impact")
            md_content.append(t["business_impact"])
            md_content.append("\n### Mandatory Technical Remediation Steps")
            md_content.append(t["recommended_action"])
            md_content.append("\n" + "-" * 50 + "\n")
            
    md_str = "\n".join(md_content)
    
    return Response(
        content=md_str,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=renewal_tasks.md"}
    )
