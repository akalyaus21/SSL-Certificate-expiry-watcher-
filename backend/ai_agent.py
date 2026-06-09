import os
import json
import requests

def generate_remediation_ticket(hostname: str, expiry_date: str, days_left: int, issuer: str):
    # Set priority based on risk rules
    priority_level = "CRITICAL" if days_left <= 7 else "HIGH"
    
    # Retrieve Groq API Key
    api_key = os.getenv("GROQ_API_KEY")
    
    # Define a high-fidelity cybersecurity remediation template to handle fallbacks
    fallback_ticket = {
        "ticket_title": f"INC-RESOLVE: TLS/SSL Certificate Expiry Imminent - {hostname.upper()}",
        "priority": priority_level,
        "description": f"Audited domain [{hostname}] is presenting an SSL certificate issued by '{issuer}' which is scheduled to expire in {days_left} days ({expiry_date}). If unmitigated, client agents navigating to this HTTPS host will experience handshake rejection. Immediate administrative renewal is required.",
        "business_impact": f"Rejection of incoming consumer sessions via public browsers due to HSTS and TLS trust path voids. Immediate disruption to downstream web-dependent integration routes and REST clients. Direct degradation of corporate brand integrity, SEO page placement scores, and security compliance scores.",
        "recommended_action": "1. Access current certificate server shell space or network load balancer interface.\n2. Formulate a 2048-bit RSA Certificate Signing Request (CSR) detailing common name and alternate target SANs.\n3. Relay CSR details to the enterprise DNS registrar or Certificate Authority console (e.g. Let's Encrypt or DigiCert).\n4. Download the signed public certificate bundle along with root/intermediate chain bundles.\n5. Bind the newly acquired bundle to port 443 web ingress listeners and reload the host service module (e.g., NGINX, IIS, or Cloudflare Proxy).\n6. Execute validation scans to guarantee absolute chain transparency."
    }
    
    if not api_key:
        return fallback_ticket

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    prompt = f"""
    You are an elite Senior Cybersecurity Automation Engineer.
    Formulate a comprehensive enterprise-level security incident resolution ticket for an expiring SSL certificate.

    Target Host: {hostname}
    Certificate Issuer: {issuer}
    Target Expiry: {expiry_date}
    Days Until Expiry: {days_left} days
    Determined Risk Priority: {priority_level}

    Format your output strictly as a raw JSON block containing the fields detailed below.
    Do NOT include any conversational text, markdown formatting blocks (like ```json), or extra explanations. Only return the raw JSON object.

    JSON Template Structure:
    {{
        "ticket_title": "String - Professional incident code, severity and domain name",
        "priority": "String - 'CRITICAL' or 'HIGH'",
        "description": "String - Extremely academic, technical overview of current SSL parameters, expiration dates, and cipher security warnings",
        "business_impact": "String - Detailed financial, operational, and commercial ramifications of service dropoff and browser trust blocks for this domain",
        "recommended_action": "String - Step-by-step instructions (numbered) on how engineers should renew, compile CSR, and install the cert securely"
    }}
    """

    payload = {
        "model": "llama3-8b-8192",
        "messages": [
            {
                "role": "system",
                "content": "You are a quiet cybersecurity AI agent who outputs only structured JSON certificates data."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=8.0)
        if response.status_code == 200:
            raw_text = response.json()["choices"][0]["message"]["content"].strip()
            # De-wrap markdown quotes just in case Llama ignored prompts
            if "```" in raw_text:
                parts = raw_text.split("```")
                for part in parts:
                    if part.strip().startswith("{") or part.strip().startswith("{\n"):
                        raw_text = part.strip()
                        break
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:].strip()
            
            clean_json = json.loads(raw_text)
            # Ensure the response has requested keys or patch them
            for key in fallback_ticket.keys():
                if key not in clean_json or not clean_json[key]:
                    clean_json[key] = fallback_ticket[key]
            return clean_json
    except Exception:
        # Fallback to high-quality template on timeout or API hiccups
        pass
        
    return fallback_ticket
