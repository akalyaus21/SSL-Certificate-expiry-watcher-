import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def scan_hostname(hostname: str):
    hostname = hostname.strip().lower()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Capture untrusted or expired certificates too for maximum audit depth
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        conn = context.wrap_socket(sock, server_hostname=hostname)
        conn.connect((hostname, 443))
        
        der_cert = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        
        # Subject Common Name
        common_name = "N/A"
        try:
            cn_attributes = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attributes:
                common_name = cn_attributes[0].value
        except Exception:
            pass
            
        # Subject Organization
        org_name = "N/A"
        try:
            org_attributes = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if org_attributes:
                org_name = org_attributes[0].value
        except Exception:
            pass
            
        # Issuer
        issuer_name = "N/A"
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if issuer_org:
                issuer_name = issuer_org[0].value
            elif issuer_cn:
                issuer_name = issuer_cn[0].value
        except Exception:
            pass
            
        # Expiration / Validity Dates
        # Handle newer cryptography (>42.0) UTC methods vs fallback naive datetime methods
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            
        valid_from_str = not_before.strftime("%Y-%m-%d")
        expiry_date_str = not_after.strftime("%Y-%m-%d")
        
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days
        
        conn.close()
        
        return {
            "success": True,
            "hostname": hostname,
            "common_name": common_name,
            "organization": org_name,
            "issuer": issuer_name,
            "valid_from": valid_from_str,
            "expiry_date": expiry_date_str,
            "days_remaining": days_remaining
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": hostname,
            "error": str(e)
        }
