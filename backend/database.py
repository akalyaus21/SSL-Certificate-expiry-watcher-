import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Create domains table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 2. Create scan_results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        issuer TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        days_remaining INTEGER NOT NULL,
        status TEXT NOT NULL,
        last_scan TEXT NOT NULL,
        FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
    )
    """)
    
    # 3. Create tickets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        ticket_title TEXT NOT NULL,
        priority TEXT NOT NULL,
        description TEXT NOT NULL,
        business_impact TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
    )
    """)
    
    conn.commit()
    conn.close()

def add_domain(hostname: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO domains (hostname) VALUES (?)", (hostname.strip().lower(),))
        conn.commit()
        domain_id = cursor.lastrowid
        return {"id": domain_id, "hostname": hostname.strip().lower(), "success": True}
    except sqlite3.IntegrityError:
        # Domain already exists
        cursor.execute("SELECT id FROM domains WHERE hostname = ?", (hostname.strip().lower(),))
        row = cursor.fetchone()
        return {"id": row["id"] if row else None, "hostname": hostname, "success": False, "message": "Domain already exists"}
    finally:
        conn.close()

def get_domains():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM domains ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r["id"], "hostname": r["hostname"], "created_at": r["created_at"]} for r in rows]

def delete_domain(domain_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
    cursor.execute("DELETE FROM scan_results WHERE domain_id = ?", (domain_id,))
    cursor.execute("DELETE FROM tickets WHERE domain_id = ?", (domain_id,))
    conn.commit()
    conn.close()
    return True

def save_scan_result(domain_id: int, issuer: str, expiry_date: str, days_remaining: int, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().isoformat()
    # Check if scan result already exists
    cursor.execute("SELECT id FROM scan_results WHERE domain_id = ?", (domain_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("""
            UPDATE scan_results 
            SET issuer = ?, expiry_date = ?, days_remaining = ?, status = ?, last_scan = ?
            WHERE domain_id = ?
        """, (issuer, expiry_date, days_remaining, status, now_str, domain_id))
    else:
        cursor.execute("""
            INSERT INTO scan_results (domain_id, issuer, expiry_date, days_remaining, status, last_scan)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain_id, issuer, expiry_date, days_remaining, status, now_str))
    conn.commit()
    conn.close()

def get_results():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sr.*, d.hostname 
        FROM scan_results sr 
        JOIN domains d ON sr.domain_id = d.id 
        ORDER BY sr.days_remaining ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r["id"],
        "domain_id": r["domain_id"],
        "hostname": r["hostname"],
        "issuer": r["issuer"],
        "expiry_date": r["expiry_date"],
        "days_remaining": r["days_remaining"],
        "status": r["status"],
        "last_scan": r["last_scan"]
    } for r in rows]

def save_ticket(domain_id: int, ticket_title: str, priority: str, description: str, business_impact: str, recommended_action: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Delete previous ticket for this domain to keep it updated
    cursor.execute("DELETE FROM tickets WHERE domain_id = ?", (domain_id,))
    cursor.execute("""
        INSERT INTO tickets (domain_id, ticket_title, priority, description, business_impact, recommended_action)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (domain_id, ticket_title, priority, description, business_impact, recommended_action))
    conn.commit()
    conn.close()

def get_tickets():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, d.hostname, sr.expiry_date, sr.days_remaining, sr.issuer
        FROM tickets t
        JOIN domains d ON t.domain_id = d.id
        LEFT JOIN scan_results sr ON t.domain_id = sr.domain_id
        ORDER BY sr.days_remaining ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r["id"],
        "domain_id": r["domain_id"],
        "hostname": r["hostname"],
        "expiry_date": r["expiry_date"],
        "days_remaining": r["days_remaining"],
        "issuer": r["issuer"],
        "ticket_title": r["ticket_title"],
        "priority": r["priority"],
        "description": r["description"],
        "business_impact": r["business_impact"],
        "recommended_action": r["recommended_action"],
        "created_at": r["created_at"]
    } for r in rows]
