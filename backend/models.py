from pydantic import BaseModel, Field
from typing import List, Optional

class DomainInput(BaseModel):
    hostname: str = Field(..., description="The target hostname to scan (e.g., google.com)")

class BulkDomainsInput(BaseModel):
    hostnames: List[str] = Field(..., description="List of target hostnames")

class DomainResponse(BaseModel):
    id: int
    hostname: str
    created_at: str

class ScanResultResponse(BaseModel):
    id: int
    domain_id: int
    hostname: str
    issuer: str
    expiry_date: str
    days_remaining: int
    status: str
    last_scan: str

class TicketResponse(BaseModel):
    id: int
    domain_id: int
    hostname: str
    expiry_date: str
    days_remaining: int
    issuer: str
    ticket_title: str
    priority: str
    description: str
    business_impact: str
    recommended_action: str
    created_at: str
