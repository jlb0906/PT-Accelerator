# This file defines the data models used in the application.
# Add your Pydantic models or other data structures here.

from pydantic import BaseModel, Field
from typing import List, Optional

class Tracker(BaseModel):
    name: str
    domain: str
    ip: Optional[str] = None
    enable: bool = True

class HostsSource(BaseModel):
    name: str
    url: str
    enable: bool = True

class CloudflareConfig(BaseModel):
    enable: bool = True
    cron: str = "0 0 * * *"
    # Add other Cloudflare related fields if necessary

class TorrentClientConfig(BaseModel):
    type: str # e.g., 'qbittorrent', 'transmission'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    enable: bool = True

class BatchAddDomainsRequest(BaseModel):
    domains: List[str]

# You might need to add other models based on your application's needs