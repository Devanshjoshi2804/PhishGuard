from typing import Dict, Any, Optional
import os
import httpx
from datetime import datetime
import json

class Database:
    """Database utility for storing and retrieving analysis results."""
    
    def __init__(self):
        """Initialize database connection."""
        self.url = os.getenv('SUPABASE_URL', '')
        self.key = os.getenv('SUPABASE_KEY', '')
        self.headers = {
            'apikey': self.key,
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }
        self.client = httpx.AsyncClient(headers=self.headers)

    async def insert_phishing_incident(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a new phishing incident."""
        url = f"{self.url}/rest/v1/phishing_incidents"
        payload = {
            'incident_id': data['incident_id'],
            'raw_data': data,
            'created_at': datetime.utcnow().isoformat()
        }
        response = await self.client.post(url, json=payload)
        response.raise_for_status()
        try:
            return response.json()[0] if response.json() else {}
        except (json.JSONDecodeError, IndexError):
            return {}

    async def update_analysis_result(self, incident_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update analysis results for an incident."""
        url = f"{self.url}/rest/v1/analysis_results"
        payload = {
            'incident_id': incident_id,
            **data,
            'updated_at': datetime.utcnow().isoformat()
        }
        # Add Prefer header for upsert
        headers = {**self.headers, 'Prefer': 'resolution=merge-duplicates'}
        response = await self.client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        try:
            return response.json()[0] if response.json() else {}
        except (json.JSONDecodeError, IndexError):
            return {}

    async def get_analysis_result(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis results for an incident."""
        url = f"{self.url}/rest/v1/analysis_results"
        params = {'incident_id': f'eq.{incident_id}'}
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        try:
            return response.json()[0] if response.json() else None
        except (json.JSONDecodeError, IndexError):
            return None

    async def cleanup(self):
        """Close the HTTP client."""
        await self.client.aclose()

# Create a singleton instance
db = Database() 