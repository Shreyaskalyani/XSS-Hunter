"""Utility functions for XSS Scanner"""

from urllib.parse import urlparse, parse_qs
from typing import Dict, List


def extract_params_from_url(url: str) -> List[Dict]:
    """Extract parameters from URL query string"""
    parsed = urlparse(url)
    params = []
    
    if parsed.query:
        query_params = parse_qs(parsed.query)
        for name in query_params.keys():
            params.append({
                'param': name,
                'url': url,
                'method': 'GET',
                'context': 'url'
            })
            
    return params


def normalize_url(url: str) -> str:
    """Normalize URL for consistent storage"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"