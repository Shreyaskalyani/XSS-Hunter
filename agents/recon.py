"""Reconnaissance Agent - Crawls target and extracts attack surface"""

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx
from typing import Dict, List, Set
from utils.bypass import get_bypass_headers


class ReconnaissanceAgent:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.visited: Set[str] = set()
        self.attack_surface = {
            'urls': [],
            'params': [],
            'forms': [],
            'js_endpoints': [],
            'headers': []
        }
        
    async def crawl(self, start_url: str, depth: int) -> Dict:
        await self._crawl_recursive(start_url, depth)
        return self.attack_surface
        
    async def _crawl_recursive(self, url: str, remaining_depth: int):
        if remaining_depth < 0 or url in self.visited:
            return
            
        self.visited.add(url)
        
        if url not in self.attack_surface['urls']:
            self.attack_surface['urls'].append(url)
        
        self._extract_url_params(url)
        
        try:
            response = await self.client.get(url, headers=get_bypass_headers())
            
            if response.status_code >= 400:
                return
            
            content_type = response.headers.get('content-type', '') if hasattr(response, 'headers') else ''
            if 'application/json' in content_type:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_info = self._extract_form(form, url)
                self.attack_surface['forms'].append(form_info)
            
            if remaining_depth > 0 and len(self.attack_surface['urls']) < 50:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if self._is_same_domain(next_url, url) and len(self.visited) < 50:
                        await self._crawl_recursive(next_url, remaining_depth - 1)
                        
        except Exception:
            pass
            
    def _extract_form(self, form, base_url: str) -> Dict:
        action = form.get('action', base_url)
        method = form.get('method', 'GET').upper()
        inputs = []
        
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            if name:
                inputs.append({
                    'name': name,
                    'type': input_type,
                    'context': 'form'
                })
                self.attack_surface['params'].append({
                    'url': urljoin(base_url, action),
                    'param': name,
                    'method': method,
                    'context': 'form',
                    'input_type': input_type
                })
                
        return {
            'action': urljoin(base_url, action),
            'method': method,
            'inputs': inputs
        }
        
    def _extract_url_params(self, url: str):
        """Extract query parameters from URL"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name in params.keys():
                param_entry = {
                    'url': url,
                    'param': name,
                    'method': 'GET',
                    'context': 'url',
                    'input_type': 'text'
                }
                if param_entry not in self.attack_surface['params']:
                    self.attack_surface['params'].append(param_entry)
        elif '=' in parsed.path or url.endswith('='):
            path_query = parsed.path.split('?')[-1] if '?' in parsed.path else ''
            if '=' in path_query or url.endswith('='):
                param_name = url.split('=')[-1].split('&')[0] if '=' in url else 'param'
                param_entry = {
                    'url': url,
                    'param': param_name,
                    'method': 'GET',
                    'context': 'url',
                    'input_type': 'text'
                }
                if param_entry not in self.attack_surface['params']:
                    self.attack_surface['params'].append(param_entry)
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        return urlparse(url1).netloc == urlparse(url2).netloc