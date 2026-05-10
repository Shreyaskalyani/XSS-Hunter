"""AI Agent - Uses Gemini API for intelligent XSS detection and analysis"""

import os
import json
import httpx
import re
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv

from agents.reporter import ReportingAgent
from agents.recon import ReconnaissanceAgent
from agents.payload import PayloadAgent
from agents.injector import InjectionAgent
from agents.detector import DetectionAgent
from utils.bypass import get_bypass_headers, BypassEngine

load_dotenv()


class AIAgent:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY', '')
        self.api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.client = httpx.AsyncClient(timeout=60.0)
        self.bypass = BypassEngine()
        self.agents = {
            'reporter': ReportingAgent(),
            'recon': ReconnaissanceAgent(self.client),
            'payload': PayloadAgent([]),
            'injector': InjectionAgent(self.client),
            'detector': DetectionAgent()
        }
        
    async def analyze_vulnerability(self, url: str, param: str, payload: str, 
                                    response_text: str, context: str) -> Dict:
        """Analyze XSS and categorize by type and impact"""
        result = {'exploitable': True, 'confidence': 50, 'bypass_techniques': [], 'remediation': ''}
        
        if '<script>' in payload.lower():
            if 'self-xss' in payload.lower() or 'console' in payload.lower():
                result['type'] = 'Self-XSS'
                result['impact'] = 'Low - Requires social engineering'
                result['remediation'] = 'Input sanitization recommended'
            else:
                result['type'] = 'Reflected XSS'
                result['impact'] = 'High - Cookie theft, redirection possible'
        elif 'onerror=' in payload or 'onload=' in payload:
            result['type'] = 'Event Handler XSS'
            result['impact'] = 'High - Executes on page load'
        else:
            result['type'] = 'Potential XSS'
            result['impact'] = 'Medium'
            
        return result
    
    async def detect_filters(self, html: str, headers: Dict = None, status_code: int = 200) -> List[str]:
        filters = []
        indicators = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai', 'akamaized', 'errors.edgesuite.net'],
            'mod_security': ['mod_security', 'NOYB'],
            'aws_waf': ['x-amz-cf-id', 'cloudfront'],
            'imperva': ['incap_ses', 'incapsula'],
        }
        
        lower_html = html.lower()
        for name, patterns in indicators.items():
            for p in patterns:
                if headers and p in str(headers).lower():
                    filters.append(name)
                    break
                if p in lower_html:
                    filters.append(name)
                    break
        return filters
    
    def analyze_csp(self, headers: Dict) -> Dict:
        csp = headers.get('content-security-policy', '')
        if not csp:
            return {'present': False, 'issues': ['No CSP header'], 'strength': 'weak'}
        
        issues = []
        strength = 'strong'
        if "'unsafe-inline'" in csp:
            issues.append("script-src allows 'unsafe-inline'")
            strength = 'weak'
        
        return {'present': True, 'issues': issues if issues else ['CSP configured'], 'strength': strength}
    
    def categorize_xss_type(self, payload: str, context: str, reflected: bool) -> Dict:
        if 'console' in payload or 'prompt' in payload:
            return {'type': 'Self-XSS', 'impact': 'Low', 'needs_user_action': True}
        elif 'document.cookie' in payload or 'location=' in payload:
            return {'type': 'Session Hijacking', 'impact': 'Critical', 'needs_user_action': True}
        elif reflected and '<script>' in payload:
            return {'type': 'Reflected XSS', 'impact': 'High', 'needs_user_action': True}
        elif reflected and ('onerror=' in payload or 'onload=' in payload):
            return {'type': 'Event Handler XSS', 'impact': 'High', 'needs_user_action': True}
        else:
            return {'type': 'Potential XSS', 'impact': 'Medium', 'needs_user_action': True}
    
    async def autonomous_scan(self, target: str) -> Dict:
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'recommendations': [],
            'security_analysis': {}
        }
        
        try:
            response, success = await self.bypass.bypass_request(self.client, 'GET', target)
            html = response.text
            headers = dict(response.headers)
            
            if not success:
                results['security_analysis'] = {'waf_detected': ['akamai'], 'csp_strength': 'unknown', 'input_points': 0}
                results['error'] = 'Target blocked by WAF (Akamai/EdgeSuite detected)'
                return results
            
            waf = await self.detect_filters(html, headers)
            if waf:
                results['security_analysis']['WAF'] = waf[0]
            
            attack_surface = await self.agents['recon'].crawl(target, 0)
            
            if not attack_surface['params']:
                attack_surface = await self.agents['recon'].crawl(target, 1)
            
            waf = await self.detect_filters(html, headers)
            csp = self.analyze_csp(headers)
            
            results['security_analysis'] = {
                'waf_detected': waf,
                'csp_strength': csp['strength'],
                'input_points': len(attack_surface['params'])
            }
            
            payloads = self.agents['payload'].generate_payloads()
            semaphore = asyncio.Semaphore(5)
            
            async def test_payload(param_info, payload):
                async with semaphore:
                    try:
                        resp = await self.agents['injector'].inject(param_info, payload)
                        if resp:
                            detection = self.agents['detector'].analyze(resp, payload, param_info)
                            if detection and detection.get('vulnerable'):
                                category = self.categorize_xss_type(
                                    payload['payload'], 
                                    detection.get('context', ''), 
                                    True
                                )
                                detection['category'] = category
                                return detection
                    except: pass
                    return None
            
            tasks = []
            for param_info in attack_surface['params']:
                for payload in payloads[:20]:
                    tasks.append(test_payload(param_info, payload))
            
            scan_results = await asyncio.gather(*tasks)
            for r in scan_results:
                if r:
                    results['vulnerabilities'].append(r)
                    
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    async def intelligent_scan(self, target: str, max_payloads: int = 50) -> Dict:
        return await self.autonomous_scan(target)
    
    async def _call_gemini(self, prompt: str) -> Dict:
        if not self.api_key:
            return {}
        try:
            response = await self.client.post(
                f"{self.api_url}?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1, "maxOutputTokens": 2000}}
            )
            if response.status_code == 200:
                return response.json()
        except: pass
        return {}
    
    async def close(self):
        await self.client.aclose()