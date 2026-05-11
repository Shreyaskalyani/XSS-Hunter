"""Detection Agent - Analyzes responses to detect XSS vulnerabilities"""

import re
import json
from bs4 import BeautifulSoup
from typing import Dict, Optional


class DetectionAgent:
    def analyze(self, response: object, payload: Dict, param_info: Dict) -> Optional[Dict]:
        if not response:
            return None
            
        content_type = response.headers.get('content-type', '') if hasattr(response, 'headers') else ''
        if 'application/json' in content_type:
            result = self._analyze_json_response(response, payload, param_info)
            if result:
                return result
        
        content = response.text
        
        if 'just a moment' in content.lower() or 'cloudflare' in content.lower():
            if 'challenge' in content.lower() or 'checking your browser' in content.lower():
                return None
        
        url = param_info.get('url', '')
        param = param_info.get('param', '')
        
        payload_str = payload['payload']
        
        if payload_str[:20] in content or self._decode_and_check(content, payload_str):
            context = self._identify_context(content, payload_str)
            
            if context in ['script', 'attribute', 'html']:
                if self._is_self_xss(payload_str, param_info):
                    return None
                    
                confidence = self._calculate_confidence(content, payload_str)
                snippet = self._extract_snippet(content, payload_str)
                
                return {
                    'vulnerable': True,
                    'url': url,
                    'parameter': param,
                    'payload': payload_str,
                    'context': context,
                    'confidence': confidence,
                    'evidence': snippet,
                    'method': param_info.get('method', 'GET')
                }
                
        return None
    
    def _analyze_json_response(self, response: object, payload: Dict, param_info: Dict) -> Optional[Dict]:
        """Analyze JSON responses for XSS in modern APIs"""
        try:
            data = response.json()
            payload_str = payload['payload']
            
            def check_json(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, str) and payload_str[:15] in v:
                            return True, f"{path}.{k}"
                        if isinstance(v, (dict, list)):
                            found, new_path = check_json(v, f"{path}.{k}")
                            if found:
                                return True, new_path
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        if isinstance(item, str) and payload_str[:15] in item:
                            return True, f"{path}[{i}]"
                        if isinstance(item, (dict, list)):
                            found, new_path = check_json(item, f"{path}[{i}]")
                            if found:
                                return True, new_path
                return False, ""
            
            found, path = check_json(data)
            if found:
                return {
                    'vulnerable': True,
                    'url': param_info.get('url', ''),
                    'parameter': param_info.get('param', ''),
                    'payload': payload_str,
                    'context': 'json',
                    'confidence': 'Medium',
                    'evidence': f'XSS in JSON response at {path}',
                    'method': param_info.get('method', 'GET')
                }
        except:
            pass
        return None
    
    def _decode_and_check(self, content: str, payload: str) -> bool:
        import urllib.parse
        try:
            decoded = urllib.parse.unquote(payload)
            if decoded in content:
                return True
        except:
            pass
        return False
    
    def _identify_context(self, content: str, payload: str) -> str:
        if payload[:10] in content:
            if '<script' in payload.lower() and '<script' in content.lower():
                return 'html'
            if 'onerror=' in payload.lower() or 'onload=' in payload.lower():
                return 'html'
            if payload[0] == '<' and payload[-1] == '>':
                return 'html'
            return 'html'
        return 'unknown'
    
    def _is_self_xss(self, payload: str, param_info: Dict) -> bool:
        self_xss_indicators = ['console.', 'prompt(', 'confirm(']
        payload_lower = payload.lower()
        for indicator in self_xss_indicators:
            if indicator in payload_lower:
                return True
        return False
    
    def _calculate_confidence(self, content: str, payload: str) -> str:
        if '<script>' in payload.lower() and '<script>' in content.lower():
            return 'High'
            
        if re.search(r'on(error|load|click|mouse|focus|blur|animation|transition)\s*=\s*', payload, re.IGNORECASE):
            if re.search(r'on(error|load|click|mouse|focus|blur)\s*=', content, re.IGNORECASE):
                return 'High'
                
        if payload[:15] in content:
            return 'Medium'
            
        return 'Low'
    
    def _extract_snippet(self, content: str, payload: str) -> str:
        idx = content.find(payload[:30])
        if idx >= 0:
            start = max(0, idx - 50)
            end = min(len(content), idx + len(payload) + 100)
            return content[start:end][:200]
        return content[:200]