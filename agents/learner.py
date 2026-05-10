"""Learning Agent - Tracks successful payloads and improves detection"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class LearningAgent:
    def __init__(self, storage_path: str = "scanner/learning_data.json"):
        self.storage_path = Path(storage_path)
        self.successful_payloads: List[Dict] = []
        self.vulnerable_patterns: List[Dict] = []
        self.load_data()
        
    def load_data(self):
        """Load previous learning data"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    self.successful_payloads = data.get('payloads', [])
                    self.vulnerable_patterns = data.get('patterns', [])
            except Exception:
                pass
                
    def record_success(self, result: Dict):
        """Record a successful vulnerability detection"""
        if not result or not result.get('vulnerable'):
            return
            
        # Record successful payload
        payload_entry = {
            'payload': result.get('payload', ''),
            'context': result.get('context', ''),
            'url': result.get('url', ''),
            'parameter': result.get('parameter', ''),
            'confidence': result.get('confidence', 'Medium'),
            'timestamp': datetime.now().isoformat()
        }
        
        self.successful_payloads.append(payload_entry)
        
        # Record vulnerable pattern
        pattern_entry = {
            'url_pattern': self._extract_pattern(result.get('url', '')),
            'param_pattern': result.get('parameter', ''),
            'context': result.get('context', ''),
            'payload_type': self._classify_payload(result.get('payload', ''))
        }
        
        self.vulnerable_patterns.append(pattern_entry)
        self._save_data()
        
    def _extract_pattern(self, url: str) -> str:
        """Extract URL pattern for matching"""
        import re
        pattern = re.sub(r'/\d+/', '/{id}/', url)
        pattern = re.sub(r'=[^&]+', '={value}', pattern)
        return pattern
        
    def _classify_payload(self, payload: str) -> str:
        """Classify payload type"""
        payload_lower = payload.lower()
        if '<script' in payload_lower:
            return 'script'
        elif 'onerror' in payload_lower or 'onload' in payload_lower:
            return 'event_handler'
        elif 'javascript:' in payload_lower:
            return 'protocol'
        else:
            return 'other'
            
    def get_successful_payloads(self, context: Optional[str] = None) -> List[str]:
        """Get previously successful payloads, optionally filtered by context"""
        payloads = self.successful_payloads
        if context:
            payloads = [p for p in payloads if p.get('context') == context]
        return [p['payload'] for p in payloads[-20:]]  # Return last 20
        
    def suggest_payloads(self, url: str, param: str) -> List[str]:
        """Suggest payloads based on learned patterns"""
        suggestions = []
        pattern = self._extract_pattern(url)
        
        for vp in self.vulnerable_patterns:
            if vp['param_pattern'] == param:
                # Find matching payload
                for sp in self.successful_payloads:
                    if sp.get('parameter') == param and sp.get('payload') not in suggestions:
                        suggestions.append(sp['payload'])
                        
        return suggestions[:10]  # Return top 10 suggestions
        
    def _save_data(self):
        """Save learning data to file"""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'payloads': self.successful_payloads[-100:],  # Keep last 100
            'patterns': self.vulnerable_patterns[-100:],
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)