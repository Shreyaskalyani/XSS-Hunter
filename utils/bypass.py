"""Firewall/WAF Bypass utilities"""

import random
import base64
from typing import Dict, List, Optional
from urllib.parse import quote

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; CrOS x86_64 12206.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
]

HEADERS_LIST = [
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-CH-UA": '"Chromium";v="120"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": "Windows",
    },
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "TE": "Trailers",
    },
]

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_bypass_headers() -> Dict:
    headers = random.choice(HEADERS_LIST).copy()
    headers["User-Agent"] = get_random_user_agent()
    headers["Referer"] = "https://www.google.com/"
    return headers

def encode_payload_url(payload: str) -> str:
    return quote(payload, safe="")

def encode_payload_double_url(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")

def encode_payload_html(payload: str) -> str:
    return payload.replace("<", "&#60;").replace(">", "&#62;").replace('"', "&#34;")

def obfuscate_payload(payload: str, technique: str = "random") -> str:
    if technique == "html":
        return encode_payload_html(payload)
    elif technique == "double_url":
        return encode_payload_double_url(payload)
    elif technique == "base64":
        return f"&#123;base64&#125;{base64.b64encode(payload.encode()).decode()}&#123;/base64&#125;"
    return payload

def get_obfuscation_variants(payload: str) -> List[str]:
    variants = [payload]
    variants.append(encode_payload_html(payload))
    variants.append(encode_payload_double_url(payload))
    variants.append(payload.replace("<", "%3C").replace(">", "%3E"))
    variants.append(payload.replace("<", "%00%3C").replace(">", "%00%3E"))
    variants.append(payload.replace("script", "scr<script>ipt"))
    variants.append(f"<img src=x onerror={payload.replace('alert(', '').replace(')', '')}>")
    return variants

class BypassEngine:
    def __init__(self):
        self.max_retries = 3
        self.blocked_indicators = [
            "access denied",
            "you don't have permission",
            "reference #",
            "errors.edgesuite.net",
            "akamai",
            "blocked by waf",
            "cloudflare",
            "security check",
            "captcha",
            "checking your browser",
            "please enable cookies",
            "enable javascript",
        ]
    
    def is_blocked(self, response) -> bool:
        if response is None:
            return False
        text = response.text.lower() if hasattr(response, "text") else ""
        status = response.status_code if hasattr(response, "status_code") else 200
        for indicator in self.blocked_indicators:
            if indicator in text:
                return True
        return status == 403 or status == 429 or status == 406
    
    def is_json_response(self, response) -> bool:
        """Check if response is JSON (API endpoint)"""
        if hasattr(response, "headers"):
            content_type = response.headers.get("content-type", "")
            return "application/json" in content_type
        return False
    
    async def bypass_request(self, client, method: str, url: str, **kwargs):
        for attempt in range(self.max_retries):
            headers = get_bypass_headers()
            if "headers" in kwargs:
                headers.update(kwargs["headers"])
            kwargs["headers"] = headers
            
            if method.upper() == "GET":
                response = await client.get(url, **kwargs)
            else:
                response = await client.post(url, **kwargs)
            
            if not self.is_blocked(response):
                return response, True
            
            await self._random_delay(attempt)
        
        return response, False
    
    async def _random_delay(self, attempt: int):
        import asyncio
        await asyncio.sleep(random.uniform(0.5 * attempt, 1.0 * attempt))