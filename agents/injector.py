"""Injection Agent - Injects payloads into discovered inputs"""

import httpx
from typing import Dict, Optional
from urllib.parse import urlencode
from utils.bypass import BypassEngine, get_bypass_headers, get_obfuscation_variants

class InjectionAgent:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.bypass = BypassEngine()
        
    async def inject(self, param_info: Dict, payload_info: Dict) -> Optional[httpx.Response]:
        """Inject payload into parameter"""
        url = param_info['url']
        param = param_info['param']
        method = param_info.get('method', 'GET')
        context = param_info.get('context', 'url')
        
        payload = payload_info['payload']
        
        try:
            if method == 'GET' or context == 'url':
                response = await self._inject_get(url, param, payload)
            elif method == 'POST' or context == 'form':
                response = await self._inject_post(url, param, payload, param_info)
            else:
                response = await self._inject_get(url, param, payload)
            
            return response
        except Exception:
            return None
            
    async def _inject_get(self, url: str, param: str, payload: str) -> httpx.Response:
        params = {param: payload}
        headers = get_bypass_headers()
        try:
            return await self.client.get(url, params=params, headers=headers)
        except Exception:
            response, _ = await self.bypass.bypass_request(
                self.client, 'GET', url, params=params, headers=headers
            )
            return response
        
    async def _inject_post(self, url: str, param: str, payload: str, param_info: Dict) -> httpx.Response:
        data = {param: payload}
        
        # Include other form fields with dummy values
        for form_input in param_info.get('inputs', []):
            if form_input['name'] != param and form_input['name'] not in data:
                input_type = form_input.get('type', 'text')
                if input_type == 'checkbox':
                    data[form_input['name']] = 'on'
                else:
                    data[form_input['name']] = 'test'
        
        headers = get_bypass_headers()
        try:
            return await self.client.post(url, data=data, headers=headers)
        except Exception:
            response, _ = await self.bypass.bypass_request(
                self.client, 'POST', url, data=data, headers=headers
            )
            return response