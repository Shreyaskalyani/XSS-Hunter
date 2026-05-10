#!/usr/bin/env python3
"""
XSS Detection System - Main Entry Point
A multi-agent XSS vulnerability scanner
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional, List

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agents.recon import ReconnaissanceAgent
from agents.payload import PayloadAgent
from agents.injector import InjectionAgent
from agents.detector import DetectionAgent
from agents.learner import LearningAgent
from agents.reporter import ReportingAgent
from agents.ai_agent import AIAgent


console = Console()


class XSSScanner:
    def __init__(self, target: str, depth: int = 2, threads: int = 10, custom_payloads: Optional[List[str]] = None):
        self.target = target.rstrip('/')
        self.depth = depth
        self.threads = threads
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        # Initialize payload agent with custom payloads if provided
        self.agents = {
            'recon': ReconnaissanceAgent(self.client),
            'payload': PayloadAgent(custom_payloads),
            'injector': InjectionAgent(self.client),
            'detector': DetectionAgent(),
            'learner': LearningAgent(),
            'reporter': ReportingAgent()
        }
        
        self.results = []
        self.attack_surface = {}
        
    async def run(self):
        console.print(Panel.fit(
            f"[bold cyan]XSS Detection System[/bold cyan]\n"
            f"Target: {self.target}\n"
            f"Depth: {self.depth}\n"
            f"Threads: {self.threads}",
            title="Scanner Started"
        ))
        
        # Phase 1: Reconnaissance
        console.print("\n[yellow]Phase 1: Reconnaissance...[/yellow]")
        self.attack_surface = await self.agents['recon'].crawl(
            self.target, self.depth
        )
        
        if not self.attack_surface['urls']:
            console.print("[red]No URLs discovered. Exiting.[/red]")
            return
            
        console.print(f"  Discovered {len(self.attack_surface['urls'])} URLs")
        console.print(f"  Found {len(self.attack_surface['forms'])} forms")
        console.print(f"  Found {len(self.attack_surface['params'])} parameters")
        
        if not self.attack_surface['params']:
            console.print("\n[yellow]No parameters found. Crawling deeper...[/yellow]")
            deeper_attack_surface = await self.agents['recon'].crawl(
                self.target, min(self.depth + 1, 3)
            )
            self.attack_surface['urls'] = list(set(self.attack_surface['urls']))
            self.attack_surface['params'] = deeper_attack_surface['params']
            self.attack_surface['forms'] = deeper_attack_surface['forms']
            console.print(f"  Now found {len(self.attack_surface['params'])} parameters")
        
        if self.attack_surface['urls']:
            console.print("\n  [cyan]URLs discovered:[/cyan]")
            table = Table(show_header=True, header_style="bold cyan", box=None)
            table.add_column("#", style="yellow")
            table.add_column("URL", style="magenta")
            
            for i, url in enumerate(self.attack_surface['urls'][:8], 1):
                table.add_row(str(i), url)
            console.print(table)
        
        if self.attack_surface['forms']:
            console.print("\n  [cyan]Forms discovered:[/cyan]")
            table = Table(show_header=True, header_style="bold cyan", box=None)
            table.add_column("Action", style="yellow")
            table.add_column("Method", style="green")
            table.add_column("Inputs", style="blue")
            
            for form in self.attack_surface['forms']:
                inputs = ', '.join([i.get('name', '') for i in form.get('inputs', [])[:3]])
                if len(form.get('inputs', [])) > 3:
                    inputs += f" (+{len(form.get('inputs', [])) - 3})"
                table.add_row(form.get('action', ''), form.get('method', 'GET'), inputs)
            console.print(table)
        
        if self.attack_surface['params']:
            console.print("\n  [cyan]Parameters discovered:[/cyan]")
            table = Table(show_header=True, header_style="bold cyan", box=None)
            table.add_column("Param", style="yellow")
            table.add_column("Method", style="green")
            table.add_column("Context", style="blue")
            table.add_column("URL", style="magenta")
            
            for param in self.attack_surface['params'][:15]:
                table.add_row(
                    param.get('param', ''),
                    param.get('method', 'GET'),
                    param.get('context', 'url'),
                    param.get('url', '')
                )
            console.print(table)
            
            if len(self.attack_surface['params']) > 15:
                console.print(f"\n  ... and {len(self.attack_surface['params']) - 15} more parameters")
        
        # Phase 2: Payload Generation
        console.print("\n[yellow]Phase 2: Generating payloads...[/yellow]")
        payloads = self.agents['payload'].generate_payloads()
        console.print(f"  Generated {len(payloads)} payloads")
        
        # Phase 3: Injection & Detection
        console.print("\n[yellow]Phase 3: Scanning for XSS...[/yellow]")
        semaphore = asyncio.Semaphore(self.threads)
        
        tasks = []
        for param_info in self.attack_surface['params']:
            for payload in payloads:
                task = self._scan_with_semaphore(param_info, payload, semaphore)
                tasks.append(task)
                
        self.results = await asyncio.gather(*tasks)
        self.results = [r for r in self.results if r]  # Filter None results
        
        # Phase 4: Learning
        console.print("\n[yellow]Phase 4: Learning from results...[/yellow]")
        for result in self.results:
            self.agents['learner'].record_success(result)
            
        # Phase 5: Reporting
        console.print("\n[yellow]Phase 5: Generating report...[/yellow]")
        self.agents['reporter'].generate_report(self.results, self.target)
        
        console.print(f"\n[green]Scan complete! Found {len(self.results)} potential vulnerabilities.[/green]")
        
    async def _scan_with_semaphore(self, param_info, payload, semaphore):
        async with semaphore:
            try:
                response = await self.agents['injector'].inject(
                    param_info, payload
                )
                
                if response:
                    detection = self.agents['detector'].analyze(
                        response, payload, param_info
                    )
                    if detection and detection.get('vulnerable'):
                        self.agents['learner'].record_success(detection)
                        return detection
            except Exception as e:
                console.print(f"[dim]Error: {e}[/dim]")
            return None
            
    async def close(self):
        await self.client.aclose()


async def main():
    parser = argparse.ArgumentParser(description='XSS Detection System', 
        epilog='Example: python3 main.py -t http://target.com/search?q= -p payloads.txt')
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('-n', '--threads', type=int, default=10, help='Concurrent threads')
    parser.add_argument('-p', '--payloads', help='Custom payloads (space-separated or file path)')
    parser.add_argument('-ai', '--ai', nargs='?', const='autonomous', default=False, 
                        choices=['autonomous', 'intelligent'], 
                        help='Use AI-powered scanning (autonomous or intelligent)')
    
    args = parser.parse_args()
    
    console.print("\n[bold red]⚠️  WARNING: Use only for authorized security testing![/bold red]\n")
    
    # AI Mode
    if args.ai:
        ai_agent = AIAgent()
        target = args.target or "https://example.com"
        scan_mode = args.ai
        try:
            console.print(Panel.fit(
                f"[bold cyan]AI-Powered XSS Detection[/bold cyan]\n"
                f"Target: {target}\n"
                f"Mode: {scan_mode.title()} AI Scan",
                title="AI Scanner Started"
            ))
            
            if scan_mode == 'intelligent':
                results = await ai_agent.intelligent_scan(target)
            else:
                results = await ai_agent.autonomous_scan(target)
            
            if 'security_analysis' in results:
                sa = results['security_analysis']
                if sa.get('waf_detected'):
                    console.print(f"\n[yellow]WAF Detected:[/yellow] {', '.join(sa['waf_detected'])}")
                elif results.get('error') and 'WAF' in results.get('error', ''):
                    console.print(f"\n[yellow]WAF Detected:[/yellow] Yes")
                if sa.get('input_points', 0) > 0:
                    console.print(f"[cyan]Input points found:[/cyan] {sa['input_points']}")
                else:
                    console.print("[yellow]Note: WAF may be blocking requests[/yellow]")
            
            ai_agent.agents['reporter'].generate_report(results.get('vulnerabilities', []), target)
            console.print(f"\n[green]AI Scan complete![/green]")
            if not ai_agent.api_key:
                console.print("[dim]Set GEMINI_API_KEY for full AI-powered analysis[/dim]")
        finally:
            await ai_agent.close()
        return
    
    # Handle target
    target = args.target
    if not target:
        target = "https://example.com"
    
    # Handle payloads - can be file path or inline
    custom_payloads = []
    if args.payloads:
        payload_input = args.payloads
        # Check if it's a file
        if Path(payload_input).exists() and Path(payload_input).suffix == '.txt':
            with open(payload_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom_payloads.append(line)
            console.print(f"[dim]Loaded {len(custom_payloads)} payloads from {payload_input}[/dim]")
        else:
            custom_payloads = payload_input.split('\n') if '\n' in payload_input else [payload_input]
    
    scanner = XSSScanner(target, args.depth, args.threads, custom_payloads)
    try:
        await scanner.run()
    finally:
        await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())