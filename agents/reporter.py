"""Reporting Agent - Generates vulnerability reports"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from rich.console import Console
from rich.table import Table


console = Console()


class ReportingAgent:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_report(self, results: List[Dict], target: str):
        """Generate and display vulnerability report"""
        self._display_results(results)
        self._save_json(results, target)
        self._save_txt(results, target)
        
    def _display_results(self, results: List[Dict]):
        """Display results in console with colors"""
        if not results:
            console.print("\n[green]✓ No XSS vulnerabilities detected[/green]")
            return
            
        console.print(f"\n[red]⚠ Found {len(results)} potential XSS vulnerabilities:[/red]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", max_width=40)
        table.add_column("Parameter", style="yellow")
        table.add_column("Confidence", style="red")
        table.add_column("Context", style="green")
        
        for result in results:
            url = result.get('url', '')[:40] + '...' if len(result.get('url', '')) > 40 else result.get('url', '')
            table.add_row(
                url,
                result.get('parameter', ''),
                result.get('confidence', 'Low'),
                result.get('context', 'unknown')
            )
        
        console.print(table)
        if len(results) > 20:
            console.print(f"\n[dim]Showing {min(20, len(results))} of {len(results)} vulnerabilities[/dim]")
        
    def _save_json(self, results: List[Dict], target: str):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"xss_report_{timestamp}.json"
        
        report = {
            'scan_info': {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(results)
            },
            'vulnerabilities': results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        console.print(f"\n[blue]JSON report saved to: {filename}[/blue]")
        
    def _save_txt(self, results: List[Dict], target: str):
        """Save results to text file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"xss_report_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("XSS VULNERABILITY REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Total Vulnerabilities: {len(results)}\n\n")
            
            for i, result in enumerate(results, 1):
                f.write(f"--- Vulnerability #{i} ---\n")
                f.write(f"URL: {result.get('url', '')}\n")
                f.write(f"Parameter: {result.get('parameter', '')}\n")
                f.write(f"Method: {result.get('method', 'GET')}\n")
                f.write(f"Confidence: {result.get('confidence', 'Low')}\n")
                f.write(f"Context: {result.get('context', 'unknown')}\n")
                f.write(f"Payload: {result.get('payload', '')}\n")
                f.write(f"Evidence:\n{result.get('evidence', '')}\n\n")
                
        console.print(f"[blue]Text report saved to: {filename}[/blue]")