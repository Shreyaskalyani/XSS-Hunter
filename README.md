# XSS Detection System

An AI-powered multi-agent XSS vulnerability scanner for authorized security testing.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file with your Gemini API key:
```bash
echo "GEMINI_API_KEY=your_api_key_here" > .env
```

Or export directly:
```bash
export GEMINI_API_KEY=your_api_key_here
```

Get your free API key at: https://ai.google.dev/gemini-api

## Usage

### Standard Scan
```bash
python main.py -t http://target.com/search?q=
```

### AI-Powered Scanning
```bash
# Autonomous AI scan (self-guided)
python main.py -t http://target.com -ai autonomous

# Intelligent AI scan (adaptive payload generation)
python main.py -t http://target.com -ai intelligent
```

### Custom Payloads
```bash
python main.py -t http://target.com/search?q= -p custom_payloads.txt
```

### Options
- `-t, --target` - Target URL
- `-d, --depth` - Crawl depth (default: 2)
- `-n, --threads` - Concurrent threads (default: 10)
- `-p, --payloads` - Custom payloads file
- `-ai {autonomous,intelligent}` - Enable AI-powered scanning

## Architecture

```
main.py                    # Entry point
agents/
├── recon.py               # Reconnaissance Agent - URL/form discovery
├── payload.py             # Payload Agent - XSS payload generation
├── injector.py            # Injection Agent - payload injection
├── detector.py            # Detection Agent - vulnerability analysis
├── learner.py             # Learning Agent - tracks patterns
├── ai_agent.py            # AI Agent - Gemini-powered intelligent analysis
└── reporter.py            # Reporting Agent - generates reports
scanner/                   # Scanner utilities
utils/                     # Helper utilities
payloads/                  # XSS payload repository
```

## Output

- Console: Color-coded vulnerability results
- JSON: `reports/xss_report_<timestamp>.json`
- TXT: `reports/xss_report_<timestamp>.txt`

## ⚠️ Legal Notice

Use ONLY for:
- Authorized security testing
- Bug bounty programs
- Educational purposes

Unauthorized scanning is illegal.