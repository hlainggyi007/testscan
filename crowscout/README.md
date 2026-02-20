# CrowScout

CrowScout is a Golang-based Bug Bounty automation CLI tool specifically designed to hunt for vulnerabilities intelligently, evade WAFs (Cloudflare/Akamai), and perform deep JavaScript analysis.

## Features
* **Smart Recon:** Uses `subfinder` and filters live hosts via `httpx`.
* **WAF Evasion:** Detects Cloudflare/WAF via `httpx` tech-detect. Skips aggressive `nmap` scans and throttles `nuclei` scanning to evade bans.
* **Targeted Scanning:** Runs specific `nuclei` tags (e.g., `wordpress`, `php`, `sqli`, `xss`) based on the detected technology stack.
* **Hidden Parameters:** Uses `arjun` to find hidden GET/POST parameters on live endpoints.
* **JavaScript Analysis:** Extracts `.js` links using `subjs` and scans them with `nuclei` for exposed secrets, tokens, and API keys.

## Prerequisites (Kali Linux / Ubuntu)
You must have the following tools installed and available in your system `$PATH`:
* `go` (Current Go version)
* `subfinder`
* `httpx`
* `nmap`
* `nuclei`
* `subjs`
* `arjun`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/crowscout.git
   cd crowscout
   ```
2. Build the binary:
   ```bash
   go build -o crowscout ./cmd/crowscout
   chmod +x crowscout
   ```

## Usage
```bash
./crowscout -t example.com
```

To just run directly without building:
```bash
go run ./cmd/crowscout -t example.com
```

### Options
* `-t <domain>` : Specify the target domain (Required).
* `-no-subs`    : Skip the subdomain discovery phase and only test the exact target provided.
* `-c <path>`   : Path to custom config file (Default: `config/config.json`).

## Configuration
Tweak the critical ports and severity output inside `config/config.json`.
