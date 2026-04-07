# BBScanning_Toolkit
Open Source tool scan bug bounty for wildcard in Kali Linux / Ubuntu
Supports fully automated scanning with an intuitive Web UI and a powerful Command-Line Interface (CLI).

---

## Key Features

- **Fully Automated Recon**: Subdomain enumeration, live host detection, and URL extraction.
- **Vulnerability Scanning**: Deep integration with specialized tools like Nuclei, Dalfox (XSS), SQLMap (SQLi), and GF patterns (SSRF, CORS, IDOR, etc.).
- **Web UI Dashboard**: Multi-user support, task queueing system, visual configuration, and live report monitoring.

  <img width="1907" height="793" alt="image" src="https://github.com/user-attachments/assets/69adb2e7-7b34-4046-84bd-bc01914da7d2" />
  <img width="1907" height="821" alt="image" src="https://github.com/user-attachments/assets/d871569d-f654-4a73-879f-5f5f2b61489d" />


- **High Performance**: Multi-threaded, with fully configurable rate limits and timeouts.
- **Telegram Alerts**: Optional notifications pushed directly to your Telegram bot upon scan completion.

---

## Installation

### Method 1: Automated setup (Recommended)
The installer script will automatically download and install all necessary dependencies (Go, Python packages, Subfinder, Httpx, Nuclei, Katana, Dalfox, SQLMap, etc.).

```bash
chmod +x install.sh
./install.sh
```
> **Note**: After installation, run `source ~/.zshrc` (or `~/.bashrc`) to update your PATH if the tools are not recognized immediately.

### Method 2: Manual setup
```bash
# 1. Install Python dependencies
pip3 install -r requirements.txt

# 2. Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest

# 3. Install other tools
pip3 install dirsearch sqlmap

# 4. Update Nuclei templates
nuclei -update-templates
```

---

## Usage

### 🌐 Using the Web UI
The Web UI provides an easy way to configure, queue, and monitor scans without memorizing CLI syntax.

```bash
# Start the production environment (Recommended)
bash start.sh
```
<img width="1920" height="821" alt="image" src="https://github.com/user-attachments/assets/781485e3-0acf-48d9-b190-70cc235c2d89" />


> **Security Notes:**
> - For safety, the Web UI listens locally on `127.0.0.1` by default. To expose it over the network/internet (e.g. on a VPS), run `HOST=0.0.0.0 bash start.sh`.
> - On the very first run, the system will **auto-generate a secure random password** for the `admin` account and print it to your terminal exactly once.

Or run directly for development/testing:
```bash
python3 app.py
```
> Open your browser and navigate to: `http://127.0.0.1:5000`

### Using the CLI

**Basic Syntax:**
```bash
python3 scanner.py example.com
```

**Common Options:**
```bash
# Scan multiple domains from a text file
python3 scanner.py -l domains.txt

# Run with a custom configuration file
python3 scanner.py example.com --config config.yaml

# High-performance mode (higher threads and rate-limit)
python3 scanner.py example.com --threads 50 --rate-limit 150

# Send Telegram alerts upon completion
python3 scanner.py example.com --telegram-token "YOUR_BOT_TOKEN" --telegram-chat-id "YOUR_CHAT_ID"

# Resume an interrupted or paused scan
python3 scanner.py example.com --resume
```

---

## Scanning Phases

The execution flow is divided into optimized phases:

| Phase | Description | Tools |
|-------|-------------|-------|
| 1 | Input Handling | argparse, built-in |
| 2 | Subdomain Enumeration | subfinder, assetfinder |
| 3 | Live Host Detection | httpx |
| 4 | URL Collection | waybackurls, gau, katana |
| 5 | Directory Discovery | dirsearch |
| 6 | URL Filtering | built-in (static extension filtering) |
| 7 | Parameter Extraction | built-in |
| 8 | Verify Alive Params | httpx |
| 9 | Filter Vulnerable Patterns | gf (sqli, ssrf, idor, cors...) |
| 10 | Vulnerability Scanning | nuclei, dalfox, sqlmap |
| 11 | Report Generation | built-in (JSON, CSV, HTML) |

---

## Output Structure

Upon completion, all results are stored under `output/<domain>/`:
```
output/
└── example.com/
    ├── subdomains.txt          # All discovered subdomains
    ├── alive_subdomains.txt    # Subdomains returning HTTP 200/responsive
    ├── all_urls.txt            # All crawled / gathered URLs
    ├── filtered_urls.txt       # URLs without standard static files
    ├── params.txt              # Extracted URLs containing parameters
    ├── alive_params.txt        # Verified parameter URLs that are live
    ├── findings.json           # Potential vulnerabilities (JSON format)
    ├── findings.txt            # Potential vulnerabilities (Raw text)
    ├── findings.csv            # Potential vulnerabilities (CSV format)
    ├── scan_report.json        # Unified comprehensive summary report
    └── .scan_state.json        # Snapshot state file for scan resuming
```

---

## Legal Disclaimer

This framework is created solely for **educational purposes** and **authorized security research** (Bug Bounty, authorized Penetration Testing). The author accepts **NO LIABILITY** and is not responsible for any misuse or damage caused by this program. Only test targets you have explicitly been granted permission to attack. Please refer to individual Bug Bounty program scopes and policies before initiating any scans! goodluck heheheheehehe
