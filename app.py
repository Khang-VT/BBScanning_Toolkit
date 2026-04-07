#!/usr/bin/env python3
"""
BugBounty AutoScanner — Production Web Server
Multi-user, authenticated, rate-limited, security-hardened.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, stream_with_context, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner as sc

# ═══════════════════════════════════════════════════════════════════════════
#  APP SETUP
# ═══════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

# ── Persistent SECRET_KEY (survives restarts) ────────────────────────────
_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
def _load_or_create_secret_key():
    env_key = os.environ.get("SECRET_KEY", "")
    if env_key:
        return env_key
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE) as f:
            k = f.read().strip()
            if k: return k
    k = os.urandom(32).hex()
    try:
        with open(_KEY_FILE, "w") as f:
            f.write(k)
        os.chmod(_KEY_FILE, 0o600)  # owner-read only
    except Exception:
        pass
    return k

app.config["SECRET_KEY"]              = _load_or_create_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

# Global state
SCANS: dict[str, "ScanSession"] = {}
SCANS_LOCK = threading.Lock()
SCANS_TTL_HOURS = int(os.environ.get("SCANS_TTL_HOURS", 24))  # purge old sessions after N hours

# ── Limits ──────────────────────────────────────────────────────────────
MAX_GLOBAL_SCANS   = int(os.environ.get("MAX_GLOBAL_SCANS", 10))
MAX_USER_SCANS     = int(os.environ.get("MAX_USER_SCANS", 3))
RATE_LIMIT_WINDOW  = 60    # seconds
RATE_LIMIT_MAX     = int(os.environ.get("RATE_LIMIT_MAX", 5))  # scans per window per user

# ── In-memory rate limit tracker: {username: [(timestamp), ...]} ─────────
_rate_tracker: dict[str, list[float]] = {}
_rate_lock = threading.Lock()

# ═══════════════════════════════════════════════════════════════════════════
#  USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

USERS_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
TELEGRAM_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telegram_config.json")


def load_users() -> dict:
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_users(users: dict) -> None:
    """Atomic write: write to temp file then rename to avoid corruption."""
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_FILE)  # atomic on POSIX and Windows Vista+


def load_telegram_config() -> dict:
    try:
        with open(TELEGRAM_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "bot_token": "", "chat_id": ""}


def save_telegram_config(cfg: dict) -> None:
    tmp = TELEGRAM_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, TELEGRAM_FILE)


def get_user(username: str) -> Optional[dict]:
    return load_users().get(username)


def create_user(username: str, password: str, role: str = "user") -> bool:
    users = load_users()
    if username in users:
        return False
    users[username] = {
        "password":   generate_password_hash(password),
        "role":       role,
        "created_at": datetime.utcnow().isoformat(),
        "active":     True,
    }
    save_users(users)
    return True


def _cleanup_old_scans():
    """Periodically remove finished scan sessions older than SCANS_TTL_HOURS."""
    import time as _time
    while True:
        _time.sleep(3600)  # run every hour
        cutoff = datetime.utcnow() - timedelta(hours=SCANS_TTL_HOURS)
        to_del = []
        with SCANS_LOCK:
            for sid, sess in SCANS.items():
                if sess.status in ("done", "error", "interrupted"):
                    try:
                        ft = sess.finished_at  # float timestamp
                        if ft and datetime.utcfromtimestamp(ft) < cutoff:
                            to_del.append(sid)
                    except Exception:
                        pass
            for sid in to_del:
                del SCANS[sid]
        if to_del:
            logging.getLogger("scanner").info(f"Cleaned up {len(to_del)} expired scan session(s)")


def _start_cleanup_thread():
    t = threading.Thread(target=_cleanup_old_scans, daemon=True, name="scan-cleanup")
    t.start()


def _ensure_default_admin():
    """Create default admin on first run if no users exist."""
    users = load_users()
    if not users:
        default_pass = os.environ.get("ADMIN_PASSWORD", "")
        if not default_pass:
            import secrets as _sec
            default_pass = _sec.token_urlsafe(12)  # auto-generate strong password
        create_user("admin", default_pass, "admin")
        print("\n" + "="*60)
        print(f"\033[92m[+] Default admin account created\033[0m")
        print(f"    username : admin")
        print(f"    password : \033[93m{default_pass}\033[0m")
        print(f"\033[91m[!] CHANGE THIS PASSWORD IMMEDIATELY after first login!\033[0m")
        print("="*60 + "\n")


# ═══════════════════════════════════════════════════════════════════════════
#  AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        user = get_user(session["username"])
        if not user or not user.get("active", True):
            session.clear()
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        user = get_user(session["username"])
        if not user or user.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════════════════
#  RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════

def check_rate_limit(username: str) -> bool:
    """Return True if allowed, False if rate-limited."""
    now = time.time()
    with _rate_lock:
        times = _rate_tracker.get(username, [])
        times = [t for t in times if now - t < RATE_LIMIT_WINDOW]
        if len(times) >= RATE_LIMIT_MAX:
            _rate_tracker[username] = times
            return False
        times.append(now)
        _rate_tracker[username] = times
        return True


# ═══════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_domain(domain: str) -> tuple[bool, str]:
    """Validate and sanitize domain input. Returns (ok, cleaned_domain)."""
    import ipaddress as _ipa
    if not domain:
        return False, "Domain is required"
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    if len(domain) > 253:
        return False, "Domain too long"

    # Block raw IP addresses pointing to private/reserved ranges
    try:
        ip = _ipa.ip_address(domain)
        if (ip.is_loopback or ip.is_private or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, "Private/reserved IP addresses are not allowed"
        # Allow public IPs to be scanned
        return True, domain
    except ValueError:
        pass  # not an IP, continue with domain validation

    if not DOMAIN_RE.match(domain):
        return False, f"Invalid domain format: {domain}"

    # Block private/internal hostnames (SSRF protection)
    _BLOCKED_PATTERNS = [
        "localhost", "local", ".internal", ".corp", ".intranet",
        ".lan", ".home", ".arpa",
        "metadata.google", "169.254",       # GCP/AWS metadata
        "instance-data", "metadata.aws",
        "kubernetes", "kube-apiserver",
        "docker", ".docker",
    ]
    if any(p in domain for p in _BLOCKED_PATTERNS):
        return False, "Domain not allowed (internal/reserved)"

    # Block single-label hostnames (e.g. "admin", "db", "redis")
    if "." not in domain:
        return False, "Domain must have at least one dot (FQDN required)"

    return True, domain


# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    if not response.content_type.startswith("text/event-stream"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ═══════════════════════════════════════════════════════════════════════════
#  SCAN SESSION
# ═══════════════════════════════════════════════════════════════════════════

PHASES = [
    (1, "Initializing",    "fa-list-check"),
    (2, "Recon",           "fa-sitemap"),
    (3, "Collection",      "fa-link"),
    (4, "Analysis",        "fa-filter"),
    (5, "Vuln Scan",       "fa-shield-halved"),
    (6, "Report",          "fa-file-lines"),
]

# Internal sub-phase → display phase mapping (for progress reporting)
_SUB_TO_MAIN_PHASE = {
    1: 1,   # Input / Initializing
    2: 2,   # Subdomain Enumeration
    3: 2,   # Live Hosts
    4: 3,   # URL Collection
    5: 3,   # Deep Discovery
    6: 3,   # JS Analysis
    7: 4,   # Normalization
    8: 4,   # Endpoint Analysis
    9: 4,   # Validation
    10: 5,  # Injection Tests
    11: 5,  # Access & Config
    12: 5,  # Infrastructure
    13: 5,  # Vuln Engine
    14: 6,  # Report
}

# ── Friendly name mappings (hide internal tool names) ────────────────────
_TOOL_ALIAS = {
    "subfinder":      "Domain Enumerator",
    "assetfinder":    "Asset Discovery",
    "httpx":          "Host Prober",
    "httpx-toolkit":  "Host Prober",
    "waybackurls":    "Archive Crawler",
    "gau":            "URL Gatherer",
    "katana":         "Web Crawler",
    "dirsearch":      "Directory Scanner",
    "nuclei":         "Vulnerability Engine",
    "dalfox":         "XSS Scanner",
    "sqlmap":         "Injection Tester",
    "gf":             "Pattern Classifier",
    "go":             "Runtime",
}

# Patterns that expose internal system info — skip from public log
_SKIP_PATTERNS = re.compile(
    r"(^Running:\s|go/bin/|/usr/bin/|/usr/local/|/root/|"
    r"--[a-zA-Z\-]+=?|\.txt\b.*-[a-z]|\bUsing:\s+httpx|"
    r"httpx-toolkit|Binary not|executable:|\bpython3\s+-m\b)",
    re.IGNORECASE,
)

# Patterns to rewrite (replacement keeps context, strips tool name)
_REWRITE_RULES: list[tuple[re.Pattern, str]] = [
    # "Running subfinder on domain" → "Enumerating subdomains for domain"
    (re.compile(r"Running subfinder on (.+)", re.I),    r"Enumerating subdomains for \1"),
    (re.compile(r"Running assetfinder on (.+)", re.I),  r"Discovering assets for \1"),
    (re.compile(r"subfinder found (\d+) subdomains", re.I), r"Found \1 candidate subdomains"),
    (re.compile(r"\[PHASE 3b\] Port scan with nmap", re.I), r"[PHASE 3b] Port discovery"),
    (re.compile(r"Scanning (\d+) hosts for ports:", re.I), r"Scanning \1 hosts for open ports"),
    (re.compile(r"Open ports: (\d+) across (\d+) hosts", re.I), r"Open ports: \1 across \2 hosts"),
    (re.compile(r"assetfinder found (\d+) subdomains", re.I), r"Asset discovery: \1 entries"),
    # httpx
    (re.compile(r"Live host detection with httpx", re.I),        r"Mapping live attack surface"),
    (re.compile(r"Probing (\d+) hosts\.\.\.", re.I),             r"Probing \1 hosts..."),
    (re.compile(r"Alive hosts: (\d+)", re.I),                    r"Active hosts confirmed: \1"),
    (re.compile(r"Using: httpx.*", re.I),                        r"Host probe engine ready"),
    (re.compile(r"No alive hosts detected.*", re.I),             r"No active hosts found — expanding scope"),
    (re.compile(r"Fallback hosts added: (\d+)", re.I),           r"Scope expanded with \1 seed targets"),
    # URL tools
    (re.compile(r"Running waybackurls for (.+)", re.I),   r"Querying archive data for \1"),
    (re.compile(r"Running gau for (.+)", re.I),           r"Collecting URL intelligence for \1"),
    (re.compile(r"Running katana on (\d+) hosts", re.I),  r"Crawling \1 hosts"),
    (re.compile(r"waybackurls: (\d+) URLs", re.I),        r"Archive URLs retrieved: \1"),
    (re.compile(r"gau: (\d+) URLs", re.I),                r"Intelligence URLs retrieved: \1"),
    (re.compile(r"katana: (\d+) URLs", re.I),             r"Crawled URLs: \1"),
    (re.compile(r"waybackurls not found.*", re.I),        r"Archive crawler unavailable — skipping"),
    (re.compile(r"gau not found.*", re.I),                r"URL intelligence module unavailable — skipping"),
    (re.compile(r"katana not found.*", re.I),             r"Web crawler unavailable — skipping"),
    # dirsearch
    (re.compile(r"Directory discovery with dirsearch", re.I),   r"Deep directory discovery in progress"),
    (re.compile(r"dirsearch not found.*", re.I),                r"Directory scanner unavailable — skipping"),
    (re.compile(r"dirsearch → (.+)", re.I),                     r"Scanning directories on \1"),
    (re.compile(r"dirsearch found: (\d+) paths", re.I),         r"New paths discovered: \1"),
    (re.compile(r"Tool not found: dirsearch", re.I),            r"Directory scanner not available"),
    # nuclei
    (re.compile(r"Running Nuclei vulnerability scan", re.I),            r"Launching vulnerability scan engine"),
    (re.compile(r"Starting nuclei \((.+)\)", re.I),                     r"Scan engine started (\1)"),
    (re.compile(r"Nuclei scan complete!", re.I),                        r"Vulnerability scan completed"),
    (re.compile(r"Vulnerability engine scan complete!", re.I),          r"Vulnerability scan completed"),
    (re.compile(r"Vulnerability engine running.*", re.I),               r"Vulnerability engine running…"),
    (re.compile(r"Updating vulnerability templates.*", re.I),           r"Updating vulnerability database…"),
    (re.compile(r"Scanning (\d+) target\(s\).*", re.I),                r"Scanning \1 target(s)"),
    (re.compile(r"No params found.*scanning (\d+) alive hosts directly", re.I),
                                                                         r"Scanning \1 confirmed hosts directly"),
    (re.compile(r"Scanning (\d+) param URLs", re.I),                   r"Analyzing \1 parameterized endpoints"),
    (re.compile(r"nuclei_targets\.txt", re.I),                          r"scan targets"),
    (re.compile(r"alive_params\.txt", re.I),                            r"verified endpoints"),
    # paths/files — strip directory info
    (re.compile(r"output/[^/]+/[^/]+/(\w+\.txt)", re.I),        r"\1"),
    (re.compile(r"/root/go/bin/\w+", re.I),                      r"[engine]"),
    (re.compile(r"/usr/bin/\w+", re.I),                          r"[engine]"),
    # new modules
    (re.compile(r"Analyzing JavaScript files for secrets", re.I),     r"Scanning JavaScript files for leaked secrets"),
    (re.compile(r"Analyzing (\d+) JS files.*", re.I),                r"Analyzing \1 JavaScript files"),
    (re.compile(r"Secrets found: (\d+)", re.I),                      r"Exposed secrets found: \1"),
    (re.compile(r"JS files found: (\d+)", re.I),                     r"JavaScript files collected: \1"),
    (re.compile(r"Classifying endpoints by vulnerability type", re.I),r"Classifying attack surface by risk category"),
    (re.compile(r"XSS\s+candidates: (\d+)", re.I),                   r"XSS risk endpoints: \1"),
    (re.compile(r"SQLI\s+candidates: (\d+)", re.I),                  r"Injection risk endpoints: \1"),
    (re.compile(r"SSRF\s+candidates: (\d+)", re.I),                  r"SSRF risk endpoints: \1"),
    (re.compile(r"IDOR\s+candidates: (\d+)", re.I),                  r"IDOR risk endpoints: \1"),
    (re.compile(r"Scanning (\d+) XSS candidates with dalfox", re.I), r"Testing \1 endpoints for XSS vulnerabilities"),
    (re.compile(r"XSS findings: (\d+)", re.I),                       r"XSS vulnerabilities confirmed: \1"),
    (re.compile(r"dalfox not found.*", re.I),                         r"XSS scanner unavailable — skipping"),
    (re.compile(r"Testing (\d+) SQLi candidates.*", re.I),           r"Testing \1 endpoints for SQL injection"),
    (re.compile(r"SQLi findings: (\d+)", re.I),                      r"SQL injection findings: \1"),
    (re.compile(r"sqlmap not found.*", re.I),                         r"Injection tester unavailable — skipping"),
    (re.compile(r"Testing (\d+) IDOR candidates", re.I),             r"Testing \1 endpoints for access control issues"),
    (re.compile(r"IDOR candidates: (\d+)", re.I),                    r"Access control issues found: \1"),
    (re.compile(r"Potential IDOR: .+param: (.+)\)", re.I),           r"Potential access control bypass detected (param: \1)"),
    (re.compile(r"HTML report:.*", re.I),                             r"Security report generated"),
    (re.compile(r"Full vulnerability scanning", re.I),               r"Running comprehensive vulnerability analysis"),
    # generic tool names
    (re.compile(r"\bhttpx\b", re.I),                             r"host prober"),
    (re.compile(r"\bnuclei\b", re.I),                            r"vuln engine"),
    (re.compile(r"\bsubfinder\b", re.I),                         r"domain enumerator"),
    (re.compile(r"\bkatan[a]\b", re.I),                          r"web crawler"),
    (re.compile(r"\bwaybackurls\b", re.I),                       r"archive crawler"),
    (re.compile(r"\bgau\b", re.I),                               r"url gatherer"),
    (re.compile(r"\bdalfox\b", re.I),                            r"xss scanner"),
    (re.compile(r"\bsqlmap\b", re.I),                            r"injection tester"),
    # New module messages
    (re.compile(r"\[CORS\] Scanning for CORS misconfigurations", re.I), r"Checking for cross-origin policy issues"),
    (re.compile(r"CORS findings: (\d+)", re.I),                  r"Cross-origin issues found: \1"),
    (re.compile(r"\[403\] Testing 403/401 bypass techniques", re.I), r"Testing access control bypass techniques"),
    (re.compile(r"403 Bypass findings: (\d+)", re.I),             r"Access bypass findings: \1"),
    (re.compile(r"\[SSTI\] Testing for Server-Side Template Injection", re.I), r"Testing for server-side code injection"),
    (re.compile(r"SSTI findings: (\d+)", re.I),                   r"Code injection findings: \1"),
    (re.compile(r"\[HostHdr\] Testing Host Header Injection", re.I), r"Testing host-based attack vectors"),
    (re.compile(r"Host header injection: (\d+)", re.I),           r"Host-based attack vectors: \1"),
    (re.compile(r"\[SSRF\] Testing for Server-Side Request Forgery", re.I), r"Testing for server-side request vulnerabilities"),
    (re.compile(r"SSRF findings: (\d+)", re.I),                   r"Server-side request vulnerabilities: \1"),
    (re.compile(r"Testing (\d+) SSRF candidate URLs", re.I),      r"Probing \1 request-forgery candidates"),
    (re.compile(r"\[Redirect\] Testing for Open Redirect", re.I), r"Testing redirect controls"),
    (re.compile(r"Open Redirect findings: (\d+)", re.I),          r"Redirect vulnerabilities: \1"),
    (re.compile(r"\[Takeover\] Checking subdomain takeover", re.I), r"Checking for unclaimed service vulnerabilities"),
    (re.compile(r"Takeover findings: (\d+)", re.I),               r"Unclaimed service findings: \1"),
    (re.compile(r"Checking (\d+) domains for takeover", re.I),    r"Auditing \1 domains for unclaimed services"),
    (re.compile(r"\[GraphQL\] Discovering and testing GraphQL", re.I), r"Discovering API endpoints and testing exposure"),
    (re.compile(r"GraphQL findings: (\d+)", re.I),                r"API endpoint findings: \1"),
    (re.compile(r"\[JWT\] Analyzing JWT tokens", re.I),           r"Analyzing authentication tokens"),
    (re.compile(r"JWT findings: (\d+)", re.I),                    r"Authentication token issues: \1"),
    (re.compile(r"\[A\] Injection & Execution tests", re.I),      r"Phase A: Testing injection & execution vectors"),
    (re.compile(r"\[B\] Access control & configuration", re.I),   r"Phase B: Testing access controls & config"),
    (re.compile(r"\[C\] Infrastructure & technology", re.I),      r"Phase C: Infrastructure security checks"),
    (re.compile(r"\[D\] Logic & access control", re.I),           r"Phase D: Logic & privilege checks"),
    (re.compile(r"Scan complete — Critical:(\d+) High:(\d+) Medium:(\d+)", re.I),
     r"Analysis complete — Critical:\1 | High:\2 | Medium:\3"),
]


def _sanitize_log(msg: str) -> tuple[str, bool]:
    """
    Sanitize a log message for public display.
    Returns (sanitized_msg, should_skip).
    """
    # Skip raw command lines and internal paths
    if _SKIP_PATTERNS.search(msg):
        return msg, True

    # Apply rewrite rules in order
    for pattern, replacement in _REWRITE_RULES:
        new_msg = pattern.sub(replacement, msg)
        if new_msg != msg:
            return new_msg, False

    return msg, False


class ScanSession:
    def __init__(self, scan_id: str, domain: str, username: str, opts: dict):
        self.scan_id    = scan_id
        self.domain     = domain
        self.username   = username
        self.opts       = opts
        self.status     = "pending"
        self.current_phase = 0
        self.logs: list[dict] = []
        self._logs_lock = threading.Lock()
        self.summary: dict    = {}
        self.counts: dict     = {}
        self.started_at: Optional[float]  = None
        self.finished_at: Optional[float] = None
        self._thread: Optional[threading.Thread] = None
        # Per-scan stop event — prevents stopping all scans when one user stops theirs
        self._stop_event  = threading.Event()
        # Pause event: when SET the scan waits between phases
        self._pause_event = threading.Event()

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return round(end - self.started_at, 1)

    def push_log(self, level: str, msg: str):
        entry = {"t": datetime.now().strftime("%H:%M:%S"), "l": level, "m": msg}
        with self._logs_lock:
            self.logs.append(entry)

    def to_dict(self) -> dict:
        return {
            "scan_id":       self.scan_id,
            "domain":        self.domain,
            "username":      self.username,
            "status":        self.status,
            "current_phase": self.current_phase,
            "elapsed":       self.elapsed,
            "summary":       self.summary,
            "counts":        self.counts,
            "paused":        self._pause_event.is_set(),
        }


# ═══════════════════════════════════════════════════════════════════════════
#  LOGGER HANDLER
# ═══════════════════════════════════════════════════════════════════════════

class SessionLogHandler(logging.Handler):
    LEVEL_MAP = {
        logging.DEBUG:    "debug",
        logging.INFO:     "info",
        logging.WARNING:  "warn",
        logging.ERROR:    "error",
        logging.CRITICAL: "error",
    }

    def __init__(self, session_obj: ScanSession):
        super().__init__()
        self.session_obj = session_obj

    def emit(self, record: logging.LogRecord):
        msg = record.getMessage()
        # Strip ANSI color codes
        msg = re.sub(r"\033\[[0-9;]*m", "", msg)
        # Strip leading whitespace used for indentation in scanner.py
        msg = msg.strip()
        if not msg:
            return

        # Sanitize before sending to frontend
        msg, skip = _sanitize_log(msg)
        if skip:
            return  # Don't expose internal commands/paths

        level = self.LEVEL_MAP.get(record.levelno, "info")
        # Debug logs are internal — only show info+ to public
        if level == "debug":
            return
        self.session_obj.push_log(level, msg)


# ═══════════════════════════════════════════════════════════════════════════
#  SCAN RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def _get_out_dir(username: str, domain: str) -> str:
    return os.path.join("output", username, domain)


def _run_scan(session_obj: ScanSession):
    session_obj.status     = "running"
    session_obj.started_at = time.time()

    config = sc.load_config(session_obj.opts.get("config_file"))
    config["threads"]         = int(session_obj.opts.get("threads", 50))
    config["rate_limit"]      = int(session_obj.opts.get("rate_limit", 150))
    config["timeout"]         = int(session_obj.opts.get("timeout", 30))
    config["nuclei_severity"] = session_obj.opts.get("severity", "low,medium,high,critical")
    config["output_base"]     = os.path.join("output", session_obj.username)
    config["auth_cookie"]     = session_obj.opts.get("auth_cookie", "")
    config["auth_header"]     = session_obj.opts.get("auth_header", "")
    config["no_xss"]          = session_obj.opts.get("no_xss", False)
    config["no_sqli"]         = session_obj.opts.get("no_sqli", False)
    config["no_js_analysis"]  = session_obj.opts.get("no_js_analysis", False)
    config["proxy"]           = session_obj.opts.get("proxy", "")
    config["scope_domains"]   = session_obj.opts.get("scope_domains", [])
    config["_current_domain"] = session_obj.domain

    class Args:
        domain           = session_obj.domain
        domains_file     = None
        skip_subfinder   = session_obj.opts.get("skip_subfinder", False)
        crawl_only       = session_obj.opts.get("crawl_only", False)
        resume           = session_obj.opts.get("resume", False)
        no_dirsearch     = session_obj.opts.get("no_dirsearch", False)
        no_nuclei        = session_obj.opts.get("no_nuclei", False)
        no_screenshots   = session_obj.opts.get("no_screenshots", False)
        no_xss           = session_obj.opts.get("no_xss", False)
        no_sqli          = session_obj.opts.get("no_sqli", False)
        no_js_analysis   = session_obj.opts.get("no_js_analysis", False)
        _tg_cfg          = load_telegram_config()
        telegram_token   = _tg_cfg.get("bot_token", "").strip() if _tg_cfg.get("enabled") else None
        telegram_chat_id = _tg_cfg.get("chat_id", "").strip() if _tg_cfg.get("enabled") else None

    logger = logging.getLogger(f"scanner.{session_obj.scan_id}")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False
    logger.addHandler(SessionLogHandler(session_obj))

    out_dir = _get_out_dir(session_obj.username, session_obj.domain)
    sc.ensure_dir(out_dir)

    if not Args.resume:
        state_file = os.path.join(out_dir, sc.RESUME_FILE)
        if os.path.exists(state_file):
            os.remove(state_file)

    # Use per-scan stop/pause events to avoid affecting unrelated scans
    _stop  = session_obj._stop_event
    _pause = session_obj._pause_event

    def _check_pause():
        """Block between phases while paused; return False if stopped while waiting."""
        if _pause.is_set():
            while _pause.is_set() and not _stop.is_set():
                time.sleep(0.5)
        return not _stop.is_set()

    def phase(n: int, name: str):
        _check_pause()
        main = _SUB_TO_MAIN_PHASE.get(n, min(n, 6))
        if main != session_obj.current_phase:
            session_obj.current_phase = main
            main_name = next((nm for num, nm, _ in PHASES if num == main), name)
            session_obj.push_log("phase", f"── Phase {main}: {main_name} ──────────────────────")

    subdomains_file   = os.path.join(out_dir, "subdomains.txt")
    alive_file        = os.path.join(out_dir, "alive_subdomains.txt")
    all_urls_file     = os.path.join(out_dir, "all_urls.txt")
    js_urls_file      = os.path.join(out_dir, "js_files.txt")
    filtered_file     = os.path.join(out_dir, "filtered_urls.txt")
    params_file       = os.path.join(out_dir, "params.txt")
    alive_params_file = os.path.join(out_dir, "alive_params.txt")

    try:
        phase(1, "Input Handling")
        session_obj.push_log("info", f"Target domain: {session_obj.domain}")
        auth_info = " | Authenticated" if config.get("auth_cookie") else ""
        session_obj.push_log("info", f"Threads: {config['threads']} | Rate: {config['rate_limit']}/s{auth_info}")

        # ── Phase 2: Subdomain Enumeration ──────────────────────────────────
        phase(2, "Subdomain Enumeration")
        if not _stop.is_set():
            sc.enumerate_subdomains(session_obj.domain, out_dir, config, logger, Args.skip_subfinder)

        # ── Phase 3: Live Host Detection ─────────────────────────────────────
        phase(3, "Live Host Detection")
        if not _stop.is_set():
            sc.run_httpx(subdomains_file, alive_file, config, logger)

        # ── Phase 3b: Port Scan ───────────────────────────────────────────────
        phase(3, "Port Scan")
        if not _stop.is_set():
            sc.run_nmap_port_scan(alive_file, out_dir, config, logger)
            _refresh_counts(session_obj, out_dir)

        # ── Phase 4: URL Collection ──────────────────────────────────────────
        phase(4, "URL Collection")
        if not _stop.is_set():
            sc.collect_urls(session_obj.domain, alive_file, out_dir, config, logger)

        if Args.crawl_only:
            session_obj.push_log("warn", "Crawl-only mode — stopping here")
            session_obj.status = "done"
            session_obj.finished_at = time.time()
            _refresh_counts(session_obj, out_dir)
            session_obj.push_log("done", "CRAWL COMPLETE")
            return

        # ── Phase 5: Deep Discovery ──────────────────────────────────────────
        phase(5, "Deep Discovery")
        if not _stop.is_set() and not Args.no_dirsearch:
            sc.run_dirsearch(alive_file, all_urls_file, out_dir, config, logger)
        if not _stop.is_set():
            sc.collect_js_files(all_urls_file, out_dir, logger)

        # ── Phase 6: JS Analysis ─────────────────────────────────────────────
        phase(6, "JS Analysis")
        if not _stop.is_set() and not Args.no_js_analysis:
            if os.path.exists(js_urls_file):
                sc.analyze_js_secrets(js_urls_file, out_dir, config, logger)
            else:
                session_obj.push_log("info", "No JS files found — JS analysis skipped")
        elif Args.no_js_analysis:
            session_obj.push_log("info", "JS analysis disabled")

        # ── Phase 7: URL Filtering + GF Classification ───────────────────────
        phase(7, "Normalization")
        gf_results: dict = {}
        if not _stop.is_set():
            sc.filter_urls(session_obj.domain, all_urls_file, out_dir, config, logger)
            gf_results = sc.run_gf_patterns(filtered_file, out_dir, logger)

        # ── Phase 8: Parameter Extraction ───────────────────────────────────
        phase(8, "Endpoint Analysis")
        if not _stop.is_set():
            sc.extract_params(filtered_file, out_dir, logger)

        # ── Phase 9: Verify Alive Params ────────────────────────────────────
        phase(9, "Validation")
        if not _stop.is_set():
            sc.verify_alive_params(params_file, out_dir, config, logger)

        # ── Phase 10-13: Full Vulnerability Scan ─────────────────────────────
        summary: dict = {}
        if not _stop.is_set() and not Args.no_nuclei:
            phase(10, "Injection Tests")
            # Split run_full_vuln_scan into sub-phases for better progress visibility
            summary = sc.run_full_vuln_scan(
                out_dir, config, logger, gf_results, alive_params_file,
                alive_file=alive_file,
                subdomains_file=subdomains_file,
            )

        phase(13, "Vuln Engine")
        # Nuclei is already called inside run_full_vuln_scan

        # ── Phase 14: Report ─────────────────────────────────────────────────
        phase(14, "Report")
        sc.save_scan_report(session_obj.domain, out_dir, summary, config, logger, session_obj.started_at)
        sc.save_html_report(session_obj.domain, out_dir, summary, gf_results, logger)

        session_obj.summary       = summary
        session_obj.status        = "done"
        session_obj.finished_at   = time.time()
        session_obj.current_phase = 6
        _refresh_counts(session_obj, out_dir)

        # Show critical/high summary in log
        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        secrets_count = summary.get("info_secrets", 0)
        if crit or high:
            session_obj.push_log("error",
                f"⚠ CRITICAL: {crit} | HIGH: {high} — Review findings immediately!")
        if secrets_count:
            session_obj.push_log("warn", f"🔑 {secrets_count} leaked secrets found in JS files!")
        session_obj.push_log("done", f"SCAN COMPLETE — {session_obj.domain}")

    except Exception as exc:
        import traceback
        session_obj.status      = "error"
        session_obj.finished_at = time.time()
        session_obj.push_log("error", f"Fatal error: {exc}")
        session_obj.push_log("error", traceback.format_exc())


def _refresh_counts(session_obj: ScanSession, out_dir: str):
    files = {
        "subdomains":    "subdomains.txt",
        "alive_hosts":   "alive_subdomains.txt",
        "all_urls":      "all_urls.txt",
        "filtered_urls": "filtered_urls.txt",
        "params":        "params.txt",
        "alive_params":  "alive_params.txt",
        "js_files":      "js_files.txt",
    }
    counts = {k: sc.count_lines(os.path.join(out_dir, v)) for k, v in files.items()}

    # Count open ports (sum of all host:port1,port2,... entries)
    open_ports_path = os.path.join(out_dir, "open_ports.txt")
    if os.path.exists(open_ports_path):
        total = 0
        for line in sc.read_lines(open_ports_path):
            if ":" in line:
                ports = line.split(":", 1)[1]
                total += len([p for p in ports.split(",") if p.strip()])
        counts["open_ports"] = total
    else:
        counts["open_ports"] = 0

    # Count JS secrets
    secrets_file = os.path.join(out_dir, "js_secrets.json")
    if os.path.exists(secrets_file):
        try:
            with open(secrets_file) as f:
                counts["js_secrets"] = len(json.load(f))
        except Exception:
            counts["js_secrets"] = 0
    else:
        counts["js_secrets"] = 0

    session_obj.counts = counts


# ═══════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if "username" in session:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)
        if user and user.get("active", True) and check_password_hash(user["password"], password):
            session.permanent = True
            session["username"] = username
            session["role"]     = user.get("role", "user")
            return redirect(url_for("index"))
        else:
            time.sleep(1)  # Slow brute force
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        phases=PHASES,
        username=session.get("username"),
        role=session.get("role"),
    )


# ═══════════════════════════════════════════════════════════════════════════
#  API — SCAN MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
@login_required
def start_scan():
    username = session["username"]
    data     = request.get_json(silent=True) or {}
    raw_domain = data.get("domain", "").strip()

    # Support comma-separated domains — validate each and start a scan per domain
    raw_list = [d.strip() for d in raw_domain.split(",") if d.strip()]
    domains = []
    for d in raw_list:
        ok, cleaned = validate_domain(d)
        if ok:
            domains.append(cleaned)
        else:
            return jsonify({"error": f"{d}: {cleaned}"}), 400
    if not domains:
        return jsonify({"error": "Enter at least one valid domain"}), 400

    # Rate limiting
    if not check_rate_limit(username):
        return jsonify({"error": f"Rate limit exceeded — max {RATE_LIMIT_MAX} scans per {RATE_LIMIT_WINDOW}s"}), 429

    opts = {
        "threads":        max(1, min(int(data.get("threads", 50)), 150)),
        "rate_limit":     max(1, min(int(data.get("rate_limit", 150)), 500)),
        "timeout":        max(5, min(int(data.get("timeout", 30)), 120)),
        "severity":       data.get("severity", "low,medium,high,critical"),
        "skip_subfinder": bool(data.get("skip_subfinder", False)),
        "crawl_only":     bool(data.get("crawl_only", False)),
        "resume":         bool(data.get("resume", False)),
        "no_dirsearch":   bool(data.get("no_dirsearch", False)),
        "no_nuclei":      bool(data.get("no_nuclei", False)),
        "no_screenshots": bool(data.get("no_screenshots", False)),
        "no_xss":         bool(data.get("no_xss", False)),
        "no_sqli":        bool(data.get("no_sqli", False)),
        "no_js_analysis": bool(data.get("no_js_analysis", False)),
        "auth_cookie":    str(data.get("auth_cookie", ""))[:2048],
        "auth_header":    str(data.get("auth_header", ""))[:512],
        "proxy":          str(data.get("proxy", ""))[:512],
        "scope_domains":  list(data.get("scope_domains", []))[:50],
    }

    started = []
    with SCANS_LOCK:
        active = [s for s in SCANS.values() if s.status == "running"]
        user_active = [s for s in active if s.username == username]
        slots = min(MAX_USER_SCANS - len(user_active), MAX_GLOBAL_SCANS - len(active))
        slots = max(0, slots)
        to_start = domains[:slots] if slots else []

    for domain in to_start:
        with SCANS_LOCK:
            active = [s for s in SCANS.values() if s.status == "running"]
            if len(active) >= MAX_GLOBAL_SCANS:
                break
            user_active = [s for s in active if s.username == username]
            if len(user_active) >= MAX_USER_SCANS:
                break

        scan_id = str(uuid.uuid4())[:8]
        sess = ScanSession(scan_id, domain, username, opts)
        with SCANS_LOCK:
            SCANS[scan_id] = sess
        t = threading.Thread(target=_run_scan, args=(sess,), daemon=True)
        sess._thread = t
        t.start()
        started.append({"scan_id": scan_id, "domain": domain})

    if not started:
        return jsonify({"error": f"Max concurrent scans reached ({MAX_USER_SCANS} per user). Stop a scan or wait for one to finish."}), 429
    if len(domains) > len(started):
        # Some domains were not started due to limits
        return jsonify({
            "scan_ids": [s["scan_id"] for s in started],
            "scan_id": started[0]["scan_id"],
            "domain": started[0]["domain"],
            "started": len(started),
            "queued": len(domains) - len(started),
            "message": f"Started {len(started)} scan(s). {len(domains) - len(started)} domain(s) queued — start more when slots free.",
        }), 202

    return jsonify({
        "scan_ids": [s["scan_id"] for s in started],
        "scan_id": started[0]["scan_id"],
        "domain": started[0]["domain"],
        "started": len(started),
    }), 202


@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
@login_required
def stop_scan(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404
    sess._pause_event.clear()   # clear pause first so thread can exit
    sess._stop_event.set()
    sess.status = "interrupted"
    sess.push_log("warn", "Scan stopped by user")
    return jsonify({"status": "interrupted"})


@app.route("/api/scan/<scan_id>/pause", methods=["POST"])
@login_required
def pause_scan(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404
    if sess.status != "running":
        return jsonify({"error": "Scan not running"}), 400
    sess._pause_event.set()
    sess.status = "paused"
    sess.push_log("warn", "Scan paused by user")
    return jsonify({"status": "paused"})


@app.route("/api/scan/<scan_id>/resume", methods=["POST"])
@login_required
def resume_scan(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404
    if sess.status != "paused":
        return jsonify({"error": "Scan not paused"}), 400
    sess._pause_event.clear()
    sess.status = "running"
    sess.push_log("info", "Scan resumed")
    return jsonify({"status": "running"})


@app.route("/api/scan/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404
    return jsonify(sess.to_dict())


@app.route("/api/scan/<scan_id>/stream")
@login_required
def stream_logs(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404

    def event_generator():
        idx = 0
        while True:
            with sess._logs_lock:
                batch = sess.logs[idx:]
            for entry in batch:
                idx += 1
                import json as _json
                yield f"data: {_json.dumps(entry)}\n\n"

            if sess.status in ("done", "error", "interrupted") and idx >= len(sess.logs):
                import json as _json
                yield f"data: {_json.dumps({'t':'','l':'eof','m':'__EOF__'})}\n\n"
                break
            time.sleep(0.3)

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/scan/<scan_id>/results")
@login_required
def get_results(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404

    out_dir  = _get_out_dir(sess.username, sess.domain)
    findings = sc.parse_nuclei_json(os.path.join(out_dir, "findings.json"))
    _refresh_counts(sess, out_dir)

    return jsonify({
        "scan":     sess.to_dict(),
        "findings": findings[:1000],
        "counts":   sess.counts,
    })


@app.route("/api/scan/<scan_id>/file/<filename>")
@login_required
def get_file(scan_id: str, filename: str):
    ALLOWED = {
        "subdomains.txt", "alive_subdomains.txt", "open_ports.txt", "all_urls.txt",
        "filtered_urls.txt", "params.txt", "alive_params.txt",
        "findings.txt", "findings.json", "scan_report.json",
        "js_files.txt", "js_secrets.json", "js_secrets.txt",
        "xss_findings.json", "sqli_findings.json", "idor_findings.json",
        "cors_findings.json", "bypass_findings.json", "ssti_findings.json",
        "hostheader_findings.json", "ssrf_findings.json", "redirect_findings.json",
        "takeover_findings.json", "graphql_findings.json", "jwt_findings.json",
        "lfi_findings.json", "xxe_findings.json", "race_findings.json", "upload_findings.json",
        "gf_xss.txt", "gf_sqli.txt", "gf_ssrf.txt",
        "gf_redirect.txt", "gf_lfi.txt", "gf_rce.txt", "gf_idor.txt",
        "report.html",
    }
    if filename not in ALLOWED:
        return jsonify({"error": "Forbidden"}), 403

    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404

    filepath = os.path.join(_get_out_dir(sess.username, sess.domain), filename)
    if not os.path.exists(filepath):
        return jsonify({"lines": [], "count": 0})

    if filename.endswith(".json"):
        # findings.json is JSONL (one JSON per line); other *_findings.json are JSON arrays
        if filename == "findings.json":
            data = sc.parse_nuclei_json(filepath)
            return jsonify({"data": data[:500], "count": len(data)})
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, list):
                return jsonify({"data": data[:500], "count": len(data)})
            return jsonify({"data": data})
        except Exception:
            # Fallback: try JSONL
            try:
                data = sc.parse_nuclei_json(filepath)
                if data:
                    return jsonify({"data": data[:500], "count": len(data)})
            except Exception:
                pass
            return jsonify({"data": [], "count": 0})

    lines = sc.read_lines(filepath)
    return jsonify({"lines": lines[:2000], "count": len(lines)})


# ── Export: HTML Report ────────────────────────────────────────────────────
@app.route("/api/scan/<scan_id>/export/html")
@login_required
def export_html(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404

    out_dir = _get_out_dir(sess.username, sess.domain)

    # Gather all findings
    all_findings = sc.parse_nuclei_json(os.path.join(out_dir, "findings.json"))
    extra_files = [
        "cors_findings.json", "ssrf_findings.json", "ssti_findings.json",
        "bypass_findings.json", "takeover_findings.json", "graphql_findings.json",
        "jwt_findings.json", "lfi_findings.json", "xxe_findings.json",
        "race_findings.json", "upload_findings.json", "xss_findings.json",
        "sqli_findings.json", "idor_findings.json", "hostheader_findings.json",
        "redirect_findings.json",
    ]
    for ef in extra_files:
        fp = os.path.join(out_dir, ef)
        if os.path.exists(fp):
            try:
                with open(fp, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_findings.extend(data)
            except Exception:
                pass

    # Severity counts
    def sev(f):
        return (f.get("info", {}).get("severity") or f.get("severity") or "info").lower()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        s = sev(f)
        counts[s] = counts.get(s, 0) + 1

    # Recon stats
    def _cnt(fname):
        p = os.path.join(out_dir, fname)
        return sc.count_lines(p) if os.path.exists(p) else 0

    def _open_ports_count():
        p = os.path.join(out_dir, "open_ports.txt")
        if not os.path.exists(p):
            return 0
        total = 0
        for line in sc.read_lines(p):
            if ":" in line:
                ports = line.split(":", 1)[1]
                total += len([x for x in ports.split(",") if x.strip()])
        return total

    recon = {
        "subdomains": _cnt("subdomains.txt"),
        "alive_hosts": _cnt("alive_subdomains.txt"),
        "open_ports": _open_ports_count(),
        "total_urls": _cnt("all_urls.txt"),
        "filtered_urls": _cnt("filtered_urls.txt"),
        "params": _cnt("params.txt"),
        "alive_params": _cnt("alive_params.txt"),
        "scan_targets": _cnt("nuclei_targets.txt"),
        "js_files": _cnt("js_files.txt"),
        "dirs_discovered": _cnt("dirsearch_raw.txt"),
    }

    # JS secrets
    secrets = []
    sp = os.path.join(out_dir, "js_secrets.json")
    if os.path.exists(sp):
        try:
            with open(sp, encoding="utf-8") as f:
                secrets = json.load(f) or []
        except Exception:
            pass

    from datetime import datetime as _dt

    def _sev_color(s):
        return {"critical": "#ff2222", "high": "#f87171", "medium": "#fbbf24",
                "low": "#60a5fa", "info": "#94a3b8"}.get(s.lower(), "#94a3b8")

    def _sev_bg(s):
        return {"critical": "rgba(255,34,34,.15)", "high": "rgba(248,113,113,.12)",
                "medium": "rgba(251,191,36,.12)", "low": "rgba(96,165,250,.12)",
                "info": "rgba(148,163,184,.08)"}.get(s.lower(), "rgba(148,163,184,.08)")

    def _finding_rows():
        rows = []
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(all_findings, key=lambda x: order.get(sev(x), 5))
        for f in sorted_f[:500]:
            s       = sev(f)
            name    = (f.get("info", {}).get("name") or f.get("description") or
                       f.get("template-id") or f.get("type") or "Unknown")
            url     = f.get("matched-at") or f.get("url") or ""
            ftype   = f.get("type") or f.get("template-id") or ""
            matcher = f.get("matcher-name") or ""
            detail  = matcher or ftype or ""
            color   = _sev_color(s)
            bg      = _sev_bg(s)
            rows.append(f"""
        <tr style="border-bottom:1px solid #1e293b">
          <td style="padding:10px 14px">
            <span style="display:inline-block;padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;
              background:{bg};color:{color};border:1px solid {color}33;letter-spacing:.5px">
              {s.upper()}
            </span>
          </td>
          <td style="padding:10px 14px;color:#e2e8f0;font-weight:500">{name[:80]}</td>
          <td style="padding:10px 14px;color:#94a3b8;font-size:11px">{detail[:50]}</td>
          <td style="padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:10px;color:#64748b;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            <a href="{url}" target="_blank" style="color:#38bdf8;text-decoration:none">{url[:100]}</a>
          </td>
        </tr>""")
        return "".join(rows)

    # Donut chart data for inline SVG
    total_vulns = sum(counts.values())
    sev_order   = ["critical", "high", "medium", "low", "info"]
    sev_colors  = {"critical": "#ff2222", "high": "#f87171", "medium": "#fbbf24", "low": "#60a5fa", "info": "#475569"}

    def _donut_segments():
        if total_vulns == 0:
            return '<circle cx="60" cy="60" r="40" fill="none" stroke="#1e293b" stroke-width="20"/>'
        segs  = []
        total = sum(counts.values())
        offset = -90  # start at top
        r, cx, cy, sw = 40, 60, 60, 20
        circumference = 2 * 3.14159 * r
        for s in sev_order:
            c = counts.get(s, 0)
            if c == 0:
                continue
            pct   = c / total
            dash  = pct * circumference
            gap   = circumference - dash
            angle = offset * 3.14159 / 180
            segs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{sev_colors[s]}" '
                f'stroke-width="{sw}" stroke-dasharray="{dash:.1f} {gap:.1f}" '
                f'stroke-dashoffset="{-offset * circumference / 360:.1f}" '
                f'transform="rotate({offset} {cx} {cy})" opacity="0.9"/>'
            )
            offset += pct * 360
        return "".join(segs)

    now_str = _dt.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_time = ""
    report_path = os.path.join(out_dir, "scan_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                rdata = json.load(f)
                scan_time = rdata.get("scan_time", "")
        except Exception:
            pass

    # ── Vuln type breakdown ────────────────────────────────────────────────
    type_counts: dict = {}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in all_findings:
        t = (f.get("type") or f.get("template-id") or
             f.get("info", {}).get("name") or "unknown").lower()
        type_counts[t] = type_counts.get(t, 0) + 1
    top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:12]

    # ── Subdomains list ─────────────────────────────────────────────────────
    sub_list = sc.read_lines(os.path.join(out_dir, "subdomains.txt"))[:50]
    alive_list = sc.read_lines(os.path.join(out_dir, "alive_subdomains.txt"))[:30]

    # ── Finding rows (detailed, expandable) ─────────────────────────────────
    _REMEDIATION = {
        "xss":         "Encode all output, use Content-Security-Policy header, sanitise user input server-side.",
        "sqli":        "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
        "ssrf":        "Whitelist allowed hosts. Block internal IP ranges at the network layer.",
        "cors":        "Set strict Access-Control-Allow-Origin. Avoid wildcards for credentialed requests.",
        "lfi":         "Never pass user-controlled filenames to filesystem APIs. Whitelist allowed paths.",
        "xxe":         "Disable external entity processing in your XML parser. Use JSON where possible.",
        "ssti":        "Escape user input before passing to template engines. Sandbox templates.",
        "jwt":         "Use strong signing secrets (≥256-bit). Reject 'alg: none' tokens. Rotate secrets.",
        "takeover":    "Remove dangling DNS records pointing to decommissioned services.",
        "cors-misconfiguration": "Restrict CORS to known trusted origins with credentials.",
        "403-bypass":  "Fix path-based authorization checks. Rely on server-side roles, not URL patterns.",
        "open-redirect": "Validate and whitelist redirect destinations.",
        "idor":        "Enforce object-level authorisation checks using session context, not client-supplied IDs.",
        "race-condition": "Implement idempotency keys, DB-level locks, or atomic operations.",
        "file-upload-bypass": "Validate MIME type server-side. Rename uploaded files. Store outside webroot.",
        "host-header": "Validate Host header against a whitelist. Never use it in password-reset links.",
        "graphql":     "Disable introspection in production. Implement query depth / cost limits.",
    }

    def _get_remediation(f):
        combined = " ".join([
            (f.get("type") or ""), (f.get("template-id") or ""),
            (f.get("info", {}).get("name") or ""),
        ]).lower()
        for k, v in _REMEDIATION.items():
            if k in combined:
                return v
        return "Review the finding manually and apply appropriate input validation and output encoding."

    def _finding_row_html(f, s, color, bg, glow):
        name    = (f.get("info", {}).get("name") or f.get("description") or
                   f.get("template-id") or f.get("type") or "Unknown")
        url     = f.get("matched-at") or f.get("url") or ""
        ftype   = (f.get("type") or f.get("template-id") or "").replace("-", " ").title()
        matcher = f.get("matcher-name") or ""
        cvss    = f.get("info", {}).get("cvss-score") or f.get("cvss") or ""
        cve     = f.get("info", {}).get("cve") or ""
        refs    = f.get("info", {}).get("reference") or []
        if isinstance(refs, str): refs = [refs]
        desc    = (f.get("info", {}).get("description") or f.get("description") or "")[:300]
        remediation = _get_remediation(f)
        cvss_html = f'<span style="font-size:10px;font-weight:700;color:{color};background:{bg};padding:2px 7px;border-radius:4px;margin-left:6px">CVSS {cvss}</span>' if cvss else ""
        cve_html  = f'<span style="font-size:10px;color:#a5b4fc;background:rgba(99,102,241,.15);padding:2px 7px;border-radius:4px;margin-left:6px">{cve}</span>' if cve else ""
        refs_html = "".join(f'<a href="{r}" target="_blank" style="font-size:10px;color:#38bdf8;margin-right:8px">🔗 ref</a>' for r in refs[:3])
        return f"""
        <tr class="finding-row" data-sev="{s}" onclick="toggleDetail(this);event.stopPropagation()"
          style="border-bottom:1px solid #0f172a;cursor:pointer;transition:background .15s">
          <td style="padding:11px 14px;width:108px;vertical-align:middle">
            <span class="sev-badge" style="display:inline-flex;align-items:center;justify-content:center;
              width:82px;padding:4px 0;border-radius:6px;font-size:10px;font-weight:800;letter-spacing:.7px;
              background:{bg};color:{color};border:1px solid {color}44;box-shadow:0 0 8px {glow}">
              {s.upper()}
            </span>
          </td>
          <td style="padding:11px 14px;vertical-align:middle">
            <div style="font-weight:600;color:#f1f5f9;font-size:13px">{name[:90]}{cvss_html}{cve_html}</div>
            {"<div style='font-size:11px;color:#64748b;margin-top:3px'>" + ftype + ("  ·  " + matcher if matcher else "") + "</div>" if ftype else ""}
          </td>
          <td style="padding:11px 14px;vertical-align:middle;max-width:340px">
            <a href="{url}" target="_blank"
              style="font-family:'Courier New',monospace;font-size:10px;color:#38bdf8;
                word-break:break-all;line-height:1.5;text-decoration:none"
              title="{url}" onclick="event.stopPropagation()">{url[:120]}{"…" if len(url)>120 else ""}</a>
          </td>
          <td style="padding:11px 14px;width:28px;text-align:center;vertical-align:middle;color:#334155;font-size:12px" class="toggle-icon">▼</td>
        </tr>
        <tr class="detail-row" style="display:none;background:#070d18">
          <td colspan="4" style="padding:16px 20px 20px 120px">
            {"<p style='font-size:12px;color:#94a3b8;margin-bottom:10px;line-height:1.7'>" + desc + "</p>" if desc else ""}
            <div style="background:#0a1020;border:1px solid #1e2a40;border-radius:8px;padding:14px;margin-bottom:10px">
              <div style="font-size:10px;font-weight:700;color:#64748b;letter-spacing:.8px;margin-bottom:6px;text-transform:uppercase">🛠 Remediation</div>
              <div style="font-size:12px;color:#94a3b8;line-height:1.7">{remediation}</div>
            </div>
            {refs_html}
          </td>
        </tr>"""

    def _finding_rows_detailed():
        # Group by severity, then output accordion: severity header (click to expand) -> list of findings (click to expand detail)
        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_colors = {"critical": "#ff2222", "high": "#f87171", "medium": "#fbbf24", "low": "#60a5fa", "info": "#475569"}
        grouped = {}
        for f in all_findings[:500]:
            s = sev(f)
            grouped.setdefault(s, []).append(f)
        out = []
        for s in sev_order:
            flist = grouped.get(s, [])
            if not flist:
                continue
            c = len(flist)
            color = sev_colors.get(s, "#475569")
            bg = _sev_bg(s)
            glow = {"critical": "rgba(255,34,34,.25)", "high": "rgba(248,113,113,.15)",
                    "medium": "rgba(251,191,36,.12)", "low": "rgba(96,165,250,.1)",
                    "info": "rgba(71,85,105,.1)"}.get(s, "rgba(71,85,105,.1)")
            # Severity header tbody - click to expand/collapse the list
            out.append(f"""
        <tbody class="severity-header-tbody" data-sev="{s}">
          <tr class="severity-header-row" onclick="toggleSeverityGroup(this)" data-sev="{s}"
            style="cursor:pointer;background:var(--bg2);border-bottom:1px solid var(--border);transition:background .2s">
            <td colspan="4" style="padding:14px 20px;display:flex;align-items:center;gap:12px">
              <span class="sev-arrow" style="font-size:11px;color:var(--text3);transition:transform .2s">▶</span>
              <span class="sev-badge" style="display:inline-flex;align-items:center;justify-content:center;
                padding:5px 14px;border-radius:6px;font-size:11px;font-weight:800;letter-spacing:.7px;
                background:{bg};color:{color};border:1px solid {color}44;box-shadow:0 0 8px {glow}">
                {s.upper()}
              </span>
              <span style="font-size:13px;color:var(--text2);font-weight:600">({c} findings)</span>
            </td>
          </tr>
        </tbody>
        <tbody class="severity-body-tbody" data-sev="{s}" style="display:none">
""")
            for f in flist:
                out.append(_finding_row_html(f, s, color, bg, glow))
            out.append("        </tbody>")
        return "".join(out)

    # ── Attack surface bar chart ─────────────────────────────────────────────
    def _type_bars():
        if not top_types: return "<p style='color:#475569;text-align:center;padding:20px'>No data</p>"
        max_c = max(c for _, c in top_types) or 1
        html_parts = []
        for name, c in top_types:
            pct = int(c / max_c * 100)
            color = "#6366f1"
            html_parts.append(f"""
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <div style="width:160px;font-size:11px;color:#94a3b8;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{name[:22]}</div>
        <div style="flex:1;background:#0f172a;border-radius:4px;height:20px;overflow:hidden;border:1px solid #1e293b">
          <div style="height:100%;width:{pct}%;background:linear-gradient(90deg,#6366f1,#8b5cf6);
            border-radius:4px;transition:width .8s ease;display:flex;align-items:center;padding-left:8px">
            <span style="font-size:10px;font-weight:700;color:#fff;white-space:nowrap">{c}</span>
          </div>
        </div>
      </div>""")
        return "".join(html_parts)

    # ── Severity bar chart (horizontal) ─────────────────────────────────────
    def _sev_bars():
        bars = []
        max_c = max(counts.values()) or 1
        for s in sev_order:
            c = counts.get(s, 0)
            pct = int(c / max_c * 100)
            col = sev_colors[s]
            bars.append(f"""
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <div style="width:70px;font-size:11px;color:{col};font-weight:700;text-transform:uppercase;letter-spacing:.5px">{s}</div>
        <div style="flex:1;background:#0a0f1e;border-radius:6px;height:26px;overflow:hidden;border:1px solid #1e293b">
          <div style="height:100%;width:{pct}%;background:{col};opacity:.85;border-radius:6px;
            display:flex;align-items:center;justify-content:flex-end;padding-right:10px;
            transition:width 1s ease;min-width:{('28px' if c>0 else '0')}">
            {"<span style='font-size:12px;font-weight:800;color:#000'>" + str(c) + "</span>" if c > 0 else ""}
          </div>
        </div>
        <div style="width:32px;font-size:11px;color:#475569;text-align:right">{int(c/max(total_vulns,1)*100)}%</div>
      </div>""")
        return "".join(bars)

    now_str = _dt.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_time = ""
    scanned_by = ""
    report_path_j = os.path.join(out_dir, "scan_report.json")
    if os.path.exists(report_path_j):
        try:
            with open(report_path_j, encoding="utf-8") as fj:
                rdata = json.load(fj)
                scan_time  = rdata.get("scan_time", "")
                scanned_by = rdata.get("user", sess.username)
        except Exception:
            pass
    scanned_by = scanned_by or sess.username

    # Risk score (0-100 weighted)
    risk_score = min(100, counts.get("critical",0)*25 + counts.get("high",0)*10 +
                     counts.get("medium",0)*3 + counts.get("low",0))
    risk_label = ("CRITICAL" if risk_score>=75 else "HIGH" if risk_score>=40
                  else "MEDIUM" if risk_score>=15 else "LOW" if risk_score>0 else "CLEAN")
    risk_color = {"CRITICAL":"#ff2222","HIGH":"#f87171","MEDIUM":"#fbbf24","LOW":"#60a5fa","CLEAN":"#22c55e"}[risk_label]
    risk_arc_pct = risk_score  # 0-100

    # ── Pre-compute complex HTML blocks (avoid backslashes inside f-string expr) ──
    _sec_html = ""
    if secrets:
        rows_s = []
        for _s in secrets[:30]:
            rows_s.append(
                '<div class="secret-item">'
                '<div class="secret-type-badge">&#128273; ' + (_s.get("type","SECRET")) + '</div>'
                '<div class="secret-url">' + (_s.get("url","")[:120]) + '</div>'
                '<div class="secret-val">' + (_s.get("value","")[:200]) + '</div>'
                '</div>'
            )
        _sec_html = (
            "<section id='secrets'><div class='section-header'>"
            "<div class='section-icon' style='background:rgba(244,63,94,.12);color:#f43f5e'>&#128273;</div>"
            "<h2>JavaScript Secrets (" + str(len(secrets)) + " found)</h2></div>"
            "<div style='background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.2);"
            "border-radius:10px;padding:12px 16px;margin-bottom:16px;font-size:12px;color:#94a3b8'>"
            "&#9888;&#65039; These secrets were extracted from JavaScript files and may expose "
            "API keys, tokens, or credentials.</div>"
            "<div class='secrets-grid'>" + "".join(rows_s) + "</div></section>"
        )

    _hosts_html = ""
    if sub_list:
        alive_set = set(alive_list)
        rows_h = []
        for h in sub_list:
            dot_cls = "host-dot" if h in alive_set else "host-dot dead"
            rows_h.append('<div class="host-item"><div class="' + dot_cls + '"></div>' + h[:50] + '</div>')
        _hosts_html = (
            "<div style='font-size:11px;color:var(--text3);margin-bottom:12px'>"
            "&#x1F7E2; Alive hosts &nbsp;&nbsp; &#x1F535; All discovered subdomains (showing first 50)"
            "</div><div class='host-grid'>" + "".join(rows_h) + "</div>"
        )
    else:
        _hosts_html = "<p style='color:var(--text3)'>No subdomains discovered</p>"

    _filter_btns = '<button class="filter-btn active" onclick="filterFindings(\'all\',this)">All (' + str(total_vulns) + ')</button>'
    for _fs, _fc in [("critical","#ff2222"),("high","#f87171"),("medium","#fbbf24"),("low","#60a5fa"),("info","#475569")]:
        _c = counts.get(_fs, 0)
        if _c > 0:
            _filter_btns += ('<button class="filter-btn" onclick="filterFindings(\'' + _fs + '\',this)" '
                             'style="color:' + _fc + '">' + _fs.capitalize() + ' (' + str(_c) + ')</button>')

    _risk_blocks = ""
    _risk_data = [
        ("critical", "#ff2222", "rgba(255,34,34,.07)", "rgba(255,34,34,.2)",
         "CRITICAL", str(counts.get("critical",0)),
         "Immediate remediation required. These vulnerabilities represent severe security risks "
         "including potential for full system compromise, unauthorized data access, or remote code execution."),
        ("high", "#f87171", "rgba(248,113,113,.06)", "rgba(248,113,113,.2)",
         "HIGH", str(counts.get("high",0)),
         "High-priority vulnerabilities that should be patched within 24-48 hours. "
         "These can lead to data breaches, authentication bypass, or significant privilege escalation."),
        ("medium", "#fbbf24", "rgba(251,191,36,.06)", "rgba(251,191,36,.2)",
         "MEDIUM", str(counts.get("medium",0)),
         "Moderate risk findings that should be addressed in the next development sprint. "
         "While not immediately critical, these represent exploitable weaknesses that could be chained."),
        ("low_info", "#60a5fa", "rgba(96,165,250,.06)", "rgba(96,165,250,.2)",
         "LOW / INFO", str(counts.get("low",0)+counts.get("info",0)),
         "Informational and low-severity findings. Review these during routine security maintenance."),
    ]
    for _key, _col, _bg, _brd, _label, _cnt, _desc in _risk_data:
        _real_key = "low" if _key == "low_info" else _key
        _show = (counts.get(_real_key, 0) + (counts.get("info",0) if _key=="low_info" else 0)) > 0
        if _show:
            _risk_blocks += (
                "<div style='padding:16px 20px;background:" + _bg + ";border:1px solid " + _brd + ";"
                "border-radius:10px;border-left:4px solid " + _col + "'>"
                "<div style='font-weight:700;color:" + _col + ";margin-bottom:6px;font-size:14px'>"
                + _label + " &mdash; " + _cnt + " findings</div>"
                "<p style='font-size:12px;color:#94a3b8;line-height:1.8'>" + _desc + "</p></div>"
            )
    if total_vulns == 0:
        _risk_blocks = (
            "<div style='padding:24px;text-align:center;background:rgba(34,197,94,.06);"
            "border:1px solid rgba(34,197,94,.2);border-radius:10px'>"
            "<div style='font-size:32px'>&#x2705;</div>"
            "<div style='font-weight:700;color:#22c55e;margin-top:8px'>No Vulnerabilities Detected</div>"
            "<p style='font-size:12px;color:#94a3b8;margin-top:6px'>The automated scan did not identify "
            "any exploitable vulnerabilities. Consider running a manual pentest for full coverage.</p></div>"
        )

    _scan_dur_pill = ('<div class="pill">&#9201; Duration: <strong>' + scan_time + '</strong></div>') if scan_time else ""
    _no_vuln_row = ('<tr><td colspan="4" style="text-align:center;padding:48px;color:var(--text3)">'
                    '<div style="font-size:36px;margin-bottom:12px">&#x2705;</div>'
                    '<div>No vulnerabilities detected</div></td></tr>')
    _empty_message = ("Critical or high severity vulnerabilities found" if risk_score >= 40
                      else "Moderate risk level detected" if risk_score > 0
                      else "No significant vulnerabilities detected")
    _risk_icon = "&#9888;" if risk_score > 0 else "&#x2705;"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Report — {sess.domain}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#030b15;--bg2:#07111e;--bg3:#0c1928;--bg4:#0f1e2e;
  --border:#162030;--border2:#1e3044;
  --text:#e8f0fe;--text2:#a8bfd4;--text3:#546e8a;
  --critical:#ff2222;--high:#f87171;--medium:#fbbf24;--low:#60a5fa;--info:#475569;
  --purple:#8b5cf6;--cyan:#22d3ee;--green:#22c55e;
}}
html{{scroll-behavior:smooth}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.6}}
a{{color:var(--cyan);text-decoration:none}}
a:hover{{text-decoration:underline}}

/* ── Sidebar ── */
.sidebar{{position:fixed;top:0;left:0;bottom:0;width:220px;background:var(--bg2);border-right:1px solid var(--border);
  padding:24px 0;z-index:100;overflow-y:auto}}
.sidebar-logo{{padding:0 20px 20px;border-bottom:1px solid var(--border);margin-bottom:12px}}
.sidebar-logo .shield{{font-size:22px;display:block;margin-bottom:4px}}
.sidebar-logo .domain{{font-size:12px;font-weight:700;color:var(--text);word-break:break-all;line-height:1.4}}
.sidebar-logo .sub{{font-size:10px;color:var(--text3)}}
.nav-item{{display:flex;align-items:center;gap:9px;padding:8px 20px;font-size:12px;color:var(--text3);
  cursor:pointer;transition:all .2s;border-left:2px solid transparent;text-decoration:none}}
.nav-item:hover,.nav-item.active{{color:var(--text);background:rgba(255,255,255,.04);border-left-color:var(--purple)}}
.nav-icon{{font-size:13px;width:16px;text-align:center}}
.nav-badge{{margin-left:auto;background:var(--bg3);border-radius:20px;padding:1px 7px;
  font-size:10px;font-weight:700;color:var(--text2)}}
.sidebar-sep{{border:none;border-top:1px solid var(--border);margin:10px 20px}}

/* ── Main ── */
.main{{margin-left:220px;min-height:100vh}}

/* ── Hero ── */
.hero{{
  background:linear-gradient(135deg,#020c18 0%,#080e20 35%,#0a0624 70%,#020c18 100%);
  padding:48px 48px 40px;position:relative;overflow:hidden;
  border-bottom:1px solid var(--border)
}}
.hero::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 70% 100% at 20% -10%,rgba(99,102,241,.18) 0%,transparent 60%),
             radial-gradient(ellipse 50% 80% at 80% 110%,rgba(34,211,238,.08) 0%,transparent 60%);
  pointer-events:none
}}
.hero-eyebrow{{display:inline-flex;align-items:center;gap:8px;
  background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.3);
  border-radius:20px;padding:5px 14px;font-size:11px;color:#a5b4fc;
  margin-bottom:20px;letter-spacing:.3px;font-weight:500}}
.hero-title{{font-size:38px;font-weight:900;letter-spacing:-1px;
  background:linear-gradient(135deg,#ffffff 0%,#c7d2fe 60%,#818cf8 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin-bottom:6px;line-height:1.1}}
.hero-sub{{font-size:13px;color:var(--text3);margin-bottom:28px}}
.hero-pills{{display:flex;gap:12px;flex-wrap:wrap}}
.pill{{display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.04);
  border:1px solid var(--border2);border-radius:8px;padding:8px 14px;font-size:12px;color:var(--text2)}}
.pill strong{{color:var(--text)}}
.risk-pill{{padding:8px 18px;border-radius:8px;font-weight:800;font-size:13px;
  border:1px solid {risk_color}55;background:{risk_color}18;color:{risk_color};
  display:flex;align-items:center;gap:8px}}

/* ── Content ── */
.content{{padding:36px 48px}}
section{{margin-bottom:48px;scroll-margin-top:20px}}
.section-header{{display:flex;align-items:center;gap:10px;margin-bottom:20px}}
.section-header h2{{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-.2px}}
.section-icon{{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;
  justify-content:center;font-size:13px;flex-shrink:0}}
.section-badge{{margin-left:auto;font-size:11px;color:var(--text3);
  background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:2px 10px}}

/* ── Dashboard top row ── */
.dash-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}}
.panel{{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:22px}}

/* ── Severity summary cards ── */
.sev-row{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}
@media(max-width:900px){{.sev-row{{grid-template-columns:repeat(3,1fr)}}}}
.sev-card{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:18px 14px;text-align:center;position:relative;overflow:hidden;transition:.2s}}
.sev-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:12px 12px 0 0}}
.sev-card:hover{{border-color:var(--border2)}}
.sev-card .num{{font-family:'JetBrains Mono',monospace;font-size:38px;font-weight:900;line-height:1}}
.sev-card .lbl{{font-size:10px;color:var(--text3);margin-top:5px;letter-spacing:.8px;text-transform:uppercase;font-weight:600}}
.sev-card .sub{{font-size:9px;color:var(--text3);margin-top:2px}}

/* ── Risk gauge ── */
.risk-gauge{{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%}}
.gauge-num{{font-family:'JetBrains Mono',monospace;font-size:48px;font-weight:900;line-height:1;color:{risk_color}}}
.gauge-label{{font-size:11px;font-weight:700;color:{risk_color};letter-spacing:1.5px;text-transform:uppercase;margin-top:4px}}
.gauge-bar-wrap{{width:100%;background:var(--bg3);border-radius:8px;height:10px;margin-top:16px;overflow:hidden;border:1px solid var(--border)}}
.gauge-bar{{height:100%;background:linear-gradient(90deg,{risk_color}88,{risk_color});border-radius:8px;
  width:{risk_arc_pct}%;transition:width 1s ease}}

/* ── Recon ── */
.recon-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px}}
.recon-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  padding:14px;text-align:center;transition:.2s}}
.recon-card:hover{{border-color:var(--border2)}}
.recon-icon{{font-size:18px;margin-bottom:6px}}
.recon-num{{font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:800;color:var(--cyan)}}
.recon-lbl{{font-size:10px;color:var(--text3);margin-top:3px;letter-spacing:.3px}}
.recon-sub{{font-size:9px;color:var(--text3);opacity:.85;margin-top:2px}}

/* ── Findings table ── */
.filter-bar{{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}}
.filter-btn{{padding:5px 14px;border-radius:20px;font-size:11px;font-weight:600;cursor:pointer;
  border:1px solid var(--border);background:var(--bg3);color:var(--text3);transition:.2s}}
.filter-btn.active,.filter-btn:hover{{background:rgba(99,102,241,.2);border-color:#6366f1;color:#a5b4fc}}
.collapse-all-btn{{padding:6px 12px;border-radius:8px;font-size:11px;font-weight:600;cursor:pointer;
  border:1px solid var(--border);background:var(--bg3);color:var(--text2);transition:.2s;
  display:inline-flex;align-items:center;gap:6px}}
.collapse-all-btn:hover{{background:rgba(34,211,238,.15);border-color:var(--cyan);color:var(--cyan)}}
.tbl-wrap{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;overflow:hidden}}
table{{width:100%;border-collapse:collapse}}
thead tr{{background:var(--bg)}}
th{{padding:11px 16px;font-size:10px;font-weight:700;color:var(--text3);
  text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--border);text-align:left}}
.finding-row td{{vertical-align:middle;padding:10px 16px}}
.finding-row:hover td{{background:rgba(255,255,255,.025)}}
.detail-row td{{background:#050f1c;border-bottom:1px solid var(--border)}}
.toggle-icon{{color:var(--text3);font-size:11px;transition:.2s}}
.finding-row.open .toggle-icon{{transform:rotate(180deg);color:var(--purple)}}
.severity-header-row:hover{{background:rgba(255,255,255,.03)!important}}

/* ── Secrets ── */
.secrets-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:12px}}
.secret-item{{background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--critical);
  border-radius:10px;padding:14px 16px}}
.secret-type-badge{{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:6px;
  font-size:10px;font-weight:700;background:rgba(244,63,94,.12);color:var(--critical);
  border:1px solid rgba(244,63,94,.25);margin-bottom:8px;letter-spacing:.3px}}
.secret-url{{font-size:10px;color:var(--text3);margin-bottom:6px;font-family:'JetBrains Mono',monospace;
  word-break:break-all}}
.secret-val{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#fbbf24;word-break:break-all;
  background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.15);border-radius:5px;
  padding:6px 8px;margin-top:4px}}

/* ── Subdomains ── */
.host-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}}
.host-item{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--cyan);
  display:flex;align-items:center;gap:8px}}
.host-dot{{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0}}
.host-dot.dead{{background:var(--text3)}}

/* ── Footer ── */
.footer{{background:var(--bg2);border-top:1px solid var(--border);padding:24px 48px;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:gap}}
.footer-left{{font-size:12px;color:var(--text3)}}
.footer-right{{display:flex;gap:10px}}

/* ── Print btn ── */
.print-btn{{display:inline-flex;align-items:center;gap:8px;background:rgba(99,102,241,.15);
  border:1px solid rgba(99,102,241,.35);color:#a5b4fc;padding:9px 20px;border-radius:8px;
  font-size:12px;font-weight:600;cursor:pointer;transition:.2s;letter-spacing:.2px}}
.print-btn:hover{{background:rgba(99,102,241,.28)}}

/* ── Scrollbar ── */
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border2);border-radius:3px}}

/* ── Print ── */
@media print{{
  .sidebar,.print-btn,.filter-bar,.no-print{{display:none!important}}
  .main{{margin-left:0}}
  .content{{padding:16px}}
  .hero{{padding:24px;background:#030b15!important}}
  .severity-body-tbody{{display:table-row-group!important}}
  .detail-row{{display:table-row!important}}
  @page{{margin:14mm}}
}}
</style>
</head>
<body>

<!-- Sidebar -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <span class="shield">🛡</span>
    <div class="domain">{sess.domain}</div>
    <div class="sub">Security Assessment</div>
  </div>
  <a class="nav-item" href="#overview">
    <span class="nav-icon">📊</span> Overview
    <span class="nav-badge" style="color:{risk_color}">{risk_label}</span>
  </a>
  <a class="nav-item" href="#recon">
    <span class="nav-icon">🔍</span> Reconnaissance
    <span class="nav-badge">{recon['subdomains']}</span>
  </a>
  <a class="nav-item" href="#findings">
    <span class="nav-icon">🐛</span> Findings
    <span class="nav-badge" style="color:{'#ff2222' if total_vulns else 'var(--green)'}">{total_vulns}</span>
  </a>
  <a class="nav-item" href="#distribution">
    <span class="nav-icon">📈</span> Distribution
  </a>
  {"<a class='nav-item' href='#secrets'><span class='nav-icon'>🔑</span> JS Secrets<span class='nav-badge' style='color:#f43f5e'>" + str(len(secrets)) + "</span></a>" if secrets else ""}
  <a class="nav-item" href="#hosts">
    <span class="nav-icon">🖥</span> Hosts
    <span class="nav-badge">{recon['alive_hosts']}</span>
  </a>
  <hr class="sidebar-sep"/>
  <a class="nav-item" href="#risk">
    <span class="nav-icon">⚠️</span> Risk Assessment
  </a>
  <div style="padding:16px 20px;margin-top:auto">
    <div style="font-size:10px;color:var(--text3);line-height:1.8">
      Generated<br><span style="color:var(--text2)">{now_str}</span>
    </div>
  </div>
</nav>

<!-- Main -->
<div class="main">

  <!-- Hero -->
  <div class="hero" id="top">
    <div class="hero-eyebrow">⚡ Security Assessment Report · Confidential</div>
    <div class="hero-title">{sess.domain}</div>
    <div class="hero-sub">Automated vulnerability assessment — do not distribute</div>
    <div class="hero-pills">
      <div class="pill">&#128197; Generated: <strong>{now_str}</strong></div>
      {_scan_dur_pill}
      <div class="pill">&#128100; Operator: <strong>{scanned_by}</strong></div>
      <div class="pill">&#128027; Findings: <strong style="color:#f87171">{total_vulns}</strong></div>
      <div class="risk-pill">{_risk_icon} Risk: {risk_label} ({risk_score}/100)</div>
      <button class="print-btn no-print" onclick="window.print()">&#128424; Save as PDF</button>
    </div>
  </div>

  <div class="content">

    <!-- ── Overview ── -->
    <section id="overview">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(244,63,94,.15);color:#f43f5e">📊</div>
        <h2>Vulnerability Overview</h2>
      </div>

      <!-- Sev cards -->
      <div class="sev-row" style="margin-bottom:20px">
        <div class="sev-card" style="--c:#ff2222">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#ff2222;border-radius:12px 12px 0 0"></div>
          <div class="num" style="color:#ff2222">{counts.get('critical',0)}</div>
          <div class="lbl">Critical</div>
          <div class="sub">Immediate action</div>
        </div>
        <div class="sev-card">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#f87171;border-radius:12px 12px 0 0"></div>
          <div class="num" style="color:#f87171">{counts.get('high',0)}</div>
          <div class="lbl">High</div>
          <div class="sub">24–48h fix</div>
        </div>
        <div class="sev-card">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#fbbf24;border-radius:12px 12px 0 0"></div>
          <div class="num" style="color:#fbbf24">{counts.get('medium',0)}</div>
          <div class="lbl">Medium</div>
          <div class="sub">Next sprint</div>
        </div>
        <div class="sev-card">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#60a5fa;border-radius:12px 12px 0 0"></div>
          <div class="num" style="color:#60a5fa">{counts.get('low',0)}</div>
          <div class="lbl">Low</div>
          <div class="sub">Backlog</div>
        </div>
        <div class="sev-card">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:#475569;border-radius:12px 12px 0 0"></div>
          <div class="num" style="color:#475569">{counts.get('info',0)}</div>
          <div class="lbl">Info</div>
          <div class="sub">FYI</div>
        </div>
      </div>

      <!-- Dashboard 2-col -->
      <div class="dash-grid">
        <div class="panel">
          <div style="font-size:11px;font-weight:700;color:var(--text3);letter-spacing:.8px;text-transform:uppercase;margin-bottom:16px">Severity Distribution</div>
          {_sev_bars()}
        </div>
        <div class="panel" style="display:flex;flex-direction:column;align-items:center;justify-content:center">
          <div style="font-size:11px;font-weight:700;color:var(--text3);letter-spacing:.8px;text-transform:uppercase;margin-bottom:16px;align-self:flex-start">Overall Risk Score</div>
          <div style="position:relative;width:160px;height:160px">
            <svg viewBox="0 0 160 160" style="width:160px;height:160px;transform:rotate(-90deg)">
              <circle cx="80" cy="80" r="65" fill="none" stroke="#0f172a" stroke-width="18"/>
              <circle cx="80" cy="80" r="65" fill="none" stroke="{risk_color}" stroke-width="18"
                stroke-dasharray="{int(risk_arc_pct/100*408)} 408" stroke-linecap="round"
                style="filter:drop-shadow(0 0 8px {risk_color}66)"/>
            </svg>
            <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
              <div style="font-family:'JetBrains Mono',monospace;font-size:36px;font-weight:900;color:{risk_color};line-height:1">{risk_score}</div>
              <div style="font-size:10px;color:var(--text3);margin-top:2px">/ 100</div>
            </div>
          </div>
          <div style="margin-top:12px;font-size:13px;font-weight:800;color:{risk_color};letter-spacing:1.5px;text-transform:uppercase">{risk_label}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:4px;text-align:center;max-width:160px">
            {_empty_message}
          </div>
        </div>
      </div>
    </section>

    <!-- ── Recon ── -->
    <section id="recon">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(34,211,238,.12);color:var(--cyan)">🔍</div>
        <h2>Reconnaissance Summary</h2>
        <span class="section-badge">Full pipeline stats</span>
      </div>
      <div class="recon-grid">
        <div class="recon-card">
          <div class="recon-icon">🌐</div>
          <div class="recon-num">{recon['subdomains']}</div>
          <div class="recon-lbl">Subdomains Found</div>
          <div class="recon-sub">Unique discovered</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">🖥</div>
          <div class="recon-num" style="color:var(--green)">{recon['alive_hosts']}</div>
          <div class="recon-lbl">Active Hosts</div>
          <div class="recon-sub">Responding endpoints</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">🔌</div>
          <div class="recon-num" style="color:#a78bfa">{recon['open_ports']}</div>
          <div class="recon-lbl">Open Ports</div>
          <div class="recon-sub">Discovered via port scan</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">🔗</div>
          <div class="recon-num" style="color:#fbbf24">{recon['total_urls']}</div>
          <div class="recon-lbl">URLs Collected</div>
          <div class="recon-sub">From all sources</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">📋</div>
          <div class="recon-num" style="color:#38bdf8">{recon['filtered_urls']}</div>
          <div class="recon-lbl">Filtered URLs</div>
          <div class="recon-sub">In-scope, unique</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">⚙️</div>
          <div class="recon-num" style="color:#fb923c">{recon['params']}</div>
          <div class="recon-lbl">Parameter URLs</div>
          <div class="recon-sub">With query params</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">✅</div>
          <div class="recon-num" style="color:var(--green)">{recon['alive_params']}</div>
          <div class="recon-lbl">Alive Param URLs</div>
          <div class="recon-sub">Verified reachable</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">🎯</div>
          <div class="recon-num" style="color:#a78bfa">{recon['scan_targets']}</div>
          <div class="recon-lbl">Scan Targets</div>
          <div class="recon-sub">URLs scanned</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">📁</div>
          <div class="recon-num" style="color:#34d399">{recon['dirs_discovered']}</div>
          <div class="recon-lbl">Directories Found</div>
          <div class="recon-sub">Path discovery</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">📜</div>
          <div class="recon-num" style="color:#e879f9">{recon['js_files']}</div>
          <div class="recon-lbl">JS Files</div>
          <div class="recon-sub">JavaScript assets</div>
        </div>
        <div class="recon-card">
          <div class="recon-icon">🔑</div>
          <div class="recon-num" style="color:{'#f43f5e' if secrets else 'var(--green)'}">{len(secrets)}</div>
          <div class="recon-lbl">JS Secrets</div>
          <div class="recon-sub">API keys, tokens</div>
        </div>
      </div>
      <div class="recon-flow" style="margin-top:20px;padding:16px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;font-size:12px;color:var(--text3)">
        <div style="font-weight:700;color:var(--text2);margin-bottom:10px;letter-spacing:.5px">Pipeline Flow</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
          <span>Subdomains <b style="color:var(--cyan)">{recon['subdomains']}</b></span>
          <span>→</span>
          <span>Alive <b style="color:var(--green)">{recon['alive_hosts']}</b></span>
          <span>→</span>
          <span>URLs <b style="color:#fbbf24">{recon['total_urls']}</b></span>
          <span>→</span>
          <span>Filtered <b style="color:#38bdf8">{recon['filtered_urls']}</b></span>
          <span>→</span>
          <span>Params <b style="color:#fb923c">{recon['params']}</b></span>
          <span>→</span>
          <span>Alive Params <b style="color:var(--green)">{recon['alive_params']}</b></span>
          <span>→</span>
          <span>Scanned <b style="color:#a78bfa">{recon['scan_targets']}</b></span>
        </div>
      </div>
    </section>

    <!-- ── Findings ── -->
    <section id="findings">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(139,92,246,.15);color:var(--purple)">🐛</div>
        <h2>Vulnerability Findings</h2>
        <span class="section-badge">{min(len(all_findings),500)} of {len(all_findings)}</span>
      </div>

      <!-- Filter buttons + Collapse All -->
      <div class="filter-bar no-print" style="align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
        <div style="display:flex;gap:8px;flex-wrap:wrap">{_filter_btns}</div>
        <div style="display:flex;gap:6px">
          <button class="collapse-all-btn" onclick="collapseAllFindings()" title="Collapse all findings">
            <i class="fa-solid fa-compress"></i> Collapse All
          </button>
          <button class="collapse-all-btn" onclick="expandAllFindings()" title="Expand all findings">
            <i class="fa-solid fa-expand"></i> Expand All
          </button>
        </div>
      </div>

      <div class="tbl-wrap" id="findings-tbl">
        <table id="findings-table">
          <thead>
            <tr>
              <th style="width:110px">Severity</th>
              <th>Vulnerability</th>
              <th style="width:38%">Affected URL</th>
              <th style="width:28px"></th>
            </tr>
          </thead>
          {_finding_rows_detailed() if all_findings else '<tbody id="findings-tbody">' + _no_vuln_row + '</tbody>'}
        </table>
      </div>
    </section>

    <!-- ── Distribution ── -->
    <section id="distribution">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(99,102,241,.15);color:#6366f1">📈</div>
        <h2>Attack Surface Distribution</h2>
      </div>
      <div class="panel" style="max-width:700px">
        <div style="font-size:11px;font-weight:700;color:var(--text3);letter-spacing:.8px;text-transform:uppercase;margin-bottom:18px">Top Vulnerability Types</div>
        {_type_bars()}
      </div>
    </section>

    {_sec_html}

    <!-- ── Hosts ── -->
    <section id="hosts">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(34,197,94,.1);color:var(--green)">&#128187;</div>
        <h2>Discovered Hosts</h2>
        <span class="section-badge">{recon['subdomains']} total &middot; {recon['alive_hosts']} alive</span>
      </div>
      {_hosts_html}
    </section>

    <!-- ── Risk Assessment ── -->
    <section id="risk">
      <div class="section-header">
        <div class="section-icon" style="background:rgba(251,191,36,.1);color:#fbbf24">&#9888;&#65039;</div>
        <h2>Risk Assessment &amp; Recommendations</h2>
      </div>
      <div style="display:flex;flex-direction:column;gap:12px">
        {_risk_blocks}
      </div>
    </section>

  </div><!-- /content -->

  <!-- Footer -->
  <div class="footer no-print">
    <div class="footer-left">
      🛡 Security Assessment Report &nbsp;·&nbsp; {sess.domain} &nbsp;·&nbsp; {now_str}<br>
      <span style="color:var(--text3);font-size:10px">⚠ Confidential — for authorised personnel only. Do not distribute.</span>
    </div>
    <div class="footer-right">
      <button class="print-btn" onclick="window.print()">🖨 Save as PDF</button>
    </div>
  </div>
</div><!-- /main -->

<script>
// ── Severity group accordion (level 1: Critical, High, etc.) ─
function toggleSeverityGroup(tr) {{
  const tbody = tr.closest('tbody');
  const next = tbody.nextElementSibling;
  if (!next || !next.classList.contains('severity-body-tbody')) return;
  const isOpen = next.style.display !== 'none';
  next.style.display = isOpen ? 'none' : 'table-row-group';
  const arrow = tr.querySelector('.sev-arrow');
  if (arrow) arrow.textContent = isOpen ? '▶' : '▼';
  tr.classList.toggle('open', !isOpen);
}}

// ── Per-finding detail (level 2: description, remediation) ─
function toggleDetail(tr) {{
  const detail = tr.nextElementSibling;
  if (!detail || !detail.classList.contains('detail-row')) return;
  const isOpen = detail.style.display !== 'none';
  detail.style.display = isOpen ? 'none' : 'table-row';
  tr.classList.toggle('open', !isOpen);
  const icon = tr.querySelector('.toggle-icon');
  if (icon) icon.textContent = isOpen ? '▼' : '▲';
}}

// ── Findings filter ─────────────────────────────────────────
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.severity-header-tbody').forEach(tb => {{
    const s = tb.dataset.sev;
    tb.style.display = (sev === 'all' || s === sev) ? '' : 'none';
  }});
  document.querySelectorAll('.severity-body-tbody').forEach(tb => {{
    const s = tb.dataset.sev;
    const show = (sev === 'all' || s === sev);
    if (!show) {{ tb.style.display = 'none'; return; }}
    const prev = tb.previousElementSibling;
    const headerOpen = prev?.querySelector('.severity-header-row.open');
    tb.style.display = headerOpen ? 'table-row-group' : 'none';
  }});
}}

// ── Collapse All: thu gọn cả nhóm severity + chi tiết từng lỗ ─
function collapseAllFindings() {{
  document.querySelectorAll('.severity-body-tbody').forEach(tb => {{ tb.style.display = 'none'; }});
  document.querySelectorAll('.severity-header-row').forEach(tr => {{
    tr.classList.remove('open');
    const arrow = tr.querySelector('.sev-arrow');
    if (arrow) arrow.textContent = '▶';
  }});
  document.querySelectorAll('.finding-row').forEach(tr => {{
    const detail = tr.nextElementSibling;
    if (detail && detail.classList.contains('detail-row')) {{
      detail.style.display = 'none';
      tr.classList.remove('open');
    }}
    const icon = tr.querySelector('.toggle-icon');
    if (icon) icon.textContent = '▼';
  }});
}}
// ── Expand All: mở tất cả nhóm severity + chi tiết từng lỗ ─
function expandAllFindings() {{
  document.querySelectorAll('.severity-header-tbody').forEach(tb => {{
    if (tb.style.display === 'none') return;
    const headerRow = tb.querySelector('.severity-header-row');
    const bodyTb = tb.nextElementSibling;
    if (headerRow && bodyTb?.classList.contains('severity-body-tbody')) {{
      headerRow.classList.add('open');
      const arrow = headerRow.querySelector('.sev-arrow');
      if (arrow) arrow.textContent = '▼';
      bodyTb.style.display = 'table-row-group';
    }}
  }});
  document.querySelectorAll('.finding-row').forEach(tr => {{
    const detail = tr.nextElementSibling;
    if (detail && detail.classList.contains('detail-row')) {{
      detail.style.display = 'table-row';
      tr.classList.add('open');
    }}
    const icon = tr.querySelector('.toggle-icon');
    if (icon) icon.textContent = '▲';
  }});
}}

// ── Active nav on scroll ─────────────────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks  = document.querySelectorAll('.nav-item');
window.addEventListener('scroll', () => {{
  let cur = '';
  sections.forEach(s => {{ if (window.scrollY >= s.offsetTop - 80) cur = s.id; }});
  navLinks.forEach(a => {{
    a.classList.toggle('active', a.getAttribute('href') === '#' + cur);
  }});
}}, {{passive:true}});
</script>
</body>
</html>"""

    from flask import Response as _Resp
    return _Resp(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="report_{sess.domain}_{_dt.utcnow().strftime("%Y%m%d_%H%M")}.html"'},
    )


# ── Export: CSV ────────────────────────────────────────────────────────────
@app.route("/api/scan/<scan_id>/export/csv")
@login_required
def export_csv(scan_id: str):
    sess = _get_own_scan(scan_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404

    out_dir = _get_out_dir(sess.username, sess.domain)

    all_findings = sc.parse_nuclei_json(os.path.join(out_dir, "findings.json"))
    extra_files = [
        "cors_findings.json", "ssrf_findings.json", "ssti_findings.json",
        "bypass_findings.json", "takeover_findings.json", "graphql_findings.json",
        "jwt_findings.json", "lfi_findings.json", "xxe_findings.json",
        "race_findings.json", "upload_findings.json", "xss_findings.json",
        "sqli_findings.json", "idor_findings.json", "hostheader_findings.json",
        "redirect_findings.json",
    ]
    for ef in extra_files:
        fp = os.path.join(out_dir, ef)
        if os.path.exists(fp):
            try:
                with open(fp, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_findings.extend(data)
            except Exception:
                pass

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "name", "type", "matched_url", "matcher", "description"])
    for f in all_findings:
        sev  = (f.get("info", {}).get("severity") or f.get("severity") or "info").lower()
        name = (f.get("info", {}).get("name") or f.get("description") or
                f.get("template-id") or f.get("type") or "")
        ftype = f.get("type") or f.get("template-id") or ""
        url   = f.get("matched-at") or f.get("url") or ""
        match = f.get("matcher-name") or ""
        desc  = f.get("description") or f.get("info", {}).get("description") or ""
        writer.writerow([sev, name, ftype, url, match, desc])

    from datetime import datetime as _dt
    from flask import Response as _Resp
    return _Resp(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings_{sess.domain}_{_dt.utcnow().strftime("%Y%m%d_%H%M")}.csv"'},
    )


@app.route("/api/scans", methods=["GET"])
@login_required
def list_scans():
    username = session["username"]
    role     = session.get("role")
    with SCANS_LOCK:
        if role == "admin":
            result = [s.to_dict() for s in SCANS.values()]
        else:
            result = [s.to_dict() for s in SCANS.values() if s.username == username]
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════
#  API — TOOLS & DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/tools")
@login_required
def check_tools():
    """Return module status with friendly names only — no tool paths exposed."""
    config   = sc.load_config()
    env_path = sc._build_env().get("PATH")

    def _check(tool_name: str) -> bool:
        path = config["tools"].get(tool_name, tool_name)
        found = bool(shutil.which(path, path=env_path))
        if not found and tool_name == "httpx":
            found = bool(sc._resolve_httpx_tool(config))
        return found

    def _check_nmap() -> bool:
        return bool(shutil.which("nmap", path=env_path))

    # Return friendly names — no internal tool names
    result = {
        "Domain Enumerator":  _check("subfinder"),
        "Host Prober":        _check("httpx"),
        "Port Scanner":       _check_nmap(),
        "Vuln Engine":        _check("nuclei"),
        "Web Crawler":        _check("katana"),
        "Archive Crawler":    _check("waybackurls"),
        "URL Gatherer":       _check("gau"),
        "Asset Discovery":    _check("assetfinder"),
        "Dir Scanner":        _check("dirsearch"),
        "XSS Scanner":        _check("dalfox"),
        "Injection Tester":   _check("sqlmap"),
    }
    return jsonify(result)


@app.route("/api/diagnose")
@admin_required  # Admin only — sensitive info
def diagnose():
    """Full diagnostic info — admin only."""
    env      = sc._build_env()
    env_path = env.get("PATH", "")
    info = {
        "go_version":   None,
        "httpx_binary": sc._resolve_httpx_tool(sc.load_config()),
        "tools":        {},
    }
    go_bin = shutil.which("go", path=env_path)
    if go_bin:
        try:
            out = subprocess.check_output([go_bin, "version"], text=True, timeout=5, env=env)
            info["go_version"] = out.strip()
        except Exception:
            pass
    for tool in sc.REQUIRED_TOOLS + sc.OPTIONAL_TOOLS + ["httpx-toolkit"]:
        info["tools"][tool] = shutil.which(tool, path=env_path) or "NOT FOUND"
    return jsonify(info)




@app.route("/api/history")
@login_required
def scan_history():
    username = session["username"]
    role     = session.get("role")
    output_dir = Path("output")
    domains = []

    if not output_dir.exists():
        return jsonify([])

    search_dirs = list(output_dir.iterdir()) if role == "admin" else [output_dir / username]
    for user_dir in search_dirs:
        if not user_dir.is_dir():
            continue
        for d in sorted(user_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir():
                report = d / "scan_report.json"
                if report.exists():
                    try:
                        with open(report) as f:
                            data = json.load(f)
                        data["owner"] = user_dir.name
                        data["folder"] = d.name
                        domains.append(data)
                    except Exception:
                        domains.append({"domain": d.name, "folder": d.name, "owner": user_dir.name})

    return jsonify(domains)


@app.route("/api/history/<owner>/<folder>", methods=["DELETE"])
@login_required
def delete_history(owner: str, folder: str):
    """Delete a scan history entry and its output files."""
    username = session["username"]
    role     = session.get("role")
    # Only allow admin or scan owner to delete
    if role != "admin" and owner != username:
        return jsonify({"error": "Forbidden"}), 403
    # Sanitise path components
    if "/" in owner or "\\" in owner or "/" in folder or "\\" in folder:
        return jsonify({"error": "Invalid path"}), 400
    scan_dir = Path("output") / owner / folder
    if not scan_dir.exists() or not scan_dir.is_dir():
        return jsonify({"error": "Not found"}), 404
    import shutil as _shutil
    try:
        _shutil.rmtree(scan_dir)
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history/<owner>/<folder>/load")
@login_required
def load_history_session(owner: str, folder: str):
    """
    Create a read-only in-memory session from saved scan files so the
    frontend can use the existing /api/scan/<id>/results and file endpoints.
    """
    username = session["username"]
    role     = session.get("role")
    if role != "admin" and owner != username:
        return jsonify({"error": "Forbidden"}), 403
    if "/" in owner or "\\" in owner or "/" in folder or "\\" in folder:
        return jsonify({"error": "Invalid path"}), 400

    scan_dir = Path("output") / owner / folder
    if not scan_dir.exists():
        return jsonify({"error": "Not found"}), 404

    # Re-use or create an ephemeral session for viewing
    session_key = f"hist:{owner}:{folder}"
    with SCANS_LOCK:
        existing = next((s for s in SCANS.values()
                         if getattr(s, "_history_key", None) == session_key), None)
        if existing:
            return jsonify({"scan_id": existing.scan_id})

    report_path = scan_dir / "scan_report.json"
    counts: dict = {}
    summary: dict = {}
    domain = folder
    try:
        with open(report_path) as f:
            rdata = json.load(f)
        counts  = rdata.get("counts", {})
        summary = rdata.get("vulnerability_summary", {})
        domain  = rdata.get("domain", folder)
    except Exception:
        pass

    hist_id = "hist-" + str(uuid.uuid4())[:8]
    # Use folder as domain so _get_out_dir resolves to the correct path on disk
    sess = ScanSession(hist_id, folder, owner, {})
    sess.status    = "done"
    sess.summary   = summary
    sess.counts    = counts
    sess.username  = owner
    sess._history_key = session_key  # type: ignore[attr-defined]
    with SCANS_LOCK:
        SCANS[hist_id] = sess
    return jsonify({"scan_id": hist_id, "domain": domain})


# ═══════════════════════════════════════════════════════════════════════════
#  API — ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    users = load_users()
    safe  = {u: {k: v for k, v in d.items() if k != "password"} for u, d in users.items()}
    return jsonify(safe)


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if not re.match(r"^[a-zA-Z0-9_]{3,32}$", username):
        return jsonify({"error": "Invalid username (3-32 alphanumeric chars)"}), 400

    if create_user(username, password, role):
        return jsonify({"status": "created", "username": username})
    return jsonify({"error": "User already exists"}), 409


@app.route("/api/admin/users/<username>", methods=["DELETE"])
@admin_required
def admin_delete_user(username: str):
    if username == session.get("username"):
        return jsonify({"error": "Cannot delete yourself"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "Not found"}), 404
    del users[username]
    save_users(users)
    return jsonify({"status": "deleted"})


@app.route("/api/admin/users/<username>/password", methods=["PUT"])
@admin_required
def admin_change_password(username: str):
    data = request.get_json(silent=True) or {}
    new_pass = data.get("password", "")
    if not new_pass or len(new_pass) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "Not found"}), 404
    users[username]["password"] = generate_password_hash(new_pass)
    save_users(users)
    return jsonify({"status": "updated"})


@app.route("/api/me/password", methods=["PUT"])
@login_required
def change_own_password():
    data     = request.get_json(silent=True) or {}
    old_pass = data.get("old_password", "")
    new_pass = data.get("new_password", "")

    if not new_pass or len(new_pass) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    user = get_user(session["username"])
    if not check_password_hash(user["password"], old_pass):
        return jsonify({"error": "Current password incorrect"}), 403

    users = load_users()
    users[session["username"]]["password"] = generate_password_hash(new_pass)
    save_users(users)
    return jsonify({"status": "updated"})


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _get_own_scan(scan_id: str) -> Optional[ScanSession]:
    """Return scan if it belongs to current user (or user is admin)."""
    with SCANS_LOCK:
        sess = SCANS.get(scan_id)
    if not sess:
        return None
    if session.get("role") == "admin" or sess.username == session.get("username"):
        return sess
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  TELEGRAM CONFIG
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/telegram", methods=["GET"])
@login_required
def get_telegram():
    cfg = load_telegram_config()
    # Never expose the real token to non-admins; just return enabled + masked token
    token = cfg.get("bot_token", "")
    masked = (token[:6] + "..." + token[-4:]) if len(token) > 10 else ("*" * len(token))
    return jsonify({
        "enabled":   cfg.get("enabled", False),
        "bot_token": masked if session.get("role") != "admin" else token,
        "chat_id":   cfg.get("chat_id", ""),
    })


@app.route("/api/telegram", methods=["POST"])
@login_required
def set_telegram():
    """Admin-only: persist Telegram config; regular users: test only."""
    data     = request.get_json(silent=True) or {}
    token    = data.get("bot_token", "").strip()
    chat_id  = data.get("chat_id", "").strip()
    enabled  = bool(data.get("enabled", False))

    if not token or not chat_id:
        return jsonify({"error": "bot_token and chat_id are required"}), 400

    # Validate by sending a test message
    test_msg = "✅ Notification connection verified from Security Scanner."
    try:
        import urllib.request as _ureq
        import urllib.parse as _up
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = _up.urlencode({"chat_id": chat_id, "text": test_msg}).encode()
        req     = _ureq.Request(url, data=payload, method="POST")
        with _ureq.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
        if not result.get("ok"):
            return jsonify({"error": "Telegram API error: " + result.get("description", "unknown")}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not reach Telegram: {exc}"}), 400

    save_telegram_config({"enabled": enabled, "bot_token": token, "chat_id": chat_id})
    return jsonify({"status": "saved", "message": "Telegram configured and test message sent."})


@app.route("/api/telegram/test", methods=["POST"])
@login_required
def test_telegram():
    cfg = load_telegram_config()
    if not cfg.get("enabled") or not cfg.get("bot_token") or not cfg.get("chat_id"):
        return jsonify({"error": "Telegram not configured"}), 400
    try:
        import urllib.request as _ureq
        import urllib.parse as _up
        token   = cfg["bot_token"]
        chat_id = cfg["chat_id"]
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = _up.urlencode({"chat_id": chat_id, "text": "🔔 Test notification from Security Scanner."}).encode()
        req     = _ureq.Request(url, data=payload, method="POST")
        with _ureq.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
        if not result.get("ok"):
            return jsonify({"error": result.get("description", "unknown")}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"status": "sent"})


# ═══════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return redirect(url_for("index"))


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {e}")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal error"}), 500
    return redirect(url_for("index"))


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BugBounty AutoScanner Web UI")
    parser.add_argument("--host",  default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    _ensure_default_admin()
    _start_cleanup_thread()

    print(f"""
\033[96m╔══════════════════════════════════════════════════════╗
║   BugBounty AutoScanner — Production Web UI          ║
║   http://{args.host}:{args.port:<5}                            ║
╚══════════════════════════════════════════════════════╝\033[0m
""")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
