#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   BugBounty AutoScanner — Production Startup Script         ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }
info() { echo -e "${CYAN}[*]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   BugBounty AutoScanner — Starting Production        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Config ─────────────────────────────────────────────────────
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
WORKERS="${WORKERS:-4}"
TIMEOUT="${TIMEOUT:-300}"
SECRET_KEY="${SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
export SECRET_KEY HOST PORT

# ── Go PATH ────────────────────────────────────────────────────
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin:/root/go/bin"

# ── Create directories ─────────────────────────────────────────
mkdir -p output logs

# ── Check Python deps ──────────────────────────────────────────
if ! python3 -c "import flask, werkzeug, yaml" 2>/dev/null; then
    warn "Installing Python dependencies..."
    pip3 install -r requirements.txt --break-system-packages -q
fi

# ── Create default admin if needed ────────────────────────────
if [ ! -f users.json ]; then
    RANDOM_PASS=$(python3 -c "import secrets, string; alphabet = string.ascii_letters + string.digits; print(''.join(secrets.choice(alphabet) for i in range(12)))")
    ADMIN_PASSWORD="${ADMIN_PASSWORD:-$RANDOM_PASS}"
    export ADMIN_PASSWORD
    warn "No users.json found !"
    warn ">> WEB UI ADMIN CREATED: Username: admin | Password: ${ADMIN_PASSWORD} <<"
    warn "Change it via Web UI or run: python3 setup_users.py"
fi

info "Starting server on ${HOST}:${PORT} (workers: ${WORKERS})"
info "Press CTRL+C to stop"
echo ""

# ── Run with gunicorn if available, else Flask dev ────────────
if command -v gunicorn &>/dev/null; then
    ok "Using gunicorn (production mode)"
    exec gunicorn \
        --bind "${HOST}:${PORT}" \
        --workers "${WORKERS}" \
        --threads 2 \
        --worker-class gthread \
        --timeout "${TIMEOUT}" \
        --keep-alive 5 \
        --access-logfile "logs/access.log" \
        --error-logfile "logs/error.log" \
        --log-level info \
        --capture-output \
        --forwarded-allow-ips='*' \
        app:app
else
    warn "gunicorn not found — using Flask dev server (not recommended for production)"
    warn "Install gunicorn: pip3 install gunicorn --break-system-packages"
    exec python3 app.py --host "${HOST}" --port "${PORT}"
fi
