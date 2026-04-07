#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║        BugBounty AutoScanner — One-Click Installer          ║
# ║        Kali Linux / Debian / Ubuntu                         ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }
info() { echo -e "${CYAN}[*]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "${RED}[✗]${RESET} $1"; }

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          BugBounty AutoScanner — Installer               ║"
echo "║   Includes: Recon · XSS · SQLi · SSRF · CORS · JWT      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ──────────────────────────────────────────────────────────────
# 1. APT UPDATE
# ──────────────────────────────────────────────────────────────
info "Updating apt cache..."
apt update -y --fix-missing 2>/dev/null || warn "apt update had warnings, continuing..."
ok "apt cache updated"

# ──────────────────────────────────────────────────────────────
# 2. CÀI GO (nếu chưa có)
# ──────────────────────────────────────────────────────────────
if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
else
    info "Installing Go from official source..."

    GO_VERSION="1.24.1"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"

    # Xoá bản cũ nếu có
    rm -rf /usr/local/go

    info "Downloading Go ${GO_VERSION}..."
    wget -q --show-progress "${GO_URL}" -O "/tmp/${GO_TAR}"

    info "Extracting Go..."
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    # Thêm Go vào PATH (bash + zsh)
    GO_PATH_LINE='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'

    for RC in ~/.bashrc ~/.zshrc; do
        if [ -f "$RC" ] && ! grep -q "/usr/local/go/bin" "$RC"; then
            echo "$GO_PATH_LINE" >> "$RC"
        fi
    done

    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    ok "Go installed: $(go version)"
fi

# Đảm bảo go/bin trong PATH cho session hiện tại
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

# ──────────────────────────────────────────────────────────────
# 3. CÀI PYTHON PACKAGES
# ──────────────────────────────────────────────────────────────
info "Installing Python packages..."
pip3 install -r requirements.txt --break-system-packages -q
ok "Python packages installed (flask, requests, pyyaml)"

# ──────────────────────────────────────────────────────────────
# 4. CÀI GO TOOLS
# ──────────────────────────────────────────────────────────────
info "Installing Go-based recon tools (this may take a few minutes)..."

install_go_tool() {
    local name=$1
    local pkg=$2
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
    else
        info "Installing $name..."
        go install "${pkg}@latest" 2>/dev/null && ok "$name installed" || warn "$name failed — skipping"
    fi
}

install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "dalfox"      "github.com/hahwul/dalfox/v2"
install_go_tool "gf"          "github.com/tomnomnom/gf"

# Install gf patterns (required for gf to work)
if command -v gf &>/dev/null; then
    if [ ! -d ~/.gf ]; then
        info "Installing gf patterns..."
        mkdir -p ~/.gf
        git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns -q 2>/dev/null \
        && cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null \
        && ok "gf patterns installed" \
        || warn "gf patterns install failed — built-in fallback will be used"
    else
        ok "gf patterns already exist"
    fi
fi

# ──────────────────────────────────────────────────────────────
# 5. CÀI DIRSEARCH (optional)
# ──────────────────────────────────────────────────────────────
if command -v dirsearch &>/dev/null || python3 -m dirsearch --version &>/dev/null 2>&1; then
    ok "dirsearch already installed"
else
    info "Installing dirsearch..."
    pip3 install dirsearch --break-system-packages -q 2>/dev/null \
    && ok "dirsearch installed" \
    || {
        warn "pip install failed, trying apt..."
        apt install dirsearch -y -q 2>/dev/null && ok "dirsearch installed via apt" || warn "dirsearch failed — skipping (optional)"
    }
fi

# ──────────────────────────────────────────────────────────────
# 5b. CÀI SQLMAP (optional but recommended)
# ──────────────────────────────────────────────────────────────
if command -v sqlmap &>/dev/null || python3 -m sqlmap --version &>/dev/null 2>&1; then
    ok "sqlmap already installed"
else
    info "Installing sqlmap..."
    apt install sqlmap -y -q 2>/dev/null && ok "sqlmap installed via apt" \
    || {
        pip3 install sqlmap --break-system-packages -q 2>/dev/null && ok "sqlmap installed via pip" \
        || warn "sqlmap failed — optional, skipping"
    }
fi

# ──────────────────────────────────────────────────────────────
# 6. KIỂM TRA httpx-toolkit (đặc thù Kali apt)
# ──────────────────────────────────────────────────────────────
# Nếu không tìm thấy httpx nhưng có httpx-toolkit, tự sửa config
if ! command -v httpx &>/dev/null && command -v httpx-toolkit &>/dev/null; then
    warn "Found 'httpx-toolkit' instead of 'httpx' — updating config.yaml..."
    sed -i 's/httpx:       httpx/httpx:       httpx-toolkit/' config.yaml
    ok "config.yaml updated: httpx → httpx-toolkit"
fi

# ──────────────────────────────────────────────────────────────
# 7. UPDATE NUCLEI TEMPLATES
# ──────────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated" || warn "Nuclei template update failed (will retry on first scan)"
fi

# ──────────────────────────────────────────────────────────────
# 8. FIX ZSH HISTORY (nếu bị corrupt)
# ──────────────────────────────────────────────────────────────
if [ -f ~/.zsh_history ]; then
    if ! strings ~/.zsh_history > /tmp/zsh_history_clean 2>/dev/null; then
        mv ~/.zsh_history ~/.zsh_history.bak
        mv /tmp/zsh_history_clean ~/.zsh_history
        ok "zsh_history fixed"
    fi
fi

# ──────────────────────────────────────────────────────────────
# 9. TỔNG KẾT
# ──────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Tool Status Check${RESET}"
echo -e "${CYAN}══════════════════════════════════════════${RESET}"

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} $1"
    else
        echo -e "  ${RED}✗${RESET} $1 — NOT FOUND"
    fi
}

check_tool subfinder
check_tool httpx
check_tool httpx-toolkit
check_tool nuclei
check_tool katana
check_tool waybackurls
check_tool gau
check_tool assetfinder
check_tool dirsearch
check_tool dalfox
check_tool sqlmap
check_tool gf
check_tool python3

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation Complete!${RESET}"
echo -e "${GREEN}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Run Web UI  :  ${CYAN}python3 app.py${RESET}"
echo -e "  Open browser:  ${CYAN}http://127.0.0.1:5000${RESET}"
echo -e "  Run CLI     :  ${CYAN}python3 scanner.py example.com${RESET}"
echo ""
echo -e "${YELLOW}  NOTE: Run 'source ~/.zshrc' to refresh PATH if tools not found${RESET}"
echo ""
