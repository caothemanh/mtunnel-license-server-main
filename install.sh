#!/bin/bash
# ═══════════════════════════════════════════════════════════
# MTunnel License Server - Auto Install
# Chạy: sudo bash install.sh
# hoặc: bash <(curl -s https://raw.githubusercontent.com/USER/REPO/main/install.sh)
# ═══════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✅]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠️]${NC} $1"; }
error() { echo -e "${RED}[❌]${NC} $1"; exit 1; }
info()  { echo -e "${CYAN}[ℹ️]${NC} $1"; }

INSTALL_DIR="/opt/mtunnel"
TOKEN_FILE="$INSTALL_DIR/.token"
CONFIG_FILE="$INSTALL_DIR/.config"

[ "$EUID" -ne 0 ] && error "Vui long chay voi sudo: sudo bash install.sh"

clear
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${BOLD}   MTunnel License Server - Auto Install   ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""

# ── Nhập thông tin cài đặt ──────────────────────────────────
printf "${CYAN}Nhap domain${NC} [vd: license.example.com]: "
read DOMAIN
printf "${CYAN}Nhap email${NC} [cho SSL cert]: "
read EMAIL
printf "${CYAN}Nhap package name${NC} [vd: com.example.app]: "
read PACKAGE

[ -z "$DOMAIN"  ] && error "Domain khong duoc de trong"
[ -z "$EMAIL"   ] && error "Email khong duoc de trong"
[ -z "$PACKAGE" ] && error "Package name khong duoc de trong"

echo ""
info "Token se duoc thiet lap sau khi cai dat xong"
echo ""

# ── Nhập cấu hình GitHub cho /api/config (tùy chọn) ─────────
echo -e "${CYAN}${BOLD}--- Dong bo file config tu GitHub (tuy chon) ---${NC}"
echo -e "${YELLOW}Dung cho endpoint /api/config. Bo trong neu chua dung, co the thiet lap sau${NC}"
echo -e "${YELLOW}bang cach tao thu cong 2 file .github_repo va .github_token trong $INSTALL_DIR${NC}"
echo ""
printf "${CYAN}GitHub owner${NC} [vd: caothemanh]: "
read GH_OWNER
printf "${CYAN}GitHub repo${NC} [vd: mtunnel-config]: "
read GH_REPO
printf "${CYAN}Branch${NC} [main]: "
read GH_BRANCH
GH_BRANCH=${GH_BRANCH:-main}
printf "${CYAN}Duong dan file trong repo${NC} [vd: config.enc]: "
read GH_PATH
printf "${CYAN}GitHub Personal Access Token (PAT, an khi go)${NC}: "
read -s GH_TOKEN
echo ""
echo ""

# ── 1. Cài packages ─────────────────────────────────────────
log "Cai dat dependencies..."
apt update -qq
apt install -y python3-pip nginx certbot python3-certbot-nginx curl > /dev/null 2>&1
pip3 install flask gunicorn gevent cryptography -q
log "Dependencies da cai xong"

# ── 2. Tạo thư mục ──────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

# ── 3. Lưu config ───────────────────────────────────────────
cat > "$CONFIG_FILE" << CFGEOF
DOMAIN=$DOMAIN
PACKAGE=$PACKAGE
CFGEOF
chmod 600 "$CONFIG_FILE"
log "Config da luu"

# ── 3b. Lưu cấu hình GitHub (nếu người dùng đã nhập) ────────
if [ -n "$GH_OWNER" ] && [ -n "$GH_REPO" ] && [ -n "$GH_PATH" ] && [ -n "$GH_TOKEN" ]; then
    cat > "$INSTALL_DIR/.github_repo" << GHEOF
OWNER=$GH_OWNER
REPO=$GH_REPO
BRANCH=$GH_BRANCH
PATH=$GH_PATH
GHEOF
    chmod 600 "$INSTALL_DIR/.github_repo"

    echo "$GH_TOKEN" > "$INSTALL_DIR/.github_token"
    chmod 600 "$INSTALL_DIR/.github_token"

    log "Da luu cau hinh GitHub (owner=$GH_OWNER repo=$GH_REPO branch=$GH_BRANCH)"
else
    warn "Bo qua cau hinh GitHub — /api/config se tra loi 500 (config_unavailable)"
    warn "cho toi khi ban tao thu cong:"
    warn "  $INSTALL_DIR/.github_repo   (OWNER=... / REPO=... / BRANCH=... / PATH=...)"
    warn "  $INSTALL_DIR/.github_token  (Personal Access Token)"
fi

# ── 4. Download server.py từ GitHub ────────────────────────
log "Download server.py..."
GITHUB_RAW="https://raw.githubusercontent.com/caothemanh/mtunnel-license-server-main/main"
curl -fsSL "$GITHUB_RAW/server.py" -o "$INSTALL_DIR/server.py"
log "server.py da tai xong"

# ── 5. Tạo update_token.sh ──────────────────────────────────
log "Tao script quan ly token..."
cat > "$INSTALL_DIR/update_token.sh" << 'TKEOF'
#!/bin/bash
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/mtunnel"
TOKEN_FILE="$INSTALL_DIR/.token"
CONFIG_FILE="$INSTALL_DIR/.config"

# Đọc config
PACKAGE=""
DOMAIN=""
if [ -f "$CONFIG_FILE" ]; then
    PACKAGE=$(grep "^PACKAGE=" "$CONFIG_FILE" | cut -d= -f2)
    DOMAIN=$(grep "^DOMAIN=" "$CONFIG_FILE" | cut -d= -f2)
fi

clear
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   MTunnel - Thiet lap Token               ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  Package : ${CYAN}$PACKAGE${NC}"
echo -e "  Domain  : ${CYAN}$DOMAIN${NC}"
echo ""

if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
    CURRENT=$(cat "$TOKEN_FILE")
    echo -e "${YELLOW}Token hien tai:${NC} ${CURRENT:0:8}...${CURRENT: -4}"
    echo ""
fi

echo -e "${CYAN}Huong dan lay token:${NC}"
echo "  1. Build release APK (cung keystore)"
echo "  2. Chay app tren thiet bi"
echo "  3. Token hien trong AlertDialog luc khoi dong"
echo "  4. Copy token roi paste vao day"
echo ""
read -p "Nhap token moi: " NEW_TOKEN

if [ -z "$NEW_TOKEN" ]; then
    echo -e "${RED}Token khong duoc de trong!${NC}"
    exit 1
fi

echo "$NEW_TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
chown www-data:www-data "$TOKEN_FILE" 2>/dev/null || true
systemctl restart mtunnel-license 2>/dev/null || true

echo ""
echo -e "${GREEN}${BOLD}✅ Token da cap nhat thanh cong!${NC}"
echo -e "   Token   : ${NEW_TOKEN:0:8}...${NEW_TOKEN: -4}"
echo -e "   Package : $PACKAGE"
echo ""
echo "Lenh quan ly:"
echo "  Xem log  : journalctl -u mtunnel-license -f"
echo "  Doi token: mtunnel-token"
echo ""
TKEOF

chmod +x "$INSTALL_DIR/update_token.sh"
ln -sf "$INSTALL_DIR/update_token.sh" /usr/local/bin/mtunnel-token
log "Script quan ly token da tao — lenh: mtunnel-token"

# ── 6. Systemd service ──────────────────────────────────────
log "Tao systemd service..."
cat > /etc/systemd/system/mtunnel-license.service << SVCEOF
[Unit]
Description=MTunnel License Server
After=network.target

[Service]
User=www-data
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/gunicorn -w 1 -k gevent --worker-connections 100 -b 127.0.0.1:5000 server:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

chown -R www-data:www-data "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable mtunnel-license
systemctl start mtunnel-license
log "Service da khoi dong"

# ── 6b. Tạo script hiển thị Server Public Key (Ed25519) ─────
cat > "$INSTALL_DIR/print_pubkey.py" << 'PYEOF'
#!/usr/bin/env python3
import base64, hashlib, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SIGNING_KEY_FILE = "/opt/mtunnel/.signing_key"

try:
    with open(SIGNING_KEY_FILE, "rb") as f:
        raw = f.read()
except FileNotFoundError:
    print("ERROR: chua tim thay signing key, service co the chua khoi dong xong", file=sys.stderr)
    sys.exit(1)

key = Ed25519PrivateKey.from_private_bytes(raw)
pub_raw = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print(f"SERVER_PUBLIC_KEY_B64={base64.b64encode(pub_raw).decode()}")
print(f"PINNED_PUBKEY_SHA256={hashlib.sha256(pub_raw).hexdigest()}")
PYEOF
chmod +x "$INSTALL_DIR/print_pubkey.py"
ln -sf "$INSTALL_DIR/print_pubkey.py" /usr/local/bin/mtunnel-pubkey
log "Script hien thi public key da tao — lenh: mtunnel-pubkey"

# ── 6c. Doi signing key duoc tao (server tao luc khoi dong) ─
log "Doi service tao signing key..."
for i in $(seq 1 10); do
    [ -f "$INSTALL_DIR/.signing_key" ] && break
    sleep 1
done

if [ -f "$INSTALL_DIR/.signing_key" ]; then
    PUBKEY_OUT=$(python3 "$INSTALL_DIR/print_pubkey.py" 2>/dev/null || true)
    SERVER_PUBLIC_KEY_B64=$(echo "$PUBKEY_OUT" | grep '^SERVER_PUBLIC_KEY_B64=' | cut -d= -f2-)
    PINNED_PUBKEY_SHA256=$(echo "$PUBKEY_OUT" | grep '^PINNED_PUBKEY_SHA256=' | cut -d= -f2-)
else
    warn "Khong thay signing key sau 10s — kiem tra: journalctl -u mtunnel-license -e"
    SERVER_PUBLIC_KEY_B64="(chua co - chay 'mtunnel-pubkey' sau)"
    PINNED_PUBKEY_SHA256="(chua co - chay 'mtunnel-pubkey' sau)"
fi

# ── 7. Nginx ────────────────────────────────────────────────
log "Cau hinh Nginx..."
cat > /etc/nginx/sites-available/mtunnel << NGXEOF
server {
    listen 80;
    server_name $DOMAIN;

    # ── SSE endpoint: tắt buffer, timeout dài ──────────────
    location /api/events {
        proxy_pass            http://127.0.0.1:5000;
        proxy_set_header      Host \$host;
        proxy_set_header      X-Real-IP \$remote_addr;

        proxy_buffering       off;
        proxy_cache           off;
        proxy_read_timeout    3600s;   # giữ kết nối SSE tối đa 1h
        proxy_send_timeout    3600s;
        keepalive_timeout     3600s;
        chunked_transfer_encoding on;

        # Tắt gzip cho SSE (gzip làm buffer dữ liệu)
        gzip                  off;
    }

    # ── Các endpoint còn lại ───────────────────────────────
    location /api/ {
        proxy_pass       http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /health {
        proxy_pass http://127.0.0.1:5000;
    }
}
NGXEOF

ln -sf /etc/nginx/sites-available/mtunnel /etc/nginx/sites-enabled/mtunnel
nginx -t > /dev/null 2>&1 && systemctl reload nginx
log "Nginx da cau hinh"

# ── 8. SSL ──────────────────────────────────────────────────
log "Cap SSL certificate..."
certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect > /dev/null 2>&1
log "SSL da cap xong"

# ── 8b. Doi port 443 -> 8443 ─────────────────────────────────
# QUAN TRONG: port 443 tren VPS nay da bi psiphond chiem dung (VPN server
# rieng, khong lien quan license server). Certbot mac dinh luon gan
# "listen 443 ssl" khi chay xong, nen phai sed doi lai NGAY SAU certbot -
# neu chay certbot lai sau nay (renew --force-renewal, hay certonly moi)
# co the ghi de mat dong sed nay, can kiem tra lai.
log "Doi port 443 -> 8443 (tranh xung dot voi psiphond)..."
sed -i 's/listen 443 ssl;/listen 8443 ssl;/' /etc/nginx/sites-available/mtunnel
sed -i 's/listen \[::\]:443 ssl;/listen [::]:8443 ssl;/' /etc/nginx/sites-available/mtunnel

if command -v ufw > /dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 8443/tcp > /dev/null 2>&1
    log "Da mo port 8443 tren ufw"
fi

nginx -t > /dev/null 2>&1 && systemctl reload nginx
log "Da doi sang port 8443"

# ── 9. Mở giao diện thiết lập token ────────────────────────
echo ""
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}${BOLD}   Buoc cuoi: Thiet lap Token              ${NC}"
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════${NC}"
bash "$INSTALL_DIR/update_token.sh"

# ── Hoàn tất ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Cai dat hoan tat!                       ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Verify URL : ${BOLD}https://$DOMAIN:8443/api/verify${NC}"
echo -e "  ⚙️  Config URL : ${BOLD}https://$DOMAIN:8443/api/config${NC}"
echo -e "  📡 SSE URL    : ${BOLD}https://$DOMAIN:8443/api/events${NC}"
echo -e "  📦 Package    : ${BOLD}$PACKAGE${NC}"
echo ""
echo -e "${YELLOW}${BOLD}Nhung vao app Android (de verify chu ky /api/config):${NC}"
echo -e "  SERVER_PUBLIC_KEY_B64 : ${BOLD}$SERVER_PUBLIC_KEY_B64${NC}"
echo -e "  PINNED_PUBKEY_SHA256  : ${BOLD}$PINNED_PUBKEY_SHA256${NC}"
echo ""
echo -e "${CYAN}Lenh quan ly:${NC}"
echo -e "  📋 Xem log    : journalctl -u mtunnel-license -f"
echo -e "  🔑 Doi token  : mtunnel-token"
echo -e "  🔐 Xem pubkey : mtunnel-pubkey"
echo -e "  🔄 Restart    : systemctl restart mtunnel-license"
echo -e "  📊 Status SSE : curl https://$DOMAIN:8443/health"
echo ""
echo -e "${CYAN}Admin API (dung server token lam admin_key):${NC}"
echo -e "  Thu hoi license:"
echo -e "  ${BOLD}curl -X POST https://$DOMAIN:8443/api/admin/revoke \\${NC}"
echo -e "  ${BOLD}  -H 'Content-Type: application/json' \\${NC}"
echo -e "  ${BOLD}  -d '{"admin_key":"TOKEN","token":"TOKEN_APP"}'${NC}"
echo ""
echo -e "  Revoke tat ca app:"
echo -e "  ${BOLD}curl -X POST https://$DOMAIN:8443/api/admin/revoke \\${NC}"
echo -e "  ${BOLD}  -H 'Content-Type: application/json' \\${NC}"
echo -e "  ${BOLD}  -d '{"admin_key":"TOKEN","token":""}'${NC}"
echo ""
