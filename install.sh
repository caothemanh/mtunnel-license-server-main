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
echo -e "${YELLOW}${BOLD}Luu y quan trong ve domain:${NC}"
echo -e "${YELLOW}Neu VPS nay dang dung chung lam may chu VPN (Psiphon/V2Ray...)${NC}"
echo -e "${YELLOW}va domain VPN chinh dang bat Cloudflare Proxy (may cam) de an IP,${NC}"
echo -e "${YELLOW}HAY DUNG 1 SUBDOMAIN RIENG cho license server nay (vd: lic5.domain.com)${NC}"
echo -e "${YELLOW}va dat subdomain do DNS only (may xam) tren Cloudflare — neu khong,${NC}"
echo -e "${YELLOW}TLS pin se khong on dinh (xem chi tiet o cuoi script).${NC}"
echo ""
printf "${CYAN}Nhap domain${NC} [vd: lic5.example.com]: "
read DOMAIN
printf "${CYAN}Nhap package name${NC} [vd: com.example.app]: "
read PACKAGE

[ -z "$DOMAIN"  ] && error "Domain khong duoc de trong"
[ -z "$PACKAGE" ] && error "Package name khong duoc de trong"

# Tu dong kiem tra domain co ve dang Proxied qua Cloudflare khong, bang
# cach so sanh IP DNS tra ve voi IP that cua VPS nay. Day chi la goi y
# (khong chinh xac 100% do co the co NAT/nhieu IP...), khong chan cai dat.
echo ""
info "Kiem tra DNS cua $DOMAIN..."
RESOLVED_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
MY_IP=$(curl -s -4 https://ifconfig.me 2>/dev/null || curl -s -4 https://icanhazip.com 2>/dev/null)
if [ -n "$RESOLVED_IP" ] && [ -n "$MY_IP" ]; then
    if [ "$RESOLVED_IP" != "$MY_IP" ]; then
        warn "Domain $DOMAIN dang tro toi IP $RESOLVED_IP, KHAC voi IP that cua VPS nay ($MY_IP)."
        warn "Day la dau hieu domain dang BAT Cloudflare Proxy (may cam) — TLS pin"
        warn "se KHONG on dinh (xem huong dan 'mtunnel-tlspin' sau khi cai xong)."
        printf "${YELLOW}Van tiep tuc cai dat voi domain nay?${NC} (y/N): "
        read CONTINUE_ANYWAY
        if [ "$CONTINUE_ANYWAY" != "y" ] && [ "$CONTINUE_ANYWAY" != "Y" ]; then
            error "Da huy. Tao subdomain rieng (DNS only) roi chay lai script."
        fi
    else
        log "Domain $DOMAIN tro dung IP VPS nay ($MY_IP) — dang DNS only, TLS pin se on dinh."
    fi
else
    warn "Khong kiem tra duoc DNS tu dong (thieu 'dig' hoac khong lay duoc IP) — bo qua buoc nay."
fi
echo ""

echo ""
info "Token se duoc thiet lap sau khi cai dat xong"
echo ""

# ── Chon phuong thuc lay chung chi SSL ──────────────────────
echo -e "${CYAN}${BOLD}--- Chung chi SSL ---${NC}"
echo "  1) Let's Encrypt tu dong qua Cloudflare DNS-01 (certbot, can Cloudflare API Token)"
echo "  2) Tu dan chung chi co san (vd: Cloudflare Origin CA certificate)"
echo ""
printf "${CYAN}Chon${NC} (1/2) [1]: "
read SSL_METHOD
SSL_METHOD=${SSL_METHOD:-1}
[ "$SSL_METHOD" != "1" ] && [ "$SSL_METHOD" != "2" ] && error "Lua chon khong hop le"
echo ""

EMAIL=""
CF_TOKEN=""
CERT_PEM=""
KEY_PEM=""

if [ "$SSL_METHOD" = "1" ]; then
    printf "${CYAN}Nhap email${NC} [cho SSL cert]: "
    read EMAIL
    [ -z "$EMAIL" ] && error "Email khong duoc de trong"
    echo ""

    # DNS-01 challenge duoc dung thay vi HTTP-01 vi khong can port 80,
    # tranh xung dot voi cac service khac (vd psiphond) da chiem port 80/443.
    echo -e "${CYAN}${BOLD}--- Cloudflare API Token (de xin SSL, khong can port 80) ---${NC}"
    echo -e "${YELLOW}Tao tai: https://dash.cloudflare.com/profile/api-tokens${NC}"
    echo -e "${YELLOW}Dung template 'Edit zone DNS', gioi han vao đúng zone cua domain ban dung${NC}"
    echo ""
    printf "${CYAN}Cloudflare API Token${NC} (an khi go): "
    read -s CF_TOKEN
    echo ""
    [ -z "$CF_TOKEN" ] && error "Can Cloudflare API Token de xin SSL qua DNS-01 (khong the dung port 80/443)"

    # Chan som token dang "cfat_..." (Account API Token — tao o muc
    # "Manage Account > Account API Tokens"). Loai token nay CHUA tuong
    # thich voi thu vien cloudflare-python ma certbot-dns-cloudflare dung,
    # se luon bao "Authentication error 10000" du quyen/zone cau hinh dung.
    # Certbot can "User API Token" tao o "My Profile > API Tokens".
    case "$CF_TOKEN" in
        cfat_*)
            error "Token nay la 'Account API Token' (tien to cfat_) — KHONG tuong thich voi certbot.
Vao https://dash.cloudflare.com/profile/api-tokens (muc 'Ma thong bao API nguoi dung',
KHONG phai 'Manage Account > Account API Tokens') de tao User API Token voi quyen
Zone:DNS:Edit + Zone:Zone:Read, gioi han vao dung zone cua domain, roi chay lai script."
            ;;
    esac
    echo ""
else
    echo -e "${CYAN}${BOLD}--- Chung chi SSL co san (vd: Cloudflare Origin CA) ---${NC}"
    echo -e "${YELLOW}Tao tai: Cloudflare dashboard > SSL/TLS > Origin Server > Create Certificate${NC}"
    echo -e "${YELLOW}Luu y: Origin CA cert CHI duoc Cloudflare edge tin cay, khong duoc trinh${NC}"
    echo -e "${YELLOW}duyet/OS tin cay mac dinh. App Android ket noi thang toi VPS se can tu${NC}"
    echo -e "${YELLOW}pin chung chi nay (hoac root CA cua no) trong network_security_config.${NC}"
    echo ""

    read_pem_until_blank_line() {
        # Doc nhieu dong, tu dung lai khi gap MOT DONG TRONG (bam Enter
        # them 1 lan sau khi dan). Bo qua dong trong o DAU (phong khi
        # nguoi dung lo bam Enter truoc khi dan). Cach nay khong phu
        # thuoc vao dinh dang PEM cu the (RSA/EC/PKCS8...) hay cach
        # terminal xu ly dong cuoi, nen chac chan hon nhieu so voi do
        # tim chuoi "-----END...-----".
        local content="" line
        while IFS= read -r line; do
            if [ -z "$line" ]; then
                [ -n "$content" ] && break
                continue
            fi
            content+="$line"$'\n'
        done
        printf '%s' "$content"
    }

    echo -e "${CYAN}Buoc 1/2 — Dan noi dung Origin Certificate (PEM):${NC}"
    echo -e "${YELLOW}Dan toan bo (ca dong BEGIN va END), roi bam Enter THEM 1 LAN NUA${NC}"
    echo -e "${YELLOW}(de lai 1 dong trong) — script se tu nhan biet va chuyen tiep.${NC}"
    echo ""
    CERT_PEM=$(read_pem_until_blank_line)
    [ -z "$CERT_PEM" ] && error "Chua nhan duoc noi dung Certificate nao — chay lai script va dan lai"
    echo -e "${GREEN}Da nhan Certificate (${NC}$(echo "$CERT_PEM" | wc -l)${GREEN} dong).${NC}"
    echo ""

    echo -e "${CYAN}Buoc 2/2 — Dan noi dung Private Key (PEM):${NC}"
    echo -e "${YELLOW}Dan toan bo (ca dong BEGIN va END), roi bam Enter THEM 1 LAN NUA${NC}"
    echo -e "${YELLOW}(de lai 1 dong trong) — script se tu nhan biet va chuyen tiep.${NC}"
    echo ""
    KEY_PEM=$(read_pem_until_blank_line)
    [ -z "$KEY_PEM" ] && error "Chua nhan duoc noi dung Private Key nao — chay lai script va dan lai"
    echo -e "${GREEN}Da nhan Private Key (${NC}$(echo "$KEY_PEM" | wc -l)${GREEN} dong).${NC}"
    echo ""

    echo "$CERT_PEM" | grep -q "BEGIN CERTIFICATE" || error "Noi dung Certificate khong hop le (thieu dong BEGIN CERTIFICATE) — chay lai script va dan lai"
    echo "$KEY_PEM" | grep -qE "BEGIN (RSA |EC )?PRIVATE KEY" || error "Noi dung Private Key khong hop le (thieu dong BEGIN ... PRIVATE KEY) — chay lai script va dan lai"
fi

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
apt install -y python3-pip python3-venv nginx curl > /dev/null 2>&1
pip3 install flask gunicorn gevent cryptography -q
log "Dependencies da cai xong"

# Mot so VPS (container/image toi gian) khong tao san /var/log/nginx du
# da apt install nginx — nginx se bao loi "could not open error log file"
# ngay ca khi config dung 100%. Tao lai cho chac, khong anh huong gi neu
# thu muc da ton tai.
mkdir -p /var/log/nginx
touch /var/log/nginx/error.log /var/log/nginx/access.log
chown -R www-data:adm /var/log/nginx
log "Da dam bao thu muc log nginx ton tai"

# ── 1b. Cai certbot + plugin Cloudflare qua pip venv rieng ──
# KHONG dung apt (certbot / python3-certbot-dns-cloudflare) vi ban apt cua
# Ubuntu qua cu doi voi Cloudflare API Token:
#   - Ubuntu 20.04 (focal): certbot-dns-cloudflare 0.39.0 — khong biet
#     "dns_cloudflare_api_token" ton tai, chi hieu Global API Key cu
#     (dns_cloudflare_email + dns_cloudflare_api_key) -> loi
#     "Missing properties ... dns_cloudflare_email/dns_cloudflare_api_key"
#     du file .ini da dung dinh dang Token 100%.
#   - Can cloudflare python module >= 2.3.1 de Token hoat dong; pip venv
#     luon lay ban moi nhat nen tranh han loai loi nay.
# Chi can khi dung phuong thuc 1 (Let's Encrypt DNS-01); phuong thuc 2
# (tu dan chung chi) khong dung certbot nen bo qua buoc nay.
if [ "$SSL_METHOD" = "1" ]; then
    log "Cai certbot + Cloudflare plugin (pip venv, ho tro API Token)..."
    CERTBOT_VENV="/opt/certbot-venv"
    python3 -m venv "$CERTBOT_VENV"
    "$CERTBOT_VENV/bin/pip" install -q --upgrade pip
    "$CERTBOT_VENV/bin/pip" install -q certbot certbot-dns-cloudflare
    ln -sf "$CERTBOT_VENV/bin/certbot" /usr/local/bin/certbot
    hash -r
    log "Certbot (venv, ho tro Cloudflare API Token) da cai xong: $(certbot --version 2>/dev/null)"
fi

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

# ── 5. Tạo mtunnel-menu.sh (menu quản lý tổng hợp) ──────────
# Gõ "mtunnel-token" se mo menu nay (khong hoi thang token moi nhu truoc) —
# gom tat ca lenh quan ly (doi token, xem pubkey, TLS pin, health, log,
# restart, signing key export/import) vao 1 cho duy nhat, de nho hon.
log "Tao script quan ly tong hop..."
cat > "$INSTALL_DIR/mtunnel-menu.sh" << 'TKEOF'
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
SIGNING_KEY_FILE="$INSTALL_DIR/.signing_key"
DEX_HASHES_FILE="$INSTALL_DIR/.dex_hashes.json"
ATTESTATION_SIGNING_HASHES_FILE="$INSTALL_DIR/.attestation_signing_hashes.json"
DEVICE_WHITELIST_FILE="$INSTALL_DIR/.attestation_whitelist.json"
DEVICE_BLOCKED_FILE="$INSTALL_DIR/.attestation_blocked_devices.json"
APK_UPLOAD_DIR="$INSTALL_DIR/apk_uploads"
mkdir -p "$APK_UPLOAD_DIR"
chown www-data:www-data "$APK_UPLOAD_DIR" 2>/dev/null || true

PACKAGE=""; DOMAIN=""; SSL_PORT=""
if [ -f "$CONFIG_FILE" ]; then
    PACKAGE=$(grep "^PACKAGE=" "$CONFIG_FILE" | cut -d= -f2)
    DOMAIN=$(grep "^DOMAIN=" "$CONFIG_FILE" | cut -d= -f2)
    SSL_PORT=$(grep "^SSL_PORT=" "$CONFIG_FILE" | cut -d= -f2)
fi
SSL_PORT=${SSL_PORT:-443}

print_public_key() {
    python3 - << PYEOF
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
try:
    with open("$SIGNING_KEY_FILE", "rb") as f:
        raw = f.read()
    key = Ed25519PrivateKey.from_private_bytes(raw)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(base64.b64encode(pub).decode())
except FileNotFoundError:
    print("(chua co signing key - service co the chua khoi dong xong)")
PYEOF
}

pause() {
    echo ""
    read -p "Nhan Enter de quay lai menu..." _
}

show_header() {
    clear
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   MTunnel License Server - Quan ly        ${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Domain  : ${CYAN}$DOMAIN${NC}"
    echo -e "  Port    : ${CYAN}$SSL_PORT${NC}"
    echo -e "  Package : ${CYAN}$PACKAGE${NC}"
    if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
        CURRENT=$(cat "$TOKEN_FILE")
        echo -e "  Token   : ${CYAN}${CURRENT:0:8}...${CURRENT: -4}${NC}"
    else
        echo -e "  Token   : ${YELLOW}(chua thiet lap)${NC}"
    fi
    echo ""
}

compute_dex_hash() {
    local apk_path="$1"
    python3 - "$apk_path" << 'PYEOF'
import sys, zipfile, hashlib, re
apk_path = sys.argv[1]
DEX_RE = re.compile(r"^classes\d*\.dex$")
try:
    with zipfile.ZipFile(apk_path, "r") as z:
        entries = sorted(n for n in z.namelist() if DEX_RE.match(n))
        if not entries:
            print("ERROR:no_dex_entries_found", file=sys.stderr)
            sys.exit(1)
        digests = b""
        for name in entries:
            data = z.read(name)
            h = hashlib.sha256(data).digest()
            digests += h
            print(f"  {name}: {h.hex()} ({len(data)} bytes)", file=sys.stderr)
        print(hashlib.sha256(digests).hexdigest())
except Exception as e:
    print(f"ERROR:{e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

pick_apk_file() {
    SELECTED_APK=""
    mapfile -t APK_FILES < <(find "$APK_UPLOAD_DIR" -maxdepth 1 -type f -iname "*.apk" 2>/dev/null | sort)
    if [ ${#APK_FILES[@]} -eq 0 ]; then
        echo -e "${RED}Khong tim thay file .apk nao trong $APK_UPLOAD_DIR${NC}"
        echo -e "${YELLOW}Upload truoc bang lenh (chay tu may build, KHONG phai tren VPS):${NC}"
        echo -e "  ${CYAN}scp app-release.apk root@<domain-hoac-ip>:$APK_UPLOAD_DIR/${NC}"
        return 1
    fi
    echo -e "${CYAN}${BOLD}Cac file APK tim thay trong $APK_UPLOAD_DIR:${NC}"
    echo ""
    local i=1
    for f in "${APK_FILES[@]}"; do
        local size mtime
        size=$(du -h "$f" 2>/dev/null | cut -f1)
        mtime=$(date -r "$f" "+%Y-%m-%d %H:%M" 2>/dev/null)
        echo -e "  ${BOLD}$i)${NC} $(basename "$f")  ${YELLOW}(${size}, sua luc ${mtime})${NC}"
        i=$((i + 1))
    done
    echo ""
    read -p "Chon so [1-${#APK_FILES[@]}] (Enter de huy): " PICK
    if [ -z "$PICK" ]; then return 1; fi
    if ! [[ "$PICK" =~ ^[0-9]+$ ]] || [ "$PICK" -lt 1 ] || [ "$PICK" -gt ${#APK_FILES[@]} ]; then
        echo -e "${RED}Lua chon khong hop le.${NC}"
        return 1
    fi
    SELECTED_APK="${APK_FILES[$((PICK - 1))]}"
    return 0
}

list_dex_hashes() {
    python3 - "$DEX_HASHES_FILE" << 'PYEOF'
import sys, json
try:
    with open(sys.argv[1]) as f:
        allowed = json.load(f).get("allowed", [])
except Exception:
    allowed = []
if not allowed:
    print("(chua co hash nao trong allow-list)")
else:
    for i, h in enumerate(allowed, 1):
        print(f"  {i}) {h}")
PYEOF
}

add_dex_hash() {
    local hash_hex="$1"
    python3 - "$DEX_HASHES_FILE" "$hash_hex" << 'PYEOF'
import sys, json, os
path, new_hash = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    doc = {"allowed": []}
allowed = doc.setdefault("allowed", [])
if new_hash in allowed:
    print("DUPLICATE")
else:
    allowed.append(new_hash)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)
    print("ADDED")
PYEOF
}

preview_dex_hash_selection() {
    local idx_csv="$1"
    python3 - "$DEX_HASHES_FILE" "$idx_csv" << 'PYEOF'
import sys, json
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        allowed = json.load(f).get("allowed", [])
except Exception:
    allowed = []
if not allowed:
    print("ERROR:empty")
    sys.exit(1)
if idx_csv.strip().lower() == "all":
    selected = set(range(1, len(allowed) + 1))
else:
    selected = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print(f"ERROR:invalid_index:{part}")
            sys.exit(1)
        selected.add(int(part))
invalid = [i for i in selected if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not selected:
    print("ERROR:no_selection")
    sys.exit(1)
for i, h in enumerate(allowed, 1):
    mark = "[x]" if i in selected else "[ ]"
    print(f"{mark} {i}) {h}")
print(f"COUNT:{len(selected)}")
PYEOF
}

remove_dex_hashes_by_indices() {
    local idx_csv="$1"
    python3 - "$DEX_HASHES_FILE" "$idx_csv" << 'PYEOF'
import sys, json, os
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    print("ERROR:file_not_found")
    sys.exit(1)
allowed = doc.get("allowed", [])
if idx_csv.strip().lower() == "all":
    indices = set(range(1, len(allowed) + 1))
else:
    indices = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if part:
            indices.add(int(part))
invalid = [i for i in indices if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not indices:
    print("ERROR:no_selection")
    sys.exit(1)
removed = []
for i in sorted(indices, reverse=True):
    removed.append(allowed.pop(i - 1))
removed.reverse()
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, path)
print("REMOVED:" + "|".join(removed))
print(f"COUNT:{len(removed)}")
PYEOF
}

# Lay SHA-256 cua signing certificate TRUC TIEP tu file APK (khong can
# apksigner/keytool). Uu tien doc tu APK Signing Block v2/v3 (pure Python,
# tu parse dinh dang - xem source.android.com/docs/security/apksigning/v2)
# vi day la thu duy nhat luon co tren APK build boi Android Gradle Plugin
# hien dai; fallback doc PKCS7 trong META-INF/*.RSA|DSA|EC (v1 JAR signing)
# neu APK chi con giu v1. Gia tri tra ve KHOP CHINH XAC voi truong
# "signatureDigests" ma Android tu dien vao AttestationApplicationId (tag
# 709) trong chain Key Attestation — day cung la gia tri server doi chieu
# trong attestation_verify() (server.py).
compute_signing_hash() {
    local apk_path="$1"
    python3 - "$apk_path" << 'PYEOF'
import sys, struct, zipfile, hashlib, re

apk_path = sys.argv[1]

def find_eocd(data):
    idx = data.rfind(b'PK\x05\x06')
    if idx == -1:
        raise ValueError("khong_tim_thay_eocd")
    return idx

def central_dir_offset(data):
    eocd = find_eocd(data)
    return struct.unpack_from('<I', data, eocd + 16)[0]

def read_lp(buf, off):
    length = struct.unpack_from('<I', buf, off)[0]
    start = off + 4
    end = start + length
    return buf[start:end], end

def iter_lp_items(buf):
    off = 0
    while off < len(buf):
        item, off = read_lp(buf, off)
        yield item

def certs_from_v2v3(data):
    cd_offset = central_dir_offset(data)
    trailer = data[cd_offset - 24:cd_offset]
    size_trailer, magic = struct.unpack('<Q16s', trailer)
    if magic != b'APK Sig Block 42':
        return []
    block_start = cd_offset - size_trailer - 8
    pairs = data[block_start + 8: cd_offset - 24]
    out = []
    off = 0
    while off < len(pairs):
        length = struct.unpack_from('<Q', pairs, off)[0]
        off += 8
        entry = pairs[off:off + length]
        id_ = struct.unpack_from('<I', entry, 0)[0]
        value = entry[4:]
        off += length
        if id_ not in (0x7109871a, 0xf05368c0, 0x1b93ad61):  # v2, v3, v3.1
            continue
        signer_seq, _ = read_lp(value, 0)
        for signer in iter_lp_items(signer_seq):
            signed_data, _ = read_lp(signer, 0)
            _, off_sd = read_lp(signed_data, 0)          # digests (bo qua)
            certs_seq, _ = read_lp(signed_data, off_sd)
            for c in iter_lp_items(certs_seq):
                out.append(c)
    return out

def certs_from_v1(data):
    with zipfile.ZipFile.__new__(zipfile.ZipFile) as _:
        pass
    import io
    z = zipfile.ZipFile(io.BytesIO(data))
    sig_re = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", re.IGNORECASE)
    sig_files = [n for n in z.namelist() if sig_re.match(n)]
    if not sig_files:
        return []
    from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
    certs = pkcs7.load_der_pkcs7_certificates(z.read(sig_files[0]))
    return [c.public_bytes(Encoding.DER) for c in certs]

try:
    with open(apk_path, 'rb') as f:
        data = f.read()

    certs = certs_from_v2v3(data)
    source = "v2/v3"
    if not certs:
        certs = certs_from_v1(data)
        source = "v1 (META-INF)"
    if not certs:
        print("ERROR:khong_tim_thay_signing_certificate_nao", file=sys.stderr)
        sys.exit(1)

    digest = hashlib.sha256(certs[0]).hexdigest()
    print(f"  Nguon: {source} | so cert: {len(certs)} | cert[0] len={len(certs[0])} bytes", file=sys.stderr)
    print(digest)
except Exception as e:
    print(f"ERROR:{e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

list_signing_hashes() {
    python3 - "$ATTESTATION_SIGNING_HASHES_FILE" << 'PYEOF'
import sys, json
try:
    with open(sys.argv[1]) as f:
        allowed = json.load(f).get("allowed", [])
except Exception:
    allowed = []
if not allowed:
    print("(chua co hash nao trong allow-list)")
else:
    for i, h in enumerate(allowed, 1):
        print(f"  {i}) {h}")
PYEOF
}

add_signing_hash() {
    local hash_hex="$1"
    python3 - "$ATTESTATION_SIGNING_HASHES_FILE" "$hash_hex" << 'PYEOF'
import sys, json, os
path, new_hash = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    doc = {"allowed": []}
allowed = doc.setdefault("allowed", [])
if new_hash in allowed:
    print("DUPLICATE")
else:
    allowed.append(new_hash)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)
    print("ADDED")
PYEOF
}

preview_signing_hash_selection() {
    local idx_csv="$1"
    python3 - "$ATTESTATION_SIGNING_HASHES_FILE" "$idx_csv" << 'PYEOF'
import sys, json
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        allowed = json.load(f).get("allowed", [])
except Exception:
    allowed = []
if not allowed:
    print("ERROR:empty")
    sys.exit(1)
if idx_csv.strip().lower() == "all":
    selected = set(range(1, len(allowed) + 1))
else:
    selected = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print(f"ERROR:invalid_index:{part}")
            sys.exit(1)
        selected.add(int(part))
invalid = [i for i in selected if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not selected:
    print("ERROR:no_selection")
    sys.exit(1)
for i, h in enumerate(allowed, 1):
    mark = "[x]" if i in selected else "[ ]"
    print(f"{mark} {i}) {h}")
print(f"COUNT:{len(selected)}")
PYEOF
}

remove_signing_hashes_by_indices() {
    local idx_csv="$1"
    python3 - "$ATTESTATION_SIGNING_HASHES_FILE" "$idx_csv" << 'PYEOF'
import sys, json, os
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    print("ERROR:file_not_found")
    sys.exit(1)
allowed = doc.get("allowed", [])
if idx_csv.strip().lower() == "all":
    indices = set(range(1, len(allowed) + 1))
else:
    indices = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if part:
            indices.add(int(part))
invalid = [i for i in indices if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not indices:
    print("ERROR:no_selection")
    sys.exit(1)
removed = []
for i in sorted(indices, reverse=True):
    removed.append(allowed.pop(i - 1))
removed.reverse()
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, path)
print("REMOVED:" + "|".join(removed))
print(f"COUNT:{len(removed)}")
PYEOF
}

signing_hash_menu() {
    while true; do
        echo -e "${CYAN}${BOLD}--- Quan ly Signing Hash Allow-list (/api/attestation-verify) ---${NC}"
        echo ""
        echo -e "${YELLOW}Hash nay doi chieu voi AttestationApplicationId trong chain Key${NC}"
        echo -e "${YELLOW}Attestation phan cung — khong the gia mao bang hook/resign APK.${NC}"
        echo ""
        echo "  1) Them hash tu file APK (chon theo so, khong go duong dan)"
        echo "  2) Xem danh sach hash dang duoc phep"
        echo "  3) Xoa 1 hash khoi allow-list"
        echo "  4) Quay lai"
        echo ""
        read -p "Chon [1-4]: " SH_CHOICE
        echo ""
        case "$SH_CHOICE" in
            1)
                if ! pick_apk_file; then
                    :
                else
                    echo ""
                    echo -e "${YELLOW}Dang doc signing certificate tu: $(basename "$SELECTED_APK")...${NC}"
                    echo ""
                    OUTPUT=$(compute_signing_hash "$SELECTED_APK")
                    SIG_HASH=$(echo "$OUTPUT" | tail -1)
                    if [[ "$SIG_HASH" == ERROR:* ]]; then
                        echo -e "${RED}That bai: $SIG_HASH${NC}"
                    else
                        echo "$OUTPUT" | head -n -1
                        echo -e "${GREEN}SHA-256 chu ky: ${BOLD}$SIG_HASH${NC}"
                        echo ""
                        read -p "Them hash nay vao allow-list? [y/N]: " SH_CONFIRM
                        if [[ "$SH_CONFIRM" == "y" || "$SH_CONFIRM" == "Y" ]]; then
                            SH_RESULT=$(add_signing_hash "$SIG_HASH")
                            chmod 600 "$ATTESTATION_SIGNING_HASHES_FILE" 2>/dev/null || true
                            chown www-data:www-data "$ATTESTATION_SIGNING_HASHES_FILE" 2>/dev/null || true
                            if [ "$SH_RESULT" == "ADDED" ]; then
                                echo -e "${GREEN}✅ Da them vao allow-list (khong can restart service).${NC}"
                            else
                                echo -e "${YELLOW}Hash nay da co san trong allow-list roi.${NC}"
                            fi
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            2)
                list_signing_hashes
                ;;
            3)
                list_signing_hashes
                echo ""
                echo -e "${YELLOW}Nhap cac so muon xoa, cach nhau boi dau phay hoac khoang trang (vd: 1,3,5).${NC}"
                echo -e "${YELLOW}Go 'all' de xoa tat ca. Enter de huy.${NC}"
                read -p "Chon: " SH_IDX
                if [ -n "$SH_IDX" ]; then
                    SH_PREVIEW=$(preview_signing_hash_selection "$SH_IDX")
                    if [[ "$SH_PREVIEW" == ERROR:empty* ]]; then
                        echo -e "${RED}Danh sach dang trong.${NC}"
                    elif [[ "$SH_PREVIEW" == ERROR:invalid_index* ]]; then
                        echo -e "${RED}So thu tu khong hop le: ${SH_PREVIEW#ERROR:invalid_index:}${NC}"
                    elif [[ "$SH_PREVIEW" == ERROR:no_selection* ]]; then
                        echo -e "${RED}Chua chon muc nao.${NC}"
                    else
                        echo "$SH_PREVIEW"
                        echo ""
                        read -p "Xac nhan xoa cac muc tren? [y/N]: " SH_DEL_CONFIRM
                        if [[ "$SH_DEL_CONFIRM" == "y" || "$SH_DEL_CONFIRM" == "Y" ]]; then
                            SH_DEL_RESULT=$(remove_signing_hashes_by_indices "$SH_IDX")
                            chmod 600 "$ATTESTATION_SIGNING_HASHES_FILE" 2>/dev/null || true
                            chown www-data:www-data "$ATTESTATION_SIGNING_HASHES_FILE" 2>/dev/null || true
                            COUNT=$(echo "$SH_DEL_RESULT" | grep -o 'COUNT:[0-9]*' | cut -d: -f2)
                            echo -e "${GREEN}✅ Da xoa $COUNT hash.${NC}"
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            4) return ;;
            *) echo -e "${RED}Lua chon khong hop le.${NC}" ;;
        esac
        pause
    done
}

dex_hash_menu() {

    while true; do
        echo -e "${CYAN}${BOLD}--- Quan ly DEX Hash Allow-list (/api/dex-verify) ---${NC}"
        echo ""
        echo "  1) Them hash tu file APK (chon theo so, khong go duong dan)"
        echo "  2) Xem danh sach hash dang duoc phep"
        echo "  3) Xoa 1 hash khoi allow-list"
        echo "  4) Quay lai"
        echo ""
        read -p "Chon [1-4]: " DH_CHOICE
        echo ""
        case "$DH_CHOICE" in
            1)
                if ! pick_apk_file; then
                    :
                else
                    echo ""
                    echo -e "${YELLOW}Dang tinh hash cho: $(basename "$SELECTED_APK")...${NC}"
                    echo ""
                    OUTPUT=$(compute_dex_hash "$SELECTED_APK")
                    COMBINED=$(echo "$OUTPUT" | tail -1)
                    if [[ "$COMBINED" == ERROR:* ]]; then
                        echo -e "${RED}That bai: $COMBINED${NC}"
                    else
                        echo -e "${GREEN}Combined SHA-256: ${BOLD}$COMBINED${NC}"
                        echo ""
                        read -p "Them hash nay vao allow-list? [y/N]: " DH_CONFIRM
                        if [[ "$DH_CONFIRM" == "y" || "$DH_CONFIRM" == "Y" ]]; then
                            DH_RESULT=$(add_dex_hash "$COMBINED")
                            chmod 600 "$DEX_HASHES_FILE" 2>/dev/null || true
                            chown www-data:www-data "$DEX_HASHES_FILE" 2>/dev/null || true
                            if [ "$DH_RESULT" == "ADDED" ]; then
                                echo -e "${GREEN}✅ Da them vao allow-list (khong can restart service).${NC}"
                            else
                                echo -e "${YELLOW}Hash nay da co san trong allow-list roi.${NC}"
                            fi
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            2)
                list_dex_hashes
                ;;
            3)
                list_dex_hashes
                echo ""
                echo -e "${YELLOW}Nhap cac so muon xoa, cach nhau boi dau phay hoac khoang trang (vd: 1,3,5).${NC}"
                echo -e "${YELLOW}Go 'all' de xoa tat ca. Enter de huy.${NC}"
                read -p "Chon: " DH_IDX
                if [ -n "$DH_IDX" ]; then
                    DH_PREVIEW=$(preview_dex_hash_selection "$DH_IDX")
                    if [[ "$DH_PREVIEW" == ERROR:empty* ]]; then
                        echo -e "${RED}Danh sach dang trong.${NC}"
                    elif [[ "$DH_PREVIEW" == ERROR:invalid_index* ]]; then
                        echo -e "${RED}So thu tu khong hop le: ${DH_PREVIEW#ERROR:invalid_index:}${NC}"
                    elif [[ "$DH_PREVIEW" == ERROR:no_selection* ]]; then
                        echo -e "${RED}Chua chon muc nao.${NC}"
                    else
                        echo ""
                        echo -e "${CYAN}${BOLD}Danh sach da chon xoa:${NC}"
                        echo "$DH_PREVIEW" | grep -v "^COUNT:"
                        DH_SEL_COUNT=$(echo "$DH_PREVIEW" | grep "^COUNT:" | cut -d: -f2)
                        echo ""
                        read -p "Xac nhan xoa $DH_SEL_COUNT hash da chon? [y/N]: " DH_CONFIRM
                        if [[ "$DH_CONFIRM" == "y" || "$DH_CONFIRM" == "Y" ]]; then
                            DH_RESULT=$(remove_dex_hashes_by_indices "$DH_IDX")
                            if [[ "$DH_RESULT" == *"REMOVED:"* ]]; then
                                DH_RM_COUNT=$(echo "$DH_RESULT" | grep "^COUNT:" | cut -d: -f2)
                                echo -e "${GREEN}✅ Da xoa $DH_RM_COUNT hash.${NC}"
                                echo -e "${RED}App nao dang chay dung cac hash nay se bi kill trong lan check ke tiep.${NC}"
                            else
                                echo -e "${RED}Loi: $DH_RESULT${NC}"
                            fi
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            4)
                return
                ;;
            *)
                echo -e "${RED}Lua chon khong hop le.${NC}"
                ;;
        esac
        echo ""
    done
}

list_whitelist_devices() {
    python3 - "$DEVICE_WHITELIST_FILE" << 'PYEOF'
import sys, json
try:
    with open(sys.argv[1]) as f:
        allowed = json.load(f).get("allowed_device_ids", [])
except Exception:
    allowed = []
if not allowed:
    print("(chua co device id nao trong whitelist)")
else:
    for i, d in enumerate(allowed, 1):
        print(f"  {i}) {d}")
PYEOF
}

add_whitelist_device() {
    local device_id="$1"
    python3 - "$DEVICE_WHITELIST_FILE" "$device_id" << 'PYEOF'
import sys, json, os
path, new_id = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    doc = {"allowed_device_ids": []}
allowed = doc.setdefault("allowed_device_ids", [])
if new_id in allowed:
    print("DUPLICATE")
else:
    allowed.append(new_id)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)
    print("ADDED")
PYEOF
}

preview_whitelist_selection() {
    local idx_csv="$1"
    python3 - "$DEVICE_WHITELIST_FILE" "$idx_csv" << 'PYEOF'
import sys, json
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        allowed = json.load(f).get("allowed_device_ids", [])
except Exception:
    allowed = []
if not allowed:
    print("ERROR:empty")
    sys.exit(1)
if idx_csv.strip().lower() == "all":
    selected = set(range(1, len(allowed) + 1))
else:
    selected = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print(f"ERROR:invalid_index:{part}")
            sys.exit(1)
        selected.add(int(part))
invalid = [i for i in selected if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not selected:
    print("ERROR:no_selection")
    sys.exit(1)
for i, d in enumerate(allowed, 1):
    mark = "[x]" if i in selected else "[ ]"
    print(f"{mark} {i}) {d}")
print(f"COUNT:{len(selected)}")
PYEOF
}

remove_whitelist_devices_by_indices() {
    local idx_csv="$1"
    python3 - "$DEVICE_WHITELIST_FILE" "$idx_csv" << 'PYEOF'
import sys, json, os
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    print("ERROR:file_not_found")
    sys.exit(1)
allowed = doc.get("allowed_device_ids", [])
if idx_csv.strip().lower() == "all":
    indices = set(range(1, len(allowed) + 1))
else:
    indices = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if part:
            indices.add(int(part))
invalid = [i for i in indices if i < 1 or i > len(allowed)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not indices:
    print("ERROR:no_selection")
    sys.exit(1)
removed = []
for i in sorted(indices, reverse=True):
    removed.append(allowed.pop(i - 1))
removed.reverse()
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, path)
print("REMOVED:" + "|".join(removed))
print(f"COUNT:{len(removed)}")
PYEOF
}

list_blocked_devices() {
    python3 - "$DEVICE_BLOCKED_FILE" << 'PYEOF'
import sys, json, time
try:
    with open(sys.argv[1]) as f:
        blocked = json.load(f).get("blocked", {})
except Exception:
    blocked = {}
if not blocked:
    print("(chua ghi nhan thiet bi nao bi chan)")
else:
    items = sorted(blocked.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
    for i, (device_id, info) in enumerate(items, 1):
        last_seen = info.get("last_seen", 0)
        last_seen_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen)) if last_seen else "?"
        reason = info.get("reason", "khong_xac_dinh")
        count = info.get("count", 1)
        pkg = info.get("pkg", "?")
        ip = info.get("last_ip", "?")
        print(f"  {i}) {device_id}")
        print(f"       ly_do={reason} | lan_cuoi={last_seen_str} | so_lan={count} | pkg={pkg} | ip={ip}")
PYEOF
}

add_blocked_device_to_whitelist_by_index() {
    local idx="$1"
    python3 - "$DEVICE_BLOCKED_FILE" "$DEVICE_WHITELIST_FILE" "$idx" << 'PYEOF'
import sys, json, os
blocked_path, whitelist_path, idx = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(blocked_path) as f:
        blocked = json.load(f).get("blocked", {})
except Exception:
    blocked = {}
if not blocked:
    print("ERROR:empty")
    sys.exit(1)
if not idx.isdigit():
    print("ERROR:invalid_index")
    sys.exit(1)
idx = int(idx)
items = sorted(blocked.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
if idx < 1 or idx > len(items):
    print("ERROR:invalid_index")
    sys.exit(1)
device_id = items[idx - 1][0]
try:
    with open(whitelist_path) as f:
        doc = json.load(f)
except Exception:
    doc = {"allowed_device_ids": []}
allowed = doc.setdefault("allowed_device_ids", [])
if device_id in allowed:
    print(f"DUPLICATE:{device_id}")
else:
    allowed.append(device_id)
    tmp = whitelist_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, whitelist_path)
    print(f"ADDED:{device_id}")
PYEOF
}

preview_blocked_selection() {
    local idx_csv="$1"
    python3 - "$DEVICE_BLOCKED_FILE" "$idx_csv" << 'PYEOF'
import sys, json
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        blocked = json.load(f).get("blocked", {})
except Exception:
    blocked = {}
if not blocked:
    print("ERROR:empty")
    sys.exit(1)
items = sorted(blocked.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
if idx_csv.strip().lower() == "all":
    selected = set(range(1, len(items) + 1))
else:
    selected = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print(f"ERROR:invalid_index:{part}")
            sys.exit(1)
        selected.add(int(part))
invalid = [i for i in selected if i < 1 or i > len(items)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not selected:
    print("ERROR:no_selection")
    sys.exit(1)
for i, (device_id, info) in enumerate(items, 1):
    mark = "[x]" if i in selected else "[ ]"
    print(f"{mark} {i}) {device_id} (ly_do={info.get('reason', '?')})")
print(f"COUNT:{len(selected)}")
PYEOF
}

clear_blocked_devices_by_indices() {
    local idx_csv="$1"
    python3 - "$DEVICE_BLOCKED_FILE" "$idx_csv" << 'PYEOF'
import sys, json, os
path, idx_csv = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except Exception:
    print("ERROR:file_not_found")
    sys.exit(1)
blocked = doc.get("blocked", {})
items = sorted(blocked.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
if idx_csv.strip().lower() == "all":
    indices = set(range(1, len(items) + 1))
else:
    indices = set()
    for part in idx_csv.replace(" ", ",").split(","):
        part = part.strip()
        if part:
            indices.add(int(part))
invalid = [i for i in indices if i < 1 or i > len(items)]
if invalid:
    print(f"ERROR:invalid_index:{','.join(map(str, sorted(invalid)))}")
    sys.exit(1)
if not indices:
    print("ERROR:no_selection")
    sys.exit(1)
removed = []
for i in indices:
    device_id = items[i - 1][0]
    removed.append(device_id)
    blocked.pop(device_id, None)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, path)
print("REMOVED:" + "|".join(removed))
print(f"COUNT:{len(removed)}")
PYEOF
}

blocked_devices_menu() {
    while true; do
        echo -e "${CYAN}${BOLD}--- Thiet bi bi chan (root / bootloader mo khoa) ---${NC}"
        echo ""
        echo -e "${YELLOW}Day la cac device_id ma server DA verify Key Attestation${NC}"
        echo -e "${YELLOW}that (ve ky hop le) nhung bi tu choi vi root hoac bootloader${NC}"
        echo -e "${YELLOW}dang mo khoa. Server tu dong ghi lai moi khi /api/config bi${NC}"
        echo -e "${YELLOW}tu choi vi ly do nay — khong can lam gi them.${NC}"
        echo ""
        list_blocked_devices
        echo ""
        echo "  1) Them 1 thiet bi tu danh sach nay vao whitelist"
        echo "  2) Xoa (don dep) khoi danh sach nay"
        echo "  3) Quay lai"
        echo ""
        read -p "Chon [1-3]: " BD_CHOICE
        echo ""
        case "$BD_CHOICE" in
            1)
                read -p "Nhap so thu tu can them vao whitelist (Enter de huy): " BD_IDX
                if [ -n "$BD_IDX" ] && [[ "$BD_IDX" =~ ^[0-9]+$ ]]; then
                    BD_RESULT=$(add_blocked_device_to_whitelist_by_index "$BD_IDX")
                    chmod 600 "$DEVICE_WHITELIST_FILE" 2>/dev/null || true
                    chown www-data:www-data "$DEVICE_WHITELIST_FILE" 2>/dev/null || true
                    case "$BD_RESULT" in
                        ADDED:*)
                            echo -e "${GREEN}✅ Da them ${BD_RESULT#ADDED:} vao whitelist.${NC}"
                            echo -e "${YELLOW}Thiet bi nay se bo qua Key Attestation tu lan goi sau.${NC}"
                            ;;
                        DUPLICATE:*)
                            echo -e "${YELLOW}${BD_RESULT#DUPLICATE:} da co san trong whitelist roi.${NC}"
                            ;;
                        *)
                            echo -e "${RED}Loi: $BD_RESULT${NC}"
                            ;;
                    esac
                elif [ -n "$BD_IDX" ]; then
                    echo -e "${RED}So thu tu khong hop le.${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}Nhap cac so muon xoa, cach nhau boi dau phay hoac khoang trang (vd: 1,3,5).${NC}"
                echo -e "${YELLOW}Go 'all' de xoa tat ca. Enter de huy. (Chi xoa khoi log, khong anh huong whitelist)${NC}"
                read -p "Chon: " BD_IDX
                if [ -n "$BD_IDX" ]; then
                    BD_PREVIEW=$(preview_blocked_selection "$BD_IDX")
                    if [[ "$BD_PREVIEW" == ERROR:empty* ]]; then
                        echo -e "${RED}Danh sach dang trong.${NC}"
                    elif [[ "$BD_PREVIEW" == ERROR:invalid_index* ]]; then
                        echo -e "${RED}So thu tu khong hop le: ${BD_PREVIEW#ERROR:invalid_index:}${NC}"
                    elif [[ "$BD_PREVIEW" == ERROR:no_selection* ]]; then
                        echo -e "${RED}Chua chon muc nao.${NC}"
                    else
                        echo ""
                        echo -e "${CYAN}${BOLD}Danh sach da chon xoa:${NC}"
                        echo "$BD_PREVIEW" | grep -v "^COUNT:"
                        BD_SEL_COUNT=$(echo "$BD_PREVIEW" | grep "^COUNT:" | cut -d: -f2)
                        echo ""
                        read -p "Xac nhan xoa $BD_SEL_COUNT muc da chon khoi log? [y/N]: " BD_CONFIRM
                        if [[ "$BD_CONFIRM" == "y" || "$BD_CONFIRM" == "Y" ]]; then
                            BD_RM_RESULT=$(clear_blocked_devices_by_indices "$BD_IDX")
                            if [[ "$BD_RM_RESULT" == *"REMOVED:"* ]]; then
                                BD_RM_COUNT=$(echo "$BD_RM_RESULT" | grep "^COUNT:" | cut -d: -f2)
                                echo -e "${GREEN}✅ Da xoa $BD_RM_COUNT muc khoi log.${NC}"
                            else
                                echo -e "${RED}Loi: $BD_RM_RESULT${NC}"
                            fi
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            3)
                return
                ;;
            *)
                echo -e "${RED}Lua chon khong hop le.${NC}"
                ;;
        esac
        echo ""
    done
}

attestation_whitelist_menu() {
    while true; do
        echo -e "${CYAN}${BOLD}--- Quan ly Attestation Whitelist (bo qua Key Attestation theo device_id) ---${NC}"
        echo ""
        echo -e "${YELLOW}Thiet bi trong danh sach nay se duoc /api/config bo qua yeu cau${NC}"
        echo -e "${YELLOW}Key Attestation (bootloader khoa + Verified Boot) — dung cho may${NC}"
        echo -e "${YELLOW}root/da mo khoa bootloader can hoat dong duoc (vd may dev/tester).${NC}"
        echo -e "${RED}Chi nen whitelist may cu the, KHONG nen dung dai tra vi se mat${NC}"
        echo -e "${RED}tac dung chong root/patch cua co che attestation.${NC}"
        echo ""
        echo "  1) Nhap device_id tu client de them vao whitelist"
        echo "  2) Xem danh sach device_id dang duoc whitelist"
        echo "  3) Xoa device_id khoi whitelist"
        echo "  4) Xem thiet bi bi chan (root / bootloader mo khoa)"
        echo "  5) Quay lai"
        echo ""
        read -p "Chon [1-5]: " WL_CHOICE
        echo ""
        case "$WL_CHOICE" in
            1)
                echo -e "${CYAN}Huong dan lay device_id:${NC}"
                echo "  1. Chay app tren thiet bi can whitelist"
                echo "  2. device_id duoc app gui kem trong request /api/config"
                echo "     (xem trong log server: journalctl -u mtunnel-license -f)"
                echo "  3. Copy device_id roi paste vao day"
                echo ""
                read -p "Nhap device_id: " NEW_DEVICE_ID
                if [ -z "$NEW_DEVICE_ID" ]; then
                    echo -e "${RED}device_id khong duoc de trong!${NC}"
                else
                    WL_RESULT=$(add_whitelist_device "$NEW_DEVICE_ID")
                    chmod 600 "$DEVICE_WHITELIST_FILE" 2>/dev/null || true
                    chown www-data:www-data "$DEVICE_WHITELIST_FILE" 2>/dev/null || true
                    if [ "$WL_RESULT" == "ADDED" ]; then
                        echo -e "${GREEN}✅ Da them device_id vao whitelist (khong can restart service).${NC}"
                        echo -e "${YELLOW}Thiet bi nay gio se bo qua yeu cau Key Attestation khi goi /api/config.${NC}"
                    else
                        echo -e "${YELLOW}device_id nay da co san trong whitelist roi.${NC}"
                    fi
                fi
                ;;
            2)
                list_whitelist_devices
                ;;
            3)
                list_whitelist_devices
                echo ""
                echo -e "${YELLOW}Nhap cac so muon xoa, cach nhau boi dau phay hoac khoang trang (vd: 1,3,5).${NC}"
                echo -e "${YELLOW}Go 'all' de xoa tat ca. Enter de huy.${NC}"
                read -p "Chon: " WL_IDX
                if [ -n "$WL_IDX" ]; then
                    WL_PREVIEW=$(preview_whitelist_selection "$WL_IDX")
                    if [[ "$WL_PREVIEW" == ERROR:empty* ]]; then
                        echo -e "${RED}Danh sach dang trong.${NC}"
                    elif [[ "$WL_PREVIEW" == ERROR:invalid_index* ]]; then
                        echo -e "${RED}So thu tu khong hop le: ${WL_PREVIEW#ERROR:invalid_index:}${NC}"
                    elif [[ "$WL_PREVIEW" == ERROR:no_selection* ]]; then
                        echo -e "${RED}Chua chon muc nao.${NC}"
                    else
                        echo ""
                        echo -e "${CYAN}${BOLD}Danh sach da chon xoa:${NC}"
                        echo "$WL_PREVIEW" | grep -v "^COUNT:"
                        WL_SEL_COUNT=$(echo "$WL_PREVIEW" | grep "^COUNT:" | cut -d: -f2)
                        echo ""
                        read -p "Xac nhan xoa $WL_SEL_COUNT thiet bi da chon? [y/N]: " WL_CONFIRM
                        if [[ "$WL_CONFIRM" == "y" || "$WL_CONFIRM" == "Y" ]]; then
                            WL_RESULT=$(remove_whitelist_devices_by_indices "$WL_IDX")
                            if [[ "$WL_RESULT" == *"REMOVED:"* ]]; then
                                WL_RM_COUNT=$(echo "$WL_RESULT" | grep "^COUNT:" | cut -d: -f2)
                                echo -e "${GREEN}✅ Da xoa $WL_RM_COUNT thiet bi.${NC}"
                                echo -e "${YELLOW}Cac thiet bi nay se phai qua Key Attestation binh thuong tu lan goi sau.${NC}"
                            else
                                echo -e "${RED}Loi: $WL_RESULT${NC}"
                            fi
                        else
                            echo -e "${YELLOW}Da huy.${NC}"
                        fi
                    fi
                fi
                ;;
            4)
                blocked_devices_menu
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}Lua chon khong hop le.${NC}"
                ;;
        esac
        echo ""
    done
}

signing_key_menu() {
    echo -e "${CYAN}${BOLD}--- Quan ly Signing Key (Ed25519) ---${NC}"
    echo ""
    if [ -f "$SIGNING_KEY_FILE" ] && [ -s "$SIGNING_KEY_FILE" ]; then
        echo -e "${YELLOW}Public key hien tai:${NC} $(print_public_key 2>/dev/null)"
    else
        echo -e "${YELLOW}Chua co signing key nao.${NC}"
    fi
    echo ""
    echo "  1) Export private key (dang base64) - de dung chung voi VPS khac"
    echo "  2) Import private key (dang base64) - tu VPS khac"
    echo "  3) Quay lai"
    echo ""
    read -p "Chon [1-3]: " SK_CHOICE
    echo ""
    case "$SK_CHOICE" in
        1)
            if [ ! -f "$SIGNING_KEY_FILE" ] || [ ! -s "$SIGNING_KEY_FILE" ]; then
                echo -e "${RED}Chua co signing key nao de export.${NC}"
                return
            fi
            EXPORTED=$(base64 -w0 "$SIGNING_KEY_FILE")
            echo -e "${GREEN}${BOLD}Private key (base64) - GIU BI MAT:${NC}"
            echo -e "${CYAN}$EXPORTED${NC}"
            echo ""
            echo -e "${YELLOW}Copy chuoi tren, chay 'mtunnel-token' tren VPS khac, chon${NC}"
            echo -e "${YELLOW}muc Signing Key -> Import, paste vao.${NC}"
            ;;
        2)
            echo -e "${YELLOW}Canh bao: se GHI DE signing key hien tai (neu co).${NC}"
            echo -e "${YELLOW}Public key cu se khong con verify duoc chu ky server nay nua.${NC}"
            echo ""
            read -p "Paste private key (base64) can import: " IMPORT_B64
            if [ -z "$IMPORT_B64" ]; then
                echo -e "${RED}Khong duoc de trong!${NC}"
                return
            fi
            VALID=$(python3 - << PYEOF
import base64
try:
    raw = base64.b64decode("$IMPORT_B64")
    if len(raw) != 32:
        print("invalid_length")
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        Ed25519PrivateKey.from_private_bytes(raw)
        print("ok")
except Exception as e:
    print("invalid:" + str(e))
PYEOF
)
            if [ "$VALID" != "ok" ]; then
                echo -e "${RED}Key khong hop le: $VALID${NC}"
                return
            fi
            python3 -c "
import base64
raw = base64.b64decode('$IMPORT_B64')
with open('$SIGNING_KEY_FILE', 'wb') as f:
    f.write(raw)
"
            chmod 600 "$SIGNING_KEY_FILE"
            chown www-data:www-data "$SIGNING_KEY_FILE" 2>/dev/null || true
            systemctl restart mtunnel-license 2>/dev/null || true
            echo -e "${GREEN}✅ Da import. Public key moi:${NC} $(print_public_key 2>/dev/null)"
            echo -e "${YELLOW}Nho cap nhat lai public key nay trong app neu khac ban cu.${NC}"
            ;;
        3) return ;;
        *) echo -e "${RED}Lua chon khong hop le.${NC}" ;;
    esac
}

while true; do
    show_header
    echo -e "${CYAN}Chon thao tac:${NC}"
    echo "  1) Doi token (thu hoi tat ca app dang dung token cu ngay lap tuc)"
    echo "  2) Xem Server Public Key (Ed25519 - verify chu ky /api/config)"
    echo "  3) Xem TLS Pin (dung cho pinning HTTPS ben app)"
    echo "  4) Xem trang thai server (/health)"
    echo "  5) Xem log realtime (Ctrl+C de quay lai menu)"
    echo "  6) Restart service"
    echo "  7) Quan ly Signing Key (Export/Import giua cac VPS)"
    echo "  8) Quan ly DEX Hash Allow-list (/api/dex-verify)"
    echo "  9) Quan ly Attestation Whitelist (cho phep may root hoat dong)"
    echo "  10) Quan ly Signing Hash Allow-list (Key Attestation - chong resign/inject APK)"
    echo "  11) Thoat"
    echo ""
    read -p "Nhap lua chon [1-11]: " CHOICE
    echo ""

    case "$CHOICE" in
        1)
            echo -e "${CYAN}Huong dan lay token:${NC}"
            echo "  1. Build release APK (cung keystore)"
            echo "  2. Chay app tren thiet bi"
            echo "  3. Token hien trong AlertDialog luc khoi dong"
            echo "  4. Copy token roi paste vao day"
            echo ""
            read -p "Nhap token moi: " NEW_TOKEN
            if [ -z "$NEW_TOKEN" ]; then
                echo -e "${RED}Token khong duoc de trong!${NC}"
            else
                echo "$NEW_TOKEN" > "$TOKEN_FILE"
                chmod 600 "$TOKEN_FILE"
                chown www-data:www-data "$TOKEN_FILE" 2>/dev/null || true
                systemctl restart mtunnel-license 2>/dev/null || true
                echo -e "${GREEN}✅ Token da cap nhat: ${NEW_TOKEN:0:8}...${NEW_TOKEN: -4}${NC}"
            fi
            ;;
        2)
            echo -e "${CYAN}Server Public Key (Ed25519):${NC}"
            echo -e "  ${BOLD}$(print_public_key 2>/dev/null)${NC}"
            echo -e "${YELLOW}(dan vao SERVER_PUBLIC_KEYS_B64[] ben Android)${NC}"
            ;;
        3)
            if [ -x "$INSTALL_DIR/print_tlspin.sh" ]; then
                "$INSTALL_DIR/print_tlspin.sh"
            else
                echo -e "${RED}Chua co script print_tlspin.sh — cai dat lai hoac tao thu cong.${NC}"
            fi
            ;;
        4)
            echo -e "${CYAN}Trang thai server (port $SSL_PORT):${NC}"
            curl -s "https://127.0.0.1:$SSL_PORT/health" -k || echo -e "${RED}Khong ket noi duoc toi server.${NC}"
            echo ""
            ;;
        5)
            echo -e "${YELLOW}Dang xem log realtime — nhan Ctrl+C de quay lai menu${NC}"
            echo ""
            journalctl -u mtunnel-license -f
            ;;
        6)
            systemctl restart mtunnel-license
            sleep 1
            if systemctl is-active --quiet mtunnel-license; then
                echo -e "${GREEN}✅ Service da restart thanh cong.${NC}"
            else
                echo -e "${RED}Service khong khoi dong duoc — xem: journalctl -u mtunnel-license -e${NC}"
            fi
            ;;
        7)
            signing_key_menu
            ;;
        8)
            dex_hash_menu
            ;;
        9)
            attestation_whitelist_menu
            ;;
        10)
            signing_hash_menu
            ;;
        11)
            echo "Tam biet."
            exit 0
            ;;
        *)
            echo -e "${RED}Lua chon khong hop le.${NC}"
            ;;
    esac
    pause
done
TKEOF

chmod +x "$INSTALL_DIR/mtunnel-menu.sh"
ln -sf "$INSTALL_DIR/mtunnel-menu.sh" /usr/local/bin/mtunnel-token
log "Menu quan ly tong hop da tao — go 'mtunnel-token' de mo (doi token/pubkey/TLS pin/health/log/restart/signing-key/dex-hash/attestation-whitelist)"

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
# LUU Y: script nay CHI in ra key dung de verify CHU KY /api/config
# (Ed25519, tach biet hoan toan voi chung chi TLS). KHONG dung gia tri
# nay lam TLS pin — xem muc "TLS_PINNED_PUBKEY_SHA256" duoc in rieng
# o buoc 8d ben duoi, do 2 loai key nay khac nhau hoan toan va tron
# ten voi nhau la nguyen nhan gay loi config khong tai duoc ve truoc day.
cat > "$INSTALL_DIR/print_pubkey.py" << 'PYEOF'
#!/usr/bin/env python3
import base64, sys

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

# Chi 1 gia tri duy nhat - dung de verify CHU KY config, KHONG lien quan TLS
print(f"SERVER_PUBLIC_KEY_B64={base64.b64encode(pub_raw).decode()}")
print("(Gia tri nay dung cho SERVER_PUBLIC_KEYS_B64[] ben Android, de verify chu ky /api/config.")
print(" KHONG dung cho TLS pin — chay 'mtunnel-tlspin' de lay TLS pin rieng.)")
PYEOF
chmod +x "$INSTALL_DIR/print_pubkey.py"
ln -sf "$INSTALL_DIR/print_pubkey.py" /usr/local/bin/mtunnel-pubkey
log "Script hien thi signing pubkey da tao — lenh: mtunnel-pubkey"

# ── 6c. Doi signing key duoc tao (server tao luc khoi dong) ─
log "Doi service tao signing key..."
for i in $(seq 1 10); do
    [ -f "$INSTALL_DIR/.signing_key" ] && break
    sleep 1
done

if [ -f "$INSTALL_DIR/.signing_key" ]; then
    PUBKEY_OUT=$(python3 "$INSTALL_DIR/print_pubkey.py" 2>/dev/null || true)
    SERVER_PUBLIC_KEY_B64=$(echo "$PUBKEY_OUT" | grep '^SERVER_PUBLIC_KEY_B64=' | cut -d= -f2-)
else
    warn "Khong thay signing key sau 10s — kiem tra: journalctl -u mtunnel-license -e"
    SERVER_PUBLIC_KEY_B64="(chua co - chay 'mtunnel-pubkey' sau)"
fi

# ── 6d. Hoi rieng ve Cloudflare Proxy — anh huong TRUC TIEP toi TLS
#        pin (khac hoan toan voi signing key o tren). Neu domain bat
#        Proxy (orange cloud), client se bat tay TLS voi CHUNG CHI CUA
#        CLOUDFLARE (vd Google Trust Services), khong phai chung chi
#        cua VPS nay — nen KHONG THE tinh pin cuc bo tren may nay duoc,
#        phai lay tu ben ngoai sau khi cai xong.
CF_PROXIED="n"
if [ "$SSL_METHOD" = "1" ]; then
    echo ""
    echo -e "${CYAN}${BOLD}--- Cloudflare Proxy status cho domain nay ---${NC}"
    echo -e "${YELLOW}Vao Cloudflare Dashboard > DNS, xem dong ban ghi cua domain nay${NC}"
    echo -e "${YELLOW}(hoac ban ghi wildcard *.domain neu khong co dong rieng):${NC}"
    echo -e "${YELLOW}  - May xam (DNS only)  -> chon 'k'${NC}"
    echo -e "${YELLOW}  - May cam (Proxied)   -> chon 'c'${NC}"
    printf "${CYAN}Domain nay dang Proxied (cam) tren Cloudflare?${NC} (c/k) [k]: "
    read CF_PROXIED_ANS
    if [ "$CF_PROXIED_ANS" = "c" ] || [ "$CF_PROXIED_ANS" = "C" ]; then
        CF_PROXIED="y"
        warn "Domain Proxied — TLS pin PHAI lay tu ben ngoai sau khi cai xong (xem huong dan cuoi script)."
        warn "Cert client thay se la cert cua Cloudflare (dung chung cho ca zone), co the doi theo chu ky renew cua Cloudflare."
    fi
fi

# ── 7a. Do cong SSL (port 80/443 co the da bi service khac nhu ────
#        psiphond chiem dung tren ca 2 port, nen dung DNS-01 challenge
#        thay vi HTTP-01 — khong can port 80 nua)
is_port_free() {
    # Tra ve 0 (true) neu khong co process nao dang LISTEN tren port $1
    ! ss -Htln "( sport = :$1 )" 2>/dev/null | grep -q .
}

if is_port_free 443; then
    SSL_PORT=443
    log "Port 443 dang trong, se dung port mac dinh 443 cho HTTPS"
else
    warn "Port 443 dang bi service khac chiem dung (vd VPN/psiphond) — se dung port thay the"
    SSL_PORT=8443
    while ! is_port_free "$SSL_PORT"; do
        warn "Port $SSL_PORT cung dang bi chiem, thu port ke tiep..."
        SSL_PORT=$((SSL_PORT + 1))
    done
    log "Se dung port $SSL_PORT cho HTTPS thay vi 443"
fi

# Luu SSL_PORT vao .config de cac lenh quan ly sau nay (mtunnel-token menu)
# doc lai duoc — luc ghi CONFIG_FILE lan dau (buoc 3) chua biet port nay.
echo "SSL_PORT=$SSL_PORT" >> "$CONFIG_FILE"

# ── 7b/8a. Lay chung chi SSL theo phuong thuc da chon ────────
if [ "$SSL_METHOD" = "1" ]; then
    # Luu Cloudflare credentials cho certbot dns plugin
    mkdir -p /root/.secrets/certbot
    cat > /root/.secrets/certbot/cloudflare.ini << CFEOF
dns_cloudflare_api_token = $CF_TOKEN
CFEOF
    chmod 600 /root/.secrets/certbot/cloudflare.ini

    # Xin chung chi SSL qua DNS-01 (khong can port 80/443). Vi psiphond
    # dang chiem dung ca port 80 va co the ca 443, HTTP-01 challenge
    # (can port 80 mo) khong the dung duoc. DNS-01 challenge xac thuc
    # qua ban ghi TXT tren Cloudflare, hoan toan khong dung den port
    # 80/443 cua may chu, nen tranh duoc xung dot nay.
    log "Xin SSL certificate cho $DOMAIN (DNS-01 qua Cloudflare)..."
    if ! certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
        --dns-cloudflare-propagation-seconds 30 \
        -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive > /tmp/certbot.log 2>&1; then
        error "Cap SSL that bai. Chi tiet: cat /tmp/certbot.log (thuong do Cloudflare API Token sai quyen, hoac domain $DOMAIN khong nam trong zone Cloudflare cua token nay)"
    fi
    log "SSL da cap xong"

    CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
else
    # Luu chung chi + private key nguoi dung da dan (vd Cloudflare Origin CA)
    log "Luu chung chi SSL da dan..."
    mkdir -p /etc/ssl/mtunnel
    printf '%s' "$CERT_PEM" > /etc/ssl/mtunnel/fullchain.pem
    printf '%s' "$KEY_PEM"  > /etc/ssl/mtunnel/privkey.pem
    chmod 644 /etc/ssl/mtunnel/fullchain.pem
    chmod 600 /etc/ssl/mtunnel/privkey.pem

    if ! openssl x509 -in /etc/ssl/mtunnel/fullchain.pem -noout > /tmp/cert-check.log 2>&1; then
        error "Chung chi khong hop le. Chi tiet: cat /tmp/cert-check.log"
    fi
    if ! openssl pkey -in /etc/ssl/mtunnel/privkey.pem -noout > /tmp/key-check.log 2>&1; then
        error "Private key khong hop le. Chi tiet: cat /tmp/key-check.log"
    fi

    CERT_PUBKEY_HASH=$(openssl x509 -in /etc/ssl/mtunnel/fullchain.pem -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)
    KEY_PUBKEY_HASH=$(openssl pkey -in /etc/ssl/mtunnel/privkey.pem -pubout -outform DER 2>/dev/null | sha256sum)
    if [ "$CERT_PUBKEY_HASH" != "$KEY_PUBKEY_HASH" ]; then
        error "Chung chi va Private Key KHONG khop nhau (public key khac nhau) — kiem tra lai da dan dung cap chua"
    fi

    CERT_EXPIRY=$(openssl x509 -in /etc/ssl/mtunnel/fullchain.pem -noout -enddate | cut -d= -f2)
    log "Chung chi hop le, khop voi private key. Het han: $CERT_EXPIRY"

    CERT_PATH="/etc/ssl/mtunnel/fullchain.pem"
    KEY_PATH="/etc/ssl/mtunnel/privkey.pem"
fi

# ── 8b. Cau hinh Nginx — chi 1 server block HTTPS tren SSL_PORT ─
# Khong tao block "listen 80" vi port 80 dang bi service khac (vd
# psiphond) chiem, nginx se khong the bind duoc port do.
log "Cau hinh Nginx..."
if [ "$SSL_METHOD" = "1" ]; then
    SSL_EXTRA_CONF="    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;"
else
    SSL_EXTRA_CONF="    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;"
fi

cat > /etc/nginx/sites-available/mtunnel << NGXEOF
server {
    listen $SSL_PORT ssl;
    listen [::]:$SSL_PORT ssl;
    server_name $DOMAIN;

    ssl_certificate     $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
$SSL_EXTRA_CONF

    location /api/events {
        proxy_pass            http://127.0.0.1:5000;
        proxy_set_header      Host \$host;
        proxy_set_header      X-Real-IP \$remote_addr;
        proxy_buffering       off;
        proxy_cache           off;
        proxy_read_timeout    3600s;
        proxy_send_timeout    3600s;
        keepalive_timeout     3600s;
        chunked_transfer_encoding on;
        gzip                  off;
    }

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
rm -f /etc/nginx/sites-enabled/default

if command -v ufw > /dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "$SSL_PORT"/tcp > /dev/null 2>&1
    log "Da mo port $SSL_PORT tren ufw"
fi

# Certbot cai qua pip venv o buoc 1b CHI co plugin certbot-dns-cloudflare,
# KHONG co plugin certbot-nginx (--nginx). Nen certbot khong tu sinh ra
# /etc/letsencrypt/options-ssl-nginx.conf va ssl-dhparams.pem nhu khi cai
# qua apt/snap ban dan co plugin nginx di kem. Config nginx o tren lai
# "include" 2 file nay khi SSL_METHOD=1 -> tu tao neu chua co, tranh loi
# "failed (2: No such file or directory)" luc nginx -t.
if [ "$SSL_METHOD" = "1" ]; then
    if [ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]; then
        log "Tao /etc/letsencrypt/options-ssl-nginx.conf (certbot venv khong tu sinh vi thieu plugin nginx)..."
        mkdir -p /etc/letsencrypt
        cat > /etc/letsencrypt/options-ssl-nginx.conf << 'SSLOPTEOF'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
SSLOPTEOF
    fi
    if [ ! -f /etc/letsencrypt/ssl-dhparams.pem ]; then
        log "Tao /etc/letsencrypt/ssl-dhparams.pem (co the mat 1-3 phut)..."
        openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 > /dev/null 2>&1
    fi
fi

if ! nginx -t > /tmp/nginx-test.log 2>&1; then
    error "Nginx config loi. Chi tiet: $(cat /tmp/nginx-test.log)"
fi

# Dung "restart" thay vi "reload" vi nginx co the dang o trang thai
# inactive/chua tung chay (vd do port 80 mac dinh bi chiem tu truoc),
# "reload" se khong lam gi neu service dang khong active.
systemctl restart nginx
if ! systemctl is-active --quiet nginx; then
    error "Nginx khong khoi dong duoc. Kiem tra: journalctl -xeu nginx --no-pager | tail -30"
fi
log "Nginx da chay HTTPS tren port $SSL_PORT"

# ── 8d. Tao lenh mtunnel-tlspin — TACH BIET hoan toan voi mtunnel-pubkey ──
# mtunnel-pubkey  = Ed25519 signing key (verify chu ky /api/config)
# mtunnel-tlspin  = pubkey hash cua CHUNG CHI TLS (dung de pin HTTPS)
# Day la 2 khai niem khac nhau — tron 2 cai nay la nguyen nhan pho bien
# nhat khien app khong tai duoc config du server hoat dong binh thuong.
cat > "$INSTALL_DIR/print_tlspin.sh" << TLSPINEOF
#!/bin/bash
DOMAIN="$DOMAIN"
SSL_PORT="$SSL_PORT"
SSL_METHOD="$SSL_METHOD"
CF_PROXIED="$CF_PROXIED"
CERT_PATH="$CERT_PATH"

if [ "\$CF_PROXIED" = "y" ]; then
    echo "Domain nay dang Proxied qua Cloudflare — KHONG THE tinh TLS pin"
    echo "chinh xac tu chinh VPS nay (client thay cert cua Cloudflare, khac"
    echo "voi cert goc tren VPS)."
    echo ""
    echo "Chay lenh sau tu MOT MAY KHAC (dien thoai 4G, laptop ca nhan —"
    echo "KHONG phai tu VPS nay, de tranh NAT hairpin cho ket qua sai):"
    echo ""
    echo "  openssl s_client -connect \$DOMAIN:\$SSL_PORT </dev/null 2>/dev/null \\"
    echo "    | openssl x509 -pubkey -noout \\"
    echo "    | openssl pkey -pubin -outform der \\"
    echo "    | openssl dgst -sha256 -binary \\"
    echo "    | base64"
    echo ""
    echo "Ket qua la TLS_PINNED_PUBKEY_SHA256 — dan vao PINNED_PUBKEYS_SHA256[]"
    echo "ben Android voi tien to 'sha256//'. LUU Y: vi cert nay do Cloudflare"
    echo "quan ly (co the dung chung cho nhieu domain trong cung zone va tu"
    echo "doi khi Cloudflare renew), can chay lai lenh nay dinh ky de kiem tra"
    echo "pin con dung khong, dac biet neu app bao loi tai config dot ngot."
else
    echo "Domain KHONG proxy (DNS only) — tinh truc tiep tu chung chi cuc bo:"
    echo ""
    PIN=\$(openssl x509 -in "\$CERT_PATH" -noout -pubkey 2>/dev/null \\
        | openssl pkey -pubin -outform der 2>/dev/null \\
        | openssl dgst -sha256 -binary \\
        | base64)
    echo "TLS_PINNED_PUBKEY_SHA256 = sha256//\$PIN"
    echo ""
    echo "Dan gia tri tren vao PINNED_PUBKEYS_SHA256[] ben Android."
fi
TLSPINEOF
chmod +x "$INSTALL_DIR/print_tlspin.sh"
ln -sf "$INSTALL_DIR/print_tlspin.sh" /usr/local/bin/mtunnel-tlspin
log "Script tinh TLS pin da tao — lenh: mtunnel-tlspin"

# ── 8c. Auto-renew (chi ap dung cho phuong thuc 1 — Let's Encrypt):
#        certbot renew se tu dung lai dns-cloudflare plugin (da luu
#        trong renewal config). Chi can dam bao nginx reload sau renew.
#        Phuong thuc 2 (tu dan chung chi) khong can renew tu dong —
#        chung chi Origin CA thuong co han rat dai (vd 15 nam).
if [ "$SSL_METHOD" = "1" ]; then
    if [ -f /etc/letsencrypt/renewal/$DOMAIN.conf ] && ! grep -q "renew_hook" /etc/letsencrypt/renewal/$DOMAIN.conf; then
        echo "renew_hook = systemctl reload nginx" >> /etc/letsencrypt/renewal/$DOMAIN.conf
    fi

    # Vi certbot gio nam trong pip venv (khong phai apt), goi apt khong tu
    # tao san cron/systemd timer de renew nhu binh thuong -> tu tao rieng.
    log "Tao systemd timer tu-gia-han SSL..."
    cat > /etc/systemd/system/certbot-renew.service << RENEWSVCEOF
[Unit]
Description=Certbot renew (mtunnel, pip venv)

[Service]
Type=oneshot
ExecStart=$CERTBOT_VENV/bin/certbot renew --quiet
RENEWSVCEOF

    cat > /etc/systemd/system/certbot-renew.timer << RENEWTIMEREOF
[Unit]
Description=Chay certbot renew 2 lan/ngay (mtunnel)

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
RENEWTIMEREOF

    systemctl daemon-reload
    systemctl enable --now certbot-renew.timer
    log "Timer tu-gia-han da bat: systemctl list-timers certbot-renew.timer"
fi

# ── 9. Thiết lập token lần đầu ───────────────────────────────
echo ""
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}${BOLD}   Buoc cuoi: Thiet lap Token              ${NC}"
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}Huong dan lay token:${NC}"
echo "  1. Build release APK (cung keystore)"
echo "  2. Chay app tren thiet bi"
echo "  3. Token hien trong AlertDialog luc khoi dong"
echo "  4. Copy token roi paste vao day"
echo ""
read -p "Nhap token (Enter de bo qua, thiet lap sau bang 'mtunnel-token'): " NEW_TOKEN
if [ -n "$NEW_TOKEN" ]; then
    echo "$NEW_TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    chown www-data:www-data "$TOKEN_FILE" 2>/dev/null || true
    systemctl restart mtunnel-license 2>/dev/null || true
    log "Token da thiet lap: ${NEW_TOKEN:0:8}...${NEW_TOKEN: -4}"
else
    warn "Bo qua — /api/verify va /api/config se tra loi 'server_not_configured' cho toi khi chay 'mtunnel-token' de thiet lap."
fi

# ── Hoàn tất ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Cai dat hoan tat!                       ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Verify URL : ${BOLD}https://$DOMAIN:$SSL_PORT/api/verify${NC}"
echo -e "  ⚙️  Config URL : ${BOLD}https://$DOMAIN:$SSL_PORT/api/config${NC}"
echo -e "  📡 SSE URL    : ${BOLD}https://$DOMAIN:$SSL_PORT/api/events${NC}"
echo -e "  📦 Package    : ${BOLD}$PACKAGE${NC}"
echo ""
echo -e "${YELLOW}${BOLD}[1/2] Ed25519 signing key — de verify CHU KY /api/config:${NC}"
echo -e "  SERVER_PUBLIC_KEY_B64 : ${BOLD}$SERVER_PUBLIC_KEY_B64${NC}"
echo -e "  (dan vao SERVER_PUBLIC_KEYS_B64[] ben Android)"
echo ""
echo -e "${YELLOW}${BOLD}[2/2] TLS certificate pin — DE RIENG, KHAC HOAN TOAN voi key o tren:${NC}"
if [ "$CF_PROXIED" = "y" ]; then
    echo -e "  Domain dang Proxied qua Cloudflare — KHONG tinh duoc tai day."
    echo -e "  Chay lenh ${BOLD}mtunnel-tlspin${NC} de xem huong dan lay pin tu ben ngoai."
else
    TLSPIN_NOW=$("$INSTALL_DIR/print_tlspin.sh" 2>/dev/null | grep '^TLS_PINNED_PUBKEY_SHA256' || true)
    echo -e "  ${BOLD}$TLSPIN_NOW${NC}"
    echo -e "  (dan vao PINNED_PUBKEYS_SHA256[] ben Android)"
fi
echo ""
if [ "$SSL_METHOD" = "2" ]; then
    echo -e "${YELLOW}${BOLD}⚠️  Luu y ve chung chi tu dan (vd Cloudflare Origin CA):${NC}"
    echo -e "  Chung chi nay KHONG duoc he thong/trinh duyet tin cay mac dinh."
    echo -e "  App phai tu pin chung chi nay (hoac root CA cua no) trong"
    echo -e "  network_security_config.xml, neu khong ket noi HTTPS se that bai."
    echo -e "  Het han: ${BOLD}$CERT_EXPIRY${NC}"
    echo -e "  Chung chi Origin CA CHI hop le neu domain o che do DNS only —"
    echo -e "  neu ban dang bat Proxy (Cloudflare cam), client se KHONG BAO GIO"
    echo -e "  thay chung chi nay, setup se khong hoat dong dung."
    echo ""
fi
echo -e "${CYAN}${BOLD}Quan ly server — chi can nho 1 lenh duy nhat:${NC}"
echo -e "  ${BOLD}mtunnel-token${NC}  ← mo menu: doi token / xem pubkey / TLS pin /"
echo -e "                  health / log / restart / signing-key export-import"
echo ""
echo -e "  Port dang dung : ${BOLD}$SSL_PORT${NC} $([ "$SSL_PORT" != "443" ] && echo "(khac 443 vi port 443 dang bi service khac chiem)")"
echo -e "  Xem log truc tiep (khong qua menu): journalctl -u mtunnel-license -f"
echo ""
echo -e "${CYAN}Thu hoi license:${NC}"
echo -e "  Server hien chi ho tro MOT token dung chung cho toan bo app."
echo -e "  De thu hoi tat ca app dang dung token cu: chay ${BOLD}mtunnel-token${NC} → chon muc 1"
echo ""
