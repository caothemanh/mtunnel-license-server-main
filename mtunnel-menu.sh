#!/bin/bash
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'
WHITE='\033[1;37m'
BLUE='\033[1;34m'
PINK='\033[1;35m'
BGRED='\033[41;1;37m'

INSTALL_DIR="/opt/mtunnel"
PANEL_GITHUB_RAW="https://raw.githubusercontent.com/caothemanh/mtunnel-license-server-main/main"
TOKEN_FILE="$INSTALL_DIR/.token"
CONFIG_FILE="$INSTALL_DIR/.config"
SIGNING_KEY_FILE="$INSTALL_DIR/.signing_key"
ATTESTATION_SIGNING_HASHES_FILE="$INSTALL_DIR/.attestation_signing_hashes.json"
DEVICE_WHITELIST_FILE="$INSTALL_DIR/.attestation_whitelist.json"
DEVICE_BLOCKED_FILE="$INSTALL_DIR/.attestation_blocked_devices.json"
GITHUB_REPO_FILE="$INSTALL_DIR/.github_repo"
GITHUB_TOKEN_FILE="$INSTALL_DIR/.github_token"
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
    local cols
    cols=$(tput cols 2>/dev/null)
    [ -z "$cols" ] && cols=60
    [ "$cols" -lt 40 ] && cols=60
    local line
    line=$(printf '%*s' "$cols" '' | tr ' ' '═')

    echo -e "${BLUE}${line}${NC}"
    printf "${BGRED} ⚡ MTUNNEL LICENSE SERVER - QUẢN LÝ%*s${NC}\n" "$((cols>36?cols-36:0))" ""
    echo -e "${BLUE}${line}${NC}"
    echo -e "  ${PINK}Domain :${NC} ${WHITE}$DOMAIN${NC}"
    echo -e "  ${PINK}Port   :${NC} ${WHITE}$SSL_PORT${NC}"
    echo -e "  ${PINK}Package:${NC} ${WHITE}$PACKAGE${NC}"
    if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
        CURRENT=$(cat "$TOKEN_FILE")
        echo -e "  ${PINK}Token  :${NC} ${WHITE}${CURRENT:0:8}...${CURRENT: -4}${NC}"
    else
        echo -e "  ${PINK}Token  :${NC} ${YELLOW}(chưa thiết lập)${NC}"
    fi
    echo -e "${BLUE}${line}${NC}"
    echo ""
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
        bl_tag = " [DA BLACKLIST - tu choi thang moi request]" if info.get("blacklisted") else ""
        print(f"  {i}) {device_id}{bl_tag}")
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
        echo -e "${YELLOW}dang mo khoa. Nhung thiet bi co bang chung root/mo khoa that${NC}"
        echo -e "${YELLOW}su se duoc tu dong danh dau [DA BLACKLIST] va bi TU CHOI THANG${NC}"
        echo -e "${YELLOW}moi request /api/config tiep theo — khong can lam gi them.${NC}"
        echo -e "${YELLOW}Muon mo lai cho 1 may: dung muc 1 (them vao whitelist) hoac${NC}"
        echo -e "${YELLOW}muc 2 (xoa khoi danh sach nay se go blacklist).${NC}"
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
                echo -e "${YELLOW}Go 'all' de xoa tat ca. Enter de huy. (Xoa se go blacklist neu co, khong anh huong whitelist)${NC}"
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

github_config_menu() {
    echo -e "${CYAN}${BOLD}--- Cau hinh GitHub cho /api/config ---${NC}"
    echo ""
    if [ -f "$GITHUB_REPO_FILE" ] && [ -s "$GITHUB_REPO_FILE" ]; then
        CUR_OWNER=$(grep "^OWNER=" "$GITHUB_REPO_FILE" | cut -d= -f2-)
        CUR_REPO=$(grep "^REPO=" "$GITHUB_REPO_FILE" | cut -d= -f2-)
        CUR_BRANCH=$(grep "^BRANCH=" "$GITHUB_REPO_FILE" | cut -d= -f2-)
        CUR_PATH=$(grep "^PATH=" "$GITHUB_REPO_FILE" | cut -d= -f2-)
        echo -e "${YELLOW}Cau hinh hien tai:${NC}"
        echo "  Owner  : ${CUR_OWNER:-(rong)}"
        echo "  Repo   : ${CUR_REPO:-(rong)}"
        echo "  Branch : ${CUR_BRANCH:-(rong)}"
        echo "  Path   : ${CUR_PATH:-(rong)}"
        if [ -f "$GITHUB_TOKEN_FILE" ] && [ -s "$GITHUB_TOKEN_FILE" ]; then
            echo "  Token  : da luu (an)"
        else
            echo -e "  Token  : ${RED}chua co${NC}"
        fi
    else
        echo -e "${RED}Chua cau hinh GitHub — /api/config dang tra loi 500 (config_unavailable).${NC}"
    fi
    echo ""
    echo "  1) Nhap/Cap nhat cau hinh GitHub (owner, repo, branch, path, token)"
    echo "  2) Xoa cau hinh GitHub"
    echo "  3) Quay lai"
    echo ""
    read -p "Chon [1-3]: " GH_CHOICE
    echo ""
    case "$GH_CHOICE" in
        1)
            printf "${CYAN}GitHub owner${NC} [vd: caothemanh]${CUR_OWNER:+ (Enter de giu \"$CUR_OWNER\")}: "
            read GH_OWNER_NEW
            GH_OWNER_NEW=${GH_OWNER_NEW:-$CUR_OWNER}
            printf "${CYAN}GitHub repo${NC} [vd: mtunnel-config]${CUR_REPO:+ (Enter de giu \"$CUR_REPO\")}: "
            read GH_REPO_NEW
            GH_REPO_NEW=${GH_REPO_NEW:-$CUR_REPO}
            printf "${CYAN}Branch${NC} [main]${CUR_BRANCH:+ (Enter de giu \"$CUR_BRANCH\")}: "
            read GH_BRANCH_NEW
            GH_BRANCH_NEW=${GH_BRANCH_NEW:-${CUR_BRANCH:-main}}
            printf "${CYAN}Duong dan file trong repo${NC} [vd: config.enc]${CUR_PATH:+ (Enter de giu \"$CUR_PATH\")}: "
            read GH_PATH_NEW
            GH_PATH_NEW=${GH_PATH_NEW:-$CUR_PATH}
            printf "${CYAN}GitHub Personal Access Token (PAT, an khi go, Enter de giu token cu)${NC}: "
            read -s GH_TOKEN_NEW
            echo ""

            if [ -z "$GH_OWNER_NEW" ] || [ -z "$GH_REPO_NEW" ] || [ -z "$GH_PATH_NEW" ]; then
                echo -e "${RED}Owner, Repo va Duong dan file khong duoc de trong. Da huy.${NC}"
                return
            fi
            if [ -z "$GH_TOKEN_NEW" ] && [ ! -s "$GITHUB_TOKEN_FILE" ]; then
                echo -e "${RED}Chua co token cu de giu lai — phai nhap token. Da huy.${NC}"
                return
            fi

            cat > "$GITHUB_REPO_FILE" << GHEOF
OWNER=$GH_OWNER_NEW
REPO=$GH_REPO_NEW
BRANCH=$GH_BRANCH_NEW
PATH=$GH_PATH_NEW
GHEOF
            chmod 600 "$GITHUB_REPO_FILE"
            chown www-data:www-data "$GITHUB_REPO_FILE" 2>/dev/null || true

            if [ -n "$GH_TOKEN_NEW" ]; then
                echo "$GH_TOKEN_NEW" > "$GITHUB_TOKEN_FILE"
                chmod 600 "$GITHUB_TOKEN_FILE"
                chown www-data:www-data "$GITHUB_TOKEN_FILE" 2>/dev/null || true
            fi

            systemctl restart mtunnel-license 2>/dev/null || true
            echo -e "${GREEN}✅ Da luu cau hinh GitHub (owner=$GH_OWNER_NEW repo=$GH_REPO_NEW branch=$GH_BRANCH_NEW path=$GH_PATH_NEW).${NC}"
            echo -e "${YELLOW}Kiem tra lai bang menu 4 (Xem trang thai server) hoac /api/config.${NC}"
            ;;
        2)
            read -p "Xac nhan xoa cau hinh GitHub? /api/config se ngung hoat dong cho toi khi cau hinh lai. [y/N]: " GH_CONFIRM
            if [[ "$GH_CONFIRM" == "y" || "$GH_CONFIRM" == "Y" ]]; then
                rm -f "$GITHUB_REPO_FILE" "$GITHUB_TOKEN_FILE"
                systemctl restart mtunnel-license 2>/dev/null || true
                echo -e "${GREEN}✅ Da xoa cau hinh GitHub.${NC}"
            else
                echo -e "${YELLOW}Da huy.${NC}"
            fi
            ;;
        3) return ;;
        *) echo -e "${RED}Lua chon khong hop le.${NC}" ;;
    esac
}

change_port_menu() {
    echo -e "${CYAN}${BOLD}--- Doi port HTTPS ---${NC}"
    echo ""
    echo -e "Port hien tai: ${BOLD}$SSL_PORT${NC}"
    echo ""
    read -p "Nhap port moi (Enter de huy): " NEW_PORT
    if [ -z "$NEW_PORT" ]; then
        echo -e "${YELLOW}Da huy.${NC}"
        return
    fi
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        echo -e "${RED}Port khong hop le (phai la so tu 1-65535).${NC}"
        return
    fi
    if [ "$NEW_PORT" = "$SSL_PORT" ]; then
        echo -e "${YELLOW}Port moi giong port hien tai, khong co gi de doi.${NC}"
        return
    fi
    if ss -Htln "( sport = :$NEW_PORT )" 2>/dev/null | grep -q .; then
        echo -e "${RED}Port $NEW_PORT dang bi service khac chiem dung tren may nay. Chon port khac.${NC}"
        return
    fi

    local NGINX_CONF="/etc/nginx/sites-available/mtunnel"
    if [ ! -f "$NGINX_CONF" ]; then
        echo -e "${RED}Khong tim thay $NGINX_CONF — khong the doi port tu dong.${NC}"
        return
    fi

    cp "$NGINX_CONF" "$NGINX_CONF.bak_before_port_change"
    sed -i "s/listen $SSL_PORT ssl;/listen $NEW_PORT ssl;/; s/listen \[::\]:$SSL_PORT ssl;/listen [::]:$NEW_PORT ssl;/" "$NGINX_CONF"

    if nginx -t 2>/tmp/nginx-port-test.log; then
        systemctl reload nginx
        if command -v ufw > /dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            ufw allow "$NEW_PORT"/tcp > /dev/null 2>&1
            read -p "Dong port cu ($SSL_PORT) tren ufw luon khong? [y/N]: " CLOSE_OLD
            if [[ "$CLOSE_OLD" == "y" || "$CLOSE_OLD" == "Y" ]]; then
                ufw delete allow "$SSL_PORT"/tcp > /dev/null 2>&1
                echo -e "${YELLOW}Da dong port $SSL_PORT tren ufw.${NC}"
            fi
        fi
        # Cap nhat .config de menu doc lai dung port cac lan sau
        if grep -q "^SSL_PORT=" "$CONFIG_FILE" 2>/dev/null; then
            sed -i "s/^SSL_PORT=.*/SSL_PORT=$NEW_PORT/" "$CONFIG_FILE"
        else
            echo "SSL_PORT=$NEW_PORT" >> "$CONFIG_FILE"
        fi
        OLD_PORT="$SSL_PORT"
        SSL_PORT="$NEW_PORT"
        rm -f "$NGINX_CONF.bak_before_port_change"
        echo -e "${GREEN}✅ Da doi port tu $OLD_PORT sang $NEW_PORT.${NC}"
        echo -e "${YELLOW}Nho cap nhat lai domain:port trong config app Android — client se khong ket noi duoc neu con tro port cu.${NC}"
    else
        cp "$NGINX_CONF.bak_before_port_change" "$NGINX_CONF"
        rm -f "$NGINX_CONF.bak_before_port_change"
        echo -e "${RED}Nginx config loi, da rollback ve port cu. Chi tiet:${NC}"
        cat /tmp/nginx-port-test.log
    fi
}

update_panel_from_github() {
    echo -e "${CYAN}${BOLD}CẬP NHẬT PANEL TỪ GITHUB${NC}"
    echo -e "${BLUE}─────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}Đang tải bản mới nhất từ:${NC} $PANEL_GITHUB_RAW"
    echo ""

    local TMP_MENU="/tmp/mtunnel-menu.sh.new"
    local TMP_SERVER="/tmp/mtunnel-server.py.new"

    if ! curl -fsSL -H "Cache-Control: no-cache" "${PANEL_GITHUB_RAW}/mtunnel-menu.sh?_=$(date +%s)" -o "$TMP_MENU"; then
        echo -e "${RED}✗ Tải mtunnel-menu.sh thất bại (kiểm tra kết nối mạng).${NC}"
        rm -f "$TMP_MENU"
        return 1
    fi
    if ! bash -n "$TMP_MENU" 2>/tmp/mtunnel-menu-update-err.log; then
        echo -e "${RED}✗ File mtunnel-menu.sh tải về lỗi cú pháp, HỦY cập nhật (giữ nguyên bản cũ):${NC}"
        sed 's/^/  /' /tmp/mtunnel-menu-update-err.log
        rm -f "$TMP_MENU"
        return 1
    fi

    if ! curl -fsSL -H "Cache-Control: no-cache" "${PANEL_GITHUB_RAW}/server.py?_=$(date +%s)" -o "$TMP_SERVER"; then
        echo -e "${RED}✗ Tải server.py thất bại — HỦY cập nhật (giữ nguyên bản cũ).${NC}"
        rm -f "$TMP_MENU" "$TMP_SERVER"
        return 1
    fi
    if ! python3 -m py_compile "$TMP_SERVER" 2>/tmp/mtunnel-server-update-err.log; then
        echo -e "${RED}✗ File server.py tải về lỗi cú pháp Python, HỦY cập nhật (giữ nguyên bản cũ):${NC}"
        sed 's/^/  /' /tmp/mtunnel-server-update-err.log
        rm -f "$TMP_MENU" "$TMP_SERVER"
        return 1
    fi

    mv "$TMP_MENU" "$INSTALL_DIR/mtunnel-menu.sh"
    chmod +x "$INSTALL_DIR/mtunnel-menu.sh"
    mv "$TMP_SERVER" "$INSTALL_DIR/server.py"
    chown www-data:www-data "$INSTALL_DIR/server.py" "$INSTALL_DIR/mtunnel-menu.sh" 2>/dev/null || true

    systemctl restart mtunnel-license 2>/dev/null || true
    echo -e "${GREEN}✓ Đã cập nhật mtunnel-menu.sh + server.py và restart service.${NC}"
    echo -e "${CYAN}Khởi động lại panel với bản mới...${NC}"
    sleep 1
    exec "$INSTALL_DIR/mtunnel-menu.sh"
}

uninstall_all() {
    echo -e "${RED}${BOLD}GỠ CÀI ĐẶT MTUNNEL LICENSE SERVER${NC}"
    echo -e "${BLUE}─────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}Thao tác này sẽ:${NC}"
    echo "  - Dừng & xoá service systemd mtunnel-license"
    echo "  - Xoá cấu hình Nginx site cho domain $DOMAIN"
    echo "  - Xoá lệnh tắt mtunnel-token / mtunnel-pubkey / mtunnel-tlspin"
    echo -e "  ${RED}- (tuỳ chọn) Xoá toàn bộ $INSTALL_DIR — signing key, token,${NC}"
    echo -e "${RED}    whitelist thiết bị, APK đã upload sẽ MẤT VĨNH VIỄN${NC}"
    echo ""
    read -p "Gõ chính xác chữ XOA để xác nhận gỡ cài đặt (Enter để huỷ): " CONFIRM
    if [ "$CONFIRM" != "XOA" ]; then
        echo -e "${YELLOW}Đã huỷ, không có gì bị xoá.${NC}"
        return 0
    fi

    echo ""
    echo -e "${CYAN}→${NC} Dừng & tắt service mtunnel-license..."
    systemctl stop mtunnel-license 2>/dev/null || true
    systemctl disable mtunnel-license 2>/dev/null || true
    rm -f /etc/systemd/system/mtunnel-license.service
    systemctl daemon-reload

    echo -e "${CYAN}→${NC} Xoá cấu hình Nginx..."
    rm -f /etc/nginx/sites-enabled/mtunnel /etc/nginx/sites-available/mtunnel
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true

    echo -e "${CYAN}→${NC} Xoá lệnh tắt (symlink)..."
    rm -f /usr/local/bin/mtunnel-token /usr/local/bin/mtunnel-pubkey /usr/local/bin/mtunnel-tlspin

    read -p "$(echo -e "${YELLOW}Xoá luôn chứng chỉ Let'\''s Encrypt của $DOMAIN? (y/N): ${NC}")" DEL_CERT
    if [ "$DEL_CERT" = "y" ] || [ "$DEL_CERT" = "Y" ]; then
        if command -v certbot >/dev/null 2>&1; then
            certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || \
                /opt/certbot-venv/bin/certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || \
                echo -e "${RED}  Không xoá được cert tự động, xoá tay tại /etc/letsencrypt/live/$DOMAIN nếu cần.${NC}"
        fi
    fi

    echo -e "${GREEN}✓ Đã gỡ service, Nginx site & lệnh tắt.${NC}"
    echo ""
    read -p "$(echo -e "${RED}${BOLD}Xoá LUÔN $INSTALL_DIR (signing key/token/whitelist/APK)? (y/N): ${NC}")" DEL_DIR
    if [ "$DEL_DIR" = "y" ] || [ "$DEL_DIR" = "Y" ]; then
        echo -e "${GREEN}✓ Đã xoá $INSTALL_DIR. Tạm biệt.${NC}"
        rm -rf "$INSTALL_DIR"
        exit 0
    else
        echo -e "${YELLOW}Đã giữ lại $INSTALL_DIR (chứa signing key/token cũ) — tự xoá tay nếu muốn.${NC}"
        exit 0
    fi
}

while true; do
    show_header
    echo -e "${CYAN}${BOLD}CHỌN THAO TÁC:${NC}"
    echo -e "  ${CYAN}[1]${NC}  ${YELLOW}ĐỔI TOKEN${NC} (thu hồi tất cả app đang dùng token cũ ngay lập tức)"
    echo -e "  ${CYAN}[2]${NC}  ${YELLOW}XEM SERVER PUBLIC KEY${NC} (Ed25519 - verify chữ ký /api/config)"
    echo -e "  ${CYAN}[3]${NC}  ${YELLOW}XEM TLS PIN${NC} (dùng cho pinning HTTPS bên app)"
    echo -e "  ${CYAN}[4]${NC}  ${YELLOW}XEM TRẠNG THÁI SERVER${NC} (/health)"
    echo -e "  ${CYAN}[5]${NC}  ${YELLOW}XEM LOG REALTIME${NC} (Ctrl+C để quay lại menu)"
    echo -e "  ${CYAN}[6]${NC}  ${YELLOW}RESTART SERVICE${NC}"
    echo -e "  ${CYAN}[7]${NC}  ${YELLOW}QUẢN LÝ SIGNING KEY${NC} (Export/Import giữa các VPS)"
    echo -e "  ${CYAN}[8]${NC}  ${YELLOW}QUẢN LÝ ATTESTATION WHITELIST${NC} (cho phép máy root hoạt động)"
    echo -e "  ${CYAN}[9]${NC}  ${YELLOW}QUẢN LÝ SIGNING HASH ALLOW-LIST${NC} (chống resign/inject APK)"
    echo -e "  ${CYAN}[10]${NC} ${YELLOW}CẤU HÌNH GITHUB CHO /API/CONFIG${NC} (owner/repo/branch/path/token)"
    echo -e "  ${CYAN}[11]${NC} ${YELLOW}ĐỔI PORT HTTPS${NC}"
    echo -e "${BLUE}  ─────────────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[12]${NC} ${YELLOW}CẬP NHẬT PANEL TỪ GITHUB${NC} (bản mới nhất)"
    echo -e "  ${CYAN}[13]${NC} ${RED}GỠ CÀI ĐẶT${NC} (xoá toàn bộ MTunnel License Server)"
    echo -e "  ${CYAN}[14]${NC} ${WHITE}THOÁT${NC}"
    echo ""
    read -p "Nhap lua chon [1-14]: " CHOICE
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
            attestation_whitelist_menu
            ;;
        9)
            signing_hash_menu
            ;;
        10)
            github_config_menu
            ;;
        11)
            change_port_menu
            ;;
        12)
            update_panel_from_github
            ;;
        13)
            uninstall_all
            ;;
        14)
            echo "Tam biet."
            exit 0
            ;;
        *)
            echo -e "${RED}Lua chon khong hop le.${NC}"
            ;;
    esac
    pause
done
