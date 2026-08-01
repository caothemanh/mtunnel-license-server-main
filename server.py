#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging, os, time, json, queue, threading, base64, hmac, hashlib, urllib.request, urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Rate-limit theo IP — chặn scrape hàng loạt (script tự động gọi /api/config
# hoặc /api/verify liên tục), không phải để chặn user thường (user thường
# chỉ gọi vài lần/ngày lúc mở app, không bao giờ chạm ngưỡng này).
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",   # đủ dùng cho 1 tiến trình gunicorn -w 1;
                               # nếu tăng lên nhiều worker, đổi sang Redis
                               # (storage_uri="redis://127.0.0.1:6379") để
                               # đếm chung giữa các worker thay vì mỗi worker
                               # đếm riêng (sẽ làm giới hạn thực tế cao hơn
                               # dự kiến theo đúng số worker).
    default_limits=[]         # không áp mặc định lên MỌI route (vd /health
                               # cần gọi thoải mái để healthcheck) — chỉ áp
                               # riêng lên từng route nhạy cảm bên dưới.
)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

INSTALL_DIR       = "/opt/mtunnel"
TOKEN_FILE        = os.path.join(INSTALL_DIR, ".token")
CONFIG_FILE       = os.path.join(INSTALL_DIR, ".config")
CONFIG_DATA_FILE  = os.path.join(INSTALL_DIR, ".config_data.json")
SIGNING_KEY_FILE  = os.path.join(INSTALL_DIR, ".signing_key")
GITHUB_TOKEN_FILE = os.path.join(INSTALL_DIR, ".github_token")
GITHUB_REPO_FILE  = os.path.join(INSTALL_DIR, ".github_repo")
DEVICE_BLOCKED_FILE = os.path.join(INSTALL_DIR, ".attestation_blocked_devices.json")
# Bảng ánh xạ "server_id" (tên logic, KHÔNG phải domain DNS public) -> IP thật
# phía sau (VPS chạy SSH/V2Ray/Psiphon). File này KHÔNG bao giờ được đưa vào
# DNS zone/Cloudflare — chỉ tồn tại ở đây và chỉ lộ ra qua /api/resolve sau
# khi verify token+attestation y hệt /api/config. Format:
#   {"servers": {"<server_id>": {"ip": "...", "port": 443, "note": "...",
#                                  "enabled": true, "updated_at": <epoch>}}}
RESOLVE_SERVERS_FILE = os.path.join(INSTALL_DIR, ".resolve_servers.json")
_resolve_servers_lock = threading.Lock()
# Whitelist SHA-256 (hex) của chữ ký ký APK thật (bản build gốc, có thể có
# nhiều giá trị khi đang rollout key mới) — xem compute_signing_hash.py.
# Đây là "nguồn sự thật" độc lập với _check_auth()/token, vì giá trị được
# đối chiếu lấy từ TRONG chain attestation phần cứng (AttestationApplicationId,
# tag 709), do system_server/Keystore điền, KHÔNG đi qua tiến trình app nên
# không bị xhook/"Kill Signature Verification" (MT Manager) đánh lừa được.
ATTESTATION_SIGNING_HASHES_FILE = os.path.join(INSTALL_DIR, ".attestation_signing_hashes.json")
# Danh sach hash DEX build hop le — tinh boi compute_dex_hash.py tren may
# build SAU KHI ky APK release. Format: {"allowed": ["<sha256 hex>", ...]}.
# Trong luc rollout ban moi, giu CA hash ban cu va ban moi trong "allowed"
# cho toi khi user cu da update het, roi moi xoa hash ban cu di.
DEX_HASHES_FILE = os.path.join(INSTALL_DIR, ".dex_hashes.json")


CACHE_TTL        = 3600
GITHUB_FETCH_TTL = 60
DEX_NONCE_TTL               = 60
ATTESTATION_NONCE_TTL       = 60
ATTESTATION_ROOT_CACHE_TTL  = 86400   # 24h — danh sách root Google ít khi đổi
                                        # (nhưng CÓ đổi, như đợt rotate 4/2026,
                                        # nên KHÔNG hardcode cứng, luôn fetch lại
                                        # định kỳ thay vì fix 1 lần rồi thôi)
GOOGLE_ATTESTATION_ROOT_URL = "https://android.googleapis.com/attestation/root"

# Danh sách serial number các key attestation ĐÃ BỊ THU HỒI (leak/compromise) —
# Google công bố tại URL này. BẮT BUỘC phải tra danh sách này, không chỉ dựa
# vào việc chain ký hợp lệ + root khớp Google: kẻ tấn công dùng 1 hardware
# keybox THẬT nhưng đã bị rò rỉ (vd qua module Magisk "TrickyStore") vẫn tạo
# ra được chain ký đúng 100%, root khớp Google, và tự khai verified_boot_state/
# device_locked "sạch" — vì các trường đó nằm trong chính chứng chỉ do kẻ tấn
# công tự dựng, không phải do TEE thật của máy đó sinh ra. Cách DUY NHẤT phát
# hiện được kiểu giả mạo này là đối chiếu serial number với danh sách thu hồi
# chính thức của Google (KHÔNG thể tự suy ra được từ nội dung chain).
GOOGLE_ATTESTATION_STATUS_URL = "https://android.googleapis.com/attestation/status"
ATTESTATION_STATUS_CACHE_TTL = 3600   # 1h — danh sách này cập nhật khá thường xuyên
                                       # (mỗi lần có keybox mới bị leak/revoke),
                                       # ngắn hơn nhiều so với cache root (86400s).

_attestation_nonces = {}
_attestation_nonce_lock = threading.Lock()
_dex_nonces = {}
_dex_nonce_lock = threading.Lock()

_attestation_roots_cache = {"certs": [], "fetched_at": 0}
_attestation_roots_lock = threading.Lock()

_attestation_status_cache = {"entries": {}, "fetched_at": 0}
_attestation_status_lock = threading.Lock()

_device_blocked_lock = threading.Lock()

_github_cache = {"bytes": None, "fetched_at": 0}

_sse_clients = []
_sse_lock = threading.Lock()

def _sse_add():
    q = queue.Queue(maxsize=10)
    with _sse_lock:
        _sse_clients.append(q)
    return q

def _sse_remove(q):
    with _sse_lock:
        if q in _sse_clients:
            _sse_clients.remove(q)

def _sse_push_all(action, **kwargs):
    payload = json.dumps({"action": action, **kwargs})
    with _sse_lock:
        clients = list(_sse_clients)
    for q in clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass

_last_token = ""

def _watch_token():
    global _last_token
    _last_token = _read_token()
    app.logger.info(f"[watcher] started, token={_last_token[:8]}...")
    while True:
        time.sleep(2)
        try:
            current = _read_token()
            if current and current != _last_token:
                app.logger.info(f"[watcher] token changed -> pushing revoke to all clients")
                _last_token = current
                _sse_push_all("revoke")
        except Exception as e:
            app.logger.error(f"[watcher] error: {e}")

def _read_token():
    try:
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    except:
        return ""

def _get_package():
    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                if line.startswith("PACKAGE="):
                    return line.strip().split("=", 1)[1]
    except:
        return ""

def _check_auth(token, pkg):
    """
    REVERT về logic gốc: 1 token duy nhất do admin đặt qua 'mtunnel-token'
    (chính là cachedPass — tính từ chữ ký APK thật, admin tự nhập 1 lần từ
    bản build gốc). Token này KHÔNG tự cấp/thay đổi được từ phía app —
    chỉ admin đổi được qua menu quản lý, nên nếu app bị inject/resign lại
    (chữ ký đổi → cachedPass tính ra khác) sẽ KHÔNG khớp token admin đã
    đặt, dù attacker có vô hiệu hóa mọi check nội bộ trong app (vd bằng
    MT Manager "Kill Signature Verification") — quyết định nằm ở SERVER,
    không phải ở app, nên không patch app để bypass được.
    """
    valid_token = _read_token()
    valid_package = _get_package()
    if not valid_token:
        return False, "server_not_configured"
    if pkg != valid_package:
        return False, "wrong_package"
    if not hmac.compare_digest(token, valid_token):
        return False, "invalid_token"
    return True, None

def _get_github_settings():
    settings = {}
    try:
        with open(GITHUB_REPO_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    settings[k.strip().upper()] = v.strip()
    except:
        pass
    return settings

def _get_github_token():
    try:
        with open(GITHUB_TOKEN_FILE, "r") as f:
            return f.read().strip()
    except:
        return ""

def _fetch_config_from_github():
    settings = _get_github_settings()
    owner  = settings.get("OWNER", "")
    repo   = settings.get("REPO", "")
    branch = settings.get("BRANCH", "main")
    path   = settings.get("PATH", "")
    pat    = _get_github_token()

    if not (owner and repo and path and pat):
        app.logger.error("[config] GitHub config chua day du (.github_repo / .github_token)")
        return None

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github.raw+json",
        "User-Agent": "mtunnel-license-server"
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
            # KHÔNG validate bằng json.loads() ở đây — server không quan tâm
            # định dạng nội dung (JSON thô hay bất kỳ dạng nào Gen tool đẩy
            # lên), chỉ coi đây là bytes bất kỳ để ký Ed25519 rồi forward
            # nguyên vẹn cho client tự xử lý.
            if len(data) == 0:
                app.logger.error("[config] GitHub tra ve file rong")
                return None
            return data
    except urllib.error.HTTPError as e:
        app.logger.error(f"[config] GitHub fetch HTTP {e.code}: {e.reason}")
        return None
    except Exception as e:
        app.logger.error(f"[config] GitHub fetch loi: {e}")
        return None

def _get_config_bytes():
    now = time.time()
    if _github_cache["bytes"] is not None and (now - _github_cache["fetched_at"]) < GITHUB_FETCH_TTL:
        return _github_cache["bytes"]

    fresh = _fetch_config_from_github()
    if fresh is not None:
        _github_cache["bytes"] = fresh
        _github_cache["fetched_at"] = now
        try:
            tmp = CONFIG_DATA_FILE + ".tmp"
            with open(tmp, "wb") as f:
                f.write(fresh)
            os.replace(tmp, CONFIG_DATA_FILE)
        except Exception as e:
            app.logger.error(f"[config] Khong ghi duoc cache local: {e}")
        return fresh

    app.logger.warning("[config] GitHub fetch that bai, dung ban cache local cu")
    try:
        with open(CONFIG_DATA_FILE, "rb") as f:
            cached = f.read()
        if len(cached) == 0:
            # File cache local rong (vd server moi cai, chua tung fetch
            # GitHub thanh cong lan nao) — KHONG duoc coi day la config
            # hop le, neu khong se ky va tra ve "thanh cong" voi noi dung
            # rong, khien client nhan duoc response hop le ve mat chu ky
            # nhung noi dung trong -> crash/loi khi parse JSON rong o phia
            # sau (Servers:[] khong ton tai).
            app.logger.error("[config] File cache local cung rong — khong co config nao kha dung")
            return None
        return cached
    except:
        return None

def _get_or_create_signing_key():
    if os.path.exists(SIGNING_KEY_FILE):
        with open(SIGNING_KEY_FILE, "rb") as f:
            raw = f.read()
        return Ed25519PrivateKey.from_private_bytes(raw)

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    old_umask = os.umask(0o077)
    try:
        with open(SIGNING_KEY_FILE, "wb") as f:
            f.write(raw)
    finally:
        os.umask(old_umask)

    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    app.logger.warning(
        "[config] Da tao signing key moi. PUBLIC KEY (base64) can nhung vao app Android:\n"
        + base64.b64encode(pub_raw).decode()
    )
    return key

SIGNING_KEY = _get_or_create_signing_key()

# Khởi động watcher thread SAU KHI mọi hàm nó cần (_read_token, _sse_push_all)
# đã được định nghĩa xong — đặt ở đây (cuối module, trước khi route chạy)
# để tránh NameError do thread chạy trước khi Python nạp xong các def phía dưới.
_watcher = threading.Thread(target=_watch_token, daemon=True, name="token-watcher")
_watcher.start()

@app.route("/api/verify", methods=["POST"])
@limiter.limit("30 per minute")   # user thật chỉ gọi lúc mở app, không bao giờ gần ngưỡng này
def verify():
    data  = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg   = data.get("pkg",   "")
    ip    = request.remote_addr

    app.logger.info(f"[verify] {ip} | pkg={pkg} | token={token[:8]}...")

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[verify] FAILED from {ip}: {reason}")
        return jsonify({"valid": False, "reason": reason})

    expire_at = int(time.time()) + CACHE_TTL
    app.logger.info(f"[verify] PASS | expire_at={expire_at}")
    return jsonify({"valid": True, "expire_at": expire_at})


def _load_allowed_signing_hashes():
    """
    File .attestation_signing_hashes.json:
      {"allowed": ["<sha256 hex chu ky APK that>", ...]}
    Tinh bang compute_signing_hash.py tren APK build goc (SHA-256 cua DER
    bytes cua signing certificate — cung thuat toan Android dung de dien
    signatureDigests trong AttestationApplicationId).
    """
    try:
        with open(ATTESTATION_SIGNING_HASHES_FILE, "r") as f:
            return set(h.lower() for h in json.load(f).get("allowed", []))
    except:
        return set()


def _load_allowed_dex_hashes():
    """
    File .dex_hashes.json: {"allowed": ["<combined sha256 hex>", ...]}
    Tinh bang compute_dex_hash.py (xem file do) tren APK release da ky.
    """
    try:
        with open(DEX_HASHES_FILE, "r") as f:
            return set(h.lower() for h in json.load(f).get("allowed", []))
    except:
        return set()


def _get_google_attestation_roots():
    """
    Tải danh sách root cert Key Attestation chính thức từ Google, cache lại
    ATTESTATION_ROOT_CACHE_TTL giây. KHÔNG hardcode cứng bytes cert trong
    code — Google ĐÃ từng đổi root (rotate tháng 4/2026), hardcode sẽ lỗi
    thời và làm mọi verify sau đó fail cứng mà không rõ lý do.
    """
    now = time.time()
    with _attestation_roots_lock:
        if _attestation_roots_cache["certs"] and \
           (now - _attestation_roots_cache["fetched_at"] < ATTESTATION_ROOT_CACHE_TTL):
            return _attestation_roots_cache["certs"]

    try:
        req = urllib.request.Request(
            GOOGLE_ATTESTATION_ROOT_URL,
            headers={"User-Agent": "mtunnel-license-server/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            pem_list = json.loads(resp.read().decode())
        certs = [x509.load_pem_x509_certificate(pem.encode()) for pem in pem_list]
        with _attestation_roots_lock:
            _attestation_roots_cache["certs"] = certs
            _attestation_roots_cache["fetched_at"] = now
        app.logger.info(f"[attestation] Da tai {len(certs)} root cert tu Google")
        return certs
    except Exception as e:
        app.logger.error(f"[attestation] Loi tai root cert tu Google: {e}")
        # Dùng cache cũ (dù hết hạn) thay vì fail cứng toàn bộ tính năng chỉ
        # vì 1 lần Google tạm không phản hồi được.
        with _attestation_roots_lock:
            return list(_attestation_roots_cache["certs"])


def _get_revoked_attestation_serials():
    """
    Tai danh sach serial number (dang hex, lowercase, khong '0x') cua cac
    key attestation DA BI THU HOI, tu GOOGLE_ATTESTATION_STATUS_URL. Cache
    lai ATTESTATION_STATUS_CACHE_TTL giay. Format JSON tra ve:
      {"entries": {"<serial_hex>": {"status": "REVOKED"|"SUSPENDED", "reason": "..."}}}
    Chi nhung serial CO van de moi xuat hien trong danh sach nay (khong phai
    liet ke toan bo key da cap).
    """
    now = time.time()
    with _attestation_status_lock:
        if _attestation_status_cache["entries"] and \
           (now - _attestation_status_cache["fetched_at"] < ATTESTATION_STATUS_CACHE_TTL):
            return _attestation_status_cache["entries"]

    try:
        req = urllib.request.Request(
            GOOGLE_ATTESTATION_STATUS_URL,
            headers={"User-Agent": "mtunnel-license-server/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            doc = json.loads(resp.read().decode())
        entries = doc.get("entries", {})
        # Chuan hoa key ve lowercase (Google tra ve da lowercase, nhung phong
        # truong hop thay doi trong tuong lai) de so sanh khong bi lech.
        entries = {k.lower(): v for k, v in entries.items()}
        with _attestation_status_lock:
            _attestation_status_cache["entries"] = entries
            _attestation_status_cache["fetched_at"] = now
        app.logger.info(f"[attestation] Da tai {len(entries)} serial bi thu hoi tu Google")
        return entries
    except Exception as e:
        app.logger.error(f"[attestation] Loi tai danh sach thu hoi tu Google: {e}")
        # Dung cache cu (du het han) thay vi fail cung/bo qua check chi vi
        # 1 lan Google tam khong phan hoi duoc.
        with _attestation_status_lock:
            return dict(_attestation_status_cache["entries"])


# ══════════════════════════════════════════════════════════════
# MINI DER PARSER — chỉ đủ dùng để đọc cấu trúc KeyDescription
# (extension Key Attestation, OID 1.3.6.1.4.1.11129.2.1.17), KHÔNG phải
# 1 parser ASN.1 tổng quát. Xem cấu trúc đầy đủ tại:
# https://source.android.com/docs/security/features/keystore/attestation
# ══════════════════════════════════════════════════════════════

KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
ROOT_OF_TRUST_TAG   = 704   # context tag [704] EXPLICIT trong AuthorizationList
ATTESTATION_APPLICATION_ID_TAG = 709   # context tag [709] EXPLICIT OCTET STRING
                                        # chua DER-encoded AttestationApplicationId:
                                        #   SEQUENCE {
                                        #     packageInfoRecords SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
                                        #     signatureDigests   SET OF OCTET STRING (SHA-256 cua tung cert ky)
                                        #   }
                                        # Do KEYSTORE/system_server dien vao luc tao key — KHONG di qua
                                        # tien trinh app, nen khong bi xhook/"Kill Signature Verification"
                                        # (vd MT Manager) danh lua duoc, khac voi getPass123()/token client tu bao cao.


class AttestationParseError(Exception):
    pass


def _der_read_tlv(data: bytes, offset: int):
    """Đọc 1 TLV tại offset. Trả về (tag_number, tag_class, is_constructed, content, next_offset)."""
    tag_byte = data[offset]
    tag_class = (tag_byte & 0xC0) >> 6     # 0=universal 1=application 2=context-specific 3=private
    is_constructed = bool(tag_byte & 0x20)
    tag_number = tag_byte & 0x1F
    offset += 1
    if tag_number == 0x1F:                  # long-form tag number (cần cho tag > 30, vd [704])
        tag_number = 0
        while True:
            b = data[offset]
            tag_number = (tag_number << 7) | (b & 0x7F)
            offset += 1
            if not (b & 0x80):
                break
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset:offset + num_len_bytes], "big")
        offset += num_len_bytes
    else:
        length = length_byte
    content = data[offset:offset + length]
    return tag_number, tag_class, is_constructed, content, offset + length


def _der_read_sequence_items(content: bytes):
    """Parse nội dung 1 SEQUENCE thành list (tag, tag_class, constructed, item_content)."""
    items = []
    offset = 0
    while offset < len(content):
        tag, tag_class, constructed, item_content, next_offset = _der_read_tlv(content, offset)
        items.append((tag, tag_class, constructed, item_content))
        offset = next_offset
    return items


def _parse_key_attestation_extension(leaf_cert):
    """
    Parse extension KeyDescription trong leaf cert, trả về dict:
      attestation_challenge (bytes), device_locked (bool),
      verified_boot_state (int: 0=Verified,1=SelfSigned,2=Unverified,3=Failed)
    """
    try:
        ext = leaf_cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(KEY_DESCRIPTION_OID))
    except x509.ExtensionNotFound:
        raise AttestationParseError("khong_co_extension_key_attestation")

    raw = ext.value.value   # UnrecognizedExtension.value = DER bytes thô của KeyDescription (bao gồm cả tag+length của SEQUENCE ngoài cùng)

    # Bóc lớp TLV ngoài cùng (SEQUENCE) trước — "raw" là toàn bộ
    # "30 82 xx xx <nội dung>", KHÔNG phải chỉ riêng phần nội dung.
    _, _, _, key_description_content, _ = _der_read_tlv(raw, 0)
    top_items = _der_read_sequence_items(key_description_content)
    # KeyDescription ::= SEQUENCE { attestationVersion, attestationSecurityLevel,
    #   keymasterVersion, keymasterSecurityLevel, attestationChallenge,
    #   uniqueId, softwareEnforced, teeEnforced }
    if len(top_items) < 8:
        # DEBUG: log chi tiết cấu trúc thực tế đọc được để xác định schema
        # KeyDescription của máy này khác bản hardcode 8-field ở chỗ nào —
        # gỡ bỏ sau khi đã xác định xong nguyên nhân.
        try:
            attestation_version = None
            if len(top_items) >= 1:
                v_content = top_items[0][3]
                attestation_version = int.from_bytes(v_content, "big") if v_content else None
            app.logger.warning(
                f"[attestation-verify] DEBUG key_description_thieu_truong | "
                f"so_field_doc_duoc={len(top_items)} | "
                f"attestation_version={attestation_version} | "
                f"raw_len={len(raw)} | "
                f"raw_hex_preview={raw[:64].hex()} | "
                f"tags={[t[0] for t in top_items]}")
        except Exception as e:
            app.logger.warning(f"[attestation-verify] DEBUG log that bai: {e}")
        raise AttestationParseError("key_description_thieu_truong")

    attestation_challenge = top_items[4][3]
    software_enforced_content = top_items[6][3]
    tee_enforced_content = top_items[7][3]
    tee_items = _der_read_sequence_items(tee_enforced_content)

    package_names, signature_digests_hex = _parse_attestation_application_id(
        software_enforced_content, tee_enforced_content
    )

    root_of_trust_content = None
    for tag, tag_class, constructed, content in tee_items:
        if tag_class == 2 and tag == ROOT_OF_TRUST_TAG:   # context-specific [704]
            # [704] EXPLICIT bọc 1 TLV bên trong = chính RootOfTrust SEQUENCE
            _, _, _, inner_content, _ = _der_read_tlv(content, 0)
            root_of_trust_content = inner_content
            break

    if root_of_trust_content is None:
        raise AttestationParseError("khong_tim_thay_root_of_trust_trong_tee_enforced")

    rot_items = _der_read_sequence_items(root_of_trust_content)
    # RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
    #                            verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING (optional) }
    if len(rot_items) < 3:
        raise AttestationParseError("root_of_trust_thieu_truong")

    device_locked_bytes = rot_items[1][3]
    verified_boot_state_bytes = rot_items[2][3]

    return {
        "attestation_challenge": attestation_challenge,
        "device_locked": device_locked_bytes != b"\x00",
        "verified_boot_state": int.from_bytes(verified_boot_state_bytes, "big"),
        "package_names": package_names,
        "signature_digests_hex": signature_digests_hex,
    }


def _find_context_tag(items, tag_number):
    """Tim item co context-specific tag == tag_number trong list (tag, class, constructed, content)."""
    for tag, tag_class, constructed, content in items:
        if tag_class == 2 and tag == tag_number:
            return content
    return None


def _parse_attestation_application_id(software_enforced_content: bytes, tee_enforced_content: bytes):
    """
    Doc AttestationApplicationId (tag 709) tu AuthorizationList. Tag nay
    THUONG nam trong softwareEnforced (Keystore dien o tang software khi
    tao key), nhung 1 so thiet bi/OEM dat trong teeEnforced — nen kiem tra
    ca hai, khong hardcode 1 cho.

    Tra ve (package_names: list[str], signature_digests_hex: list[str]).
    Raise AttestationParseError neu khong tim thay o ca hai noi.
    """
    software_items = _der_read_sequence_items(software_enforced_content)
    tee_items = _der_read_sequence_items(tee_enforced_content)

    raw_709 = _find_context_tag(software_items, ATTESTATION_APPLICATION_ID_TAG)
    if raw_709 is None:
        raw_709 = _find_context_tag(tee_items, ATTESTATION_APPLICATION_ID_TAG)
    if raw_709 is None:
        raise AttestationParseError("khong_tim_thay_attestation_application_id")

    # [709] EXPLICIT OCTET STRING -> boc 1 lop de lay noi dung OCTET STRING,
    # noi dung do chinh la DER bytes cua SEQUENCE AttestationApplicationId.
    _, _, _, octet_content, _ = _der_read_tlv(raw_709, 0)
    _, _, _, aaid_seq_content, _ = _der_read_tlv(octet_content, 0)
    aaid_items = _der_read_sequence_items(aaid_seq_content)
    if len(aaid_items) < 2:
        raise AttestationParseError("attestation_application_id_thieu_truong")

    package_info_set_content = aaid_items[0][3]
    signature_digest_set_content = aaid_items[1][3]

    package_names = []
    for _, _, _, pkg_info_content in _der_read_sequence_items(package_info_set_content):
        pkg_info_items = _der_read_sequence_items(pkg_info_content)
        if pkg_info_items:
            package_names.append(pkg_info_items[0][3].decode("utf-8", errors="replace"))

    signature_digests_hex = [
        content.hex() for _, _, _, content in _der_read_sequence_items(signature_digest_set_content)
    ]

    return package_names, signature_digests_hex


def _verify_cert_signed_by(child_cert, parent_pubkey):
    """Raise InvalidSignature nếu child_cert KHÔNG được ký bởi parent_pubkey."""
    if isinstance(parent_pubkey, rsa.RSAPublicKey):
        parent_pubkey.verify(
            child_cert.signature, child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), child_cert.signature_hash_algorithm)
    elif isinstance(parent_pubkey, ec.EllipticCurvePublicKey):
        parent_pubkey.verify(
            child_cert.signature, child_cert.tbs_certificate_bytes,
            ec.ECDSA(child_cert.signature_hash_algorithm))
    else:
        raise ValueError("loai_khoa_khong_ho_tro")


def _verify_attestation_chain(cert_chain_der_list):
    """
    cert_chain_der_list: list bytes DER, thứ tự leaf -> ... -> root (đúng thứ
    tự KeyStore.getCertificateChain() trả về trên Android).
    Trả về (True, None, leaf_cert) nếu hợp lệ, ngược lại (False, reason, None).
    """
    if len(cert_chain_der_list) < 2:
        return False, "chain_qua_ngan", None

    try:
        certs = [x509.load_der_x509_certificate(der) for der in cert_chain_der_list]
    except Exception as e:
        return False, f"loi_parse_cert:{e}", None

    for i in range(len(certs) - 1):
        try:
            _verify_cert_signed_by(certs[i], certs[i + 1].public_key())
        except InvalidSignature:
            return False, f"chu_ky_sai_vi_tri_{i}", None
        except Exception as e:
            return False, f"loi_verify_vi_tri_{i}:{e}", None

    google_roots = _get_google_attestation_roots()
    if not google_roots:
        return False, "khong_tai_duoc_root_google", None

    # So theo PUBLIC KEY (SubjectPublicKeyInfo), KHÔNG so toàn bộ DER của cert.
    # Google thỉnh thoảng "re-sign" lại cùng 1 root (cùng key, khác serial/hạn
    # dùng) — Android tự khuyến nghị tin cậy theo subject/key bất kể validity
    # period. So nguyên cert sẽ fail sai với các bản re-signed hợp lệ.
    def _pubkey_der(cert):
        return cert.public_key().public_bytes(Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    root_pubkey_der = _pubkey_der(certs[-1])
    is_trusted = any(root_pubkey_der == _pubkey_der(g) for g in google_roots)
    if not is_trusted:
        # DEBUG: log chi tiết root máy gửi lên vs danh sách root server đang
        # cache, để xác định đây là do Google đang xoay vòng root (RKP) hay
        # do lỗi khác — gỡ bỏ khối log này sau khi đã xác định xong nguyên nhân.
        try:
            def _not_after_iso(cert):
                # cryptography >= 42.0 co not_valid_after_utc (aware datetime);
                # ban cu hon chi co not_valid_after (naive datetime) — fallback
                # de khong crash tren VPS dang dung version cu.
                dt = getattr(cert, "not_valid_after_utc", None)
                if dt is None:
                    dt = cert.not_valid_after
                return dt.isoformat()

            device_root_fp = hashlib.sha256(certs[-1].public_bytes(Encoding.DER)).hexdigest()
            device_root_subject = certs[-1].subject.rfc4514_string()
            device_root_serial = certs[-1].serial_number
            device_root_not_after = _not_after_iso(certs[-1])
            app.logger.warning(
                f"[attestation-verify] DEBUG root_khong_khop_google | "
                f"device_root_subject='{device_root_subject}' | "
                f"device_root_serial={device_root_serial} | "
                f"device_root_not_after={device_root_not_after} | "
                f"device_root_sha256={device_root_fp} | "
                f"chain_len={len(certs)}")
            for idx, g in enumerate(google_roots):
                g_fp = hashlib.sha256(g.public_bytes(Encoding.DER)).hexdigest()
                app.logger.warning(
                    f"[attestation-verify] DEBUG server_cached_root[{idx}] | "
                    f"subject='{g.subject.rfc4514_string()}' | "
                    f"serial={g.serial_number} | "
                    f"not_after={_not_after_iso(g)} | "
                    f"sha256={g_fp}")
        except Exception as e:
            app.logger.warning(f"[attestation-verify] DEBUG log that bai: {e}")
        return False, "root_khong_khop_google", None

    # ── Kiểm tra thu hồi (BẮT BUỘC) ──────────────────────────────────────
    # Chain ký hợp lệ + root khớp Google KHÔNG đủ để tin cậy: nếu 1 hardware
    # keybox thật đã bị rò rỉ (vd bị bán/leak, dùng qua module kiểu
    # "TrickyStore" trên máy root), kẻ tấn công vẫn tự dựng được 1 chain
    # ký đúng 100% về mặt mật mã, root vẫn khớp Google — vì họ có private
    # key thật của keybox đó. verified_boot_state/device_locked trong chain
    # đó cũng do CHÍNH kẻ tấn công tự điền lúc dựng chain giả, nên không thể
    # dùng 2 trường đó để phát hiện. Cách DUY NHẤT là đối chiếu serial number
    # từng cert trong chain với danh sách thu hồi chính thức của Google.
    revoked_serials = _get_revoked_attestation_serials()
    if revoked_serials:
        for idx, cert in enumerate(certs):
            serial_hex = format(cert.serial_number, "x")   # hex lowercase, khong '0x', khong leading zero
            entry = revoked_serials.get(serial_hex)
            if entry is not None:
                status = entry.get("status", "UNKNOWN")
                reason = entry.get("reason", "khong_ro")
                app.logger.warning(
                    f"[attestation-verify] REJECT: cert_bi_thu_hoi vi_tri={idx} "
                    f"serial={serial_hex} status={status} reason={reason}")
                return False, f"cert_thu_hoi:{status}:{reason}", None
    else:
        # Không tải được danh sách thu hồi (Google lỗi + chưa có cache) —
        # KHÔNG âm thầm coi như "sạch". Từ chối rõ ràng để không bao giờ
        # vô tình bỏ qua bước kiểm tra quan trọng nhất chống leaked-keybox.
        app.logger.error("[attestation-verify] REJECT: khong_tai_duoc_danh_sach_thu_hoi")
        return False, "khong_tai_duoc_danh_sach_thu_hoi", None

    return True, None, certs[0]


@app.route("/api/attestation-challenge", methods=["POST"])
@limiter.limit("30 per minute")
def attestation_challenge():
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg = data.get("pkg", "")
    ip = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[attestation-challenge] DENIED {ip}: {reason}")
        return jsonify({"error": reason}), 403

    now = time.time()
    with _attestation_nonce_lock:
        expired = [n for n, exp in _attestation_nonces.items() if exp < now]
        for n in expired:
            del _attestation_nonces[n]

    nonce_bytes = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce_bytes).decode()
    with _attestation_nonce_lock:
        _attestation_nonces[nonce_b64] = now + ATTESTATION_NONCE_TTL

    return jsonify({"challenge": nonce_b64, "expires_in": ATTESTATION_NONCE_TTL})


@app.route("/api/attestation-verify", methods=["POST"])
@limiter.limit("30 per minute")
def attestation_verify():
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg = data.get("pkg", "")
    challenge_b64 = data.get("challenge", "")
    cert_chain_b64 = data.get("cert_chain", [])
    # FIX (replay ticket giữa nhiều máy): device_id gửi kèm ở đây được nhúng
    # thẳng vào result_payload bên dưới rồi ký cùng — không phải field client
    # tự khai được dùng sau này để "match", mà là 1 phần payload ĐÃ KÝ. Muốn
    # đổi device_id trong vé, phải giả mạo chữ ký Ed25519 của SIGNING_KEY —
    # không làm được nếu không có private key server.
    device_id = data.get("device_id", "")
    ip = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[attestation-verify] AUTH FAILED {ip}: {reason}")
        return jsonify({"valid": False, "reason": reason})

    with _attestation_nonce_lock:
        expire_at = _attestation_nonces.pop(challenge_b64, None)
    if expire_at is None or expire_at < time.time():
        app.logger.warning(f"[attestation-verify] REJECT {ip}: bad_or_expired_challenge")
        return jsonify({"valid": False, "reason": "bad_or_expired_challenge"})

    if not isinstance(cert_chain_b64, list) or len(cert_chain_b64) < 2:
        return jsonify({"valid": False, "reason": "cert_chain_thieu_hoac_sai_dang"})

    try:
        cert_chain_der = [base64.b64decode(c) for c in cert_chain_b64]
    except Exception:
        return jsonify({"valid": False, "reason": "cert_chain_base64_sai"})

    chain_ok, chain_reason, leaf_cert = _verify_attestation_chain(cert_chain_der)
    if not chain_ok:
        app.logger.warning(f"[attestation-verify] REJECT {ip}: {chain_reason}")
        return jsonify({"valid": False, "reason": chain_reason})

    try:
        parsed = _parse_key_attestation_extension(leaf_cert)
    except AttestationParseError as e:
        app.logger.warning(f"[attestation-verify] REJECT {ip}: parse_error={e}")
        return jsonify({"valid": False, "reason": f"parse_error:{e}"})

    expected_challenge = base64.b64decode(challenge_b64)
    if not hmac.compare_digest(parsed["attestation_challenge"], expected_challenge):
        app.logger.warning(f"[attestation-verify] REJECT {ip}: challenge_mismatch")
        return jsonify({"valid": False, "reason": "challenge_mismatch"})

    # verifiedBootState 0 = Verified (bootloader khoá, ROM gốc nhà sản xuất).
    # deviceLocked = true nghĩa là bootloader đang ở trạng thái khoá tại
    # thời điểm tạo khoá này.
    #
    # QUAN TRỌNG: 2 điều kiện trên chỉ chứng minh "máy sạch" (TEE thật,
    # chưa root, bootloader khoá) — KHÔNG chứng minh app nào đã yêu cầu key.
    # Một APK bị inject/ký lại (vd qua MT Manager "Kill Signature
    # Verification" + libSignatureKiller.so hook PackageManager trong tiến
    # trình app) vẫn tạo ra chain attestation hợp lệ 100% về mặt phần cứng
    # trên 1 máy zin không root, vì `pkg`/`token` gửi kèm request body là
    # dữ liệu client tự khai — không liên quan gì tới nội dung chain đã ký.
    #
    # Muốn chặn đúng trường hợp đó, PHẢI đối chiếu package name + hash chữ
    # ký lấy TỪ TRONG chain (AttestationApplicationId, tag 709) — trường
    # này do Keystore/system_server điền lúc tạo key, không đi qua tiến
    # trình app nên hook kiểu xhook không với tới được.
    valid_package = _get_package()
    allowed_sig_hashes = _load_allowed_signing_hashes()

    package_ok = bool(valid_package) and (valid_package in parsed["package_names"])
    sig_ok = bool(allowed_sig_hashes) and any(
        h in allowed_sig_hashes for h in parsed["signature_digests_hex"]
    )
    identity_ok = package_ok and sig_ok

    if not package_ok:
        app.logger.warning(
            f"[attestation-verify] REJECT {ip}: package_mismatch | "
            f"expected={valid_package} | got={parsed['package_names']}"
        )
    if not sig_ok:
        app.logger.warning(
            f"[attestation-verify] REJECT {ip}: signing_hash_mismatch | "
            f"got={parsed['signature_digests_hex']}"
        )

    is_valid = (
        (parsed["verified_boot_state"] == 0)
        and parsed["device_locked"]
        and identity_ok
    )

    result_payload = {
        "valid": is_valid,
        "pkg": pkg,
        "device_id": device_id,
        "verified_boot_state": parsed["verified_boot_state"],
        "device_locked": parsed["device_locked"],
        "package_ok": package_ok,
        "sig_ok": sig_ok,
        "challenge": challenge_b64,
        "ts": int(time.time()),
    }
    message = json.dumps(result_payload, sort_keys=True, separators=(",", ":")).encode()
    signature = SIGNING_KEY.sign(message)

    if is_valid:
        app.logger.info(f"[attestation-verify] OK {ip} | pkg={pkg} | device_id={device_id or '(rong)'}")
    else:
        app.logger.warning(
            f"[attestation-verify] NOT_VERIFIED {ip} | pkg={pkg} | "
            f"boot_state={parsed['verified_boot_state']} | locked={parsed['device_locked']}")

    return jsonify({
        "result": base64.b64encode(message).decode(),
        "signature": base64.b64encode(signature).decode(),
    })


@app.route("/api/dex-challenge", methods=["POST"])
@limiter.limit("30 per minute")
def dex_challenge():
    """
    Buoc 1/2 cua DEX integrity check (xem DexIntegrity.cpp ben client).
    Request:  {"token": "...", "pkg": "..."}
    Response: {"nonce": "<base64>", "expires_in": <giay>}
    """
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg = data.get("pkg", "")
    ip = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[dex-challenge] DENIED {ip}: {reason}")
        return jsonify({"error": reason}), 403

    now = time.time()
    with _dex_nonce_lock:
        expired = [n for n, exp in _dex_nonces.items() if exp < now]
        for n in expired:
            del _dex_nonces[n]

        nonce_bytes = os.urandom(32)
        nonce_b64 = base64.b64encode(nonce_bytes).decode()
        _dex_nonces[nonce_b64] = now + DEX_NONCE_TTL

    return jsonify({"nonce": nonce_b64, "expires_in": DEX_NONCE_TTL})


@app.route("/api/dex-verify", methods=["POST"])
@limiter.limit("30 per minute")
def dex_verify():
    """
    Buoc 2/2 cua DEX integrity check. Client gui lai dung "nonce" nhan tu
    /api/dex-challenge kem dex_hash da tinh tren APK dang chay.
    Request:  {"token": "...", "pkg": "...", "nonce": "...", "dex_hash": "<hex>"}
    Response: {"result": "<base64 JSON da ky>", "signature": "<base64 Ed25519>"}

    Payload da ky ben trong "result" gom {"valid", "nonce", "pkg", "dex_hash",
    "ts"} — client (DexIntegrity::verify) BAT BUOC verify chu ky Ed25519
    TRUOC KHI doc bat ky field nao, roi doi chieu lai dung "nonce" no vua
    gui de chong replay response cu — nen 2 buoc do PHAI khop dinh dang nay.
    """
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg = data.get("pkg", "")
    nonce = data.get("nonce", "")
    dex_hash = data.get("dex_hash", "").strip().lower()
    ip = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[dex-verify] AUTH FAILED {ip}: {reason}")
        return jsonify({"error": reason}), 403

    with _dex_nonce_lock:
        expire_at = _dex_nonces.pop(nonce, None)
    if expire_at is None or expire_at < time.time():
        app.logger.warning(f"[dex-verify] REJECT {ip}: bad_or_expired_nonce")
        return jsonify({"error": "bad_or_expired_nonce"}), 400

    allowed_hashes = _load_allowed_dex_hashes()
    is_valid = bool(dex_hash) and bool(allowed_hashes) and dex_hash in allowed_hashes

    if is_valid:
        app.logger.info(f"[dex-verify] OK {ip} | pkg={pkg} | dex_hash={dex_hash[:12]}...")
    else:
        app.logger.warning(
            f"[dex-verify] MISMATCH {ip} | pkg={pkg} | dex_hash={dex_hash[:12]}... "
            f"| allowed_count={len(allowed_hashes)}")

    result_payload = {
        "valid": is_valid,
        "nonce": nonce,
        "pkg": pkg,
        "dex_hash": dex_hash,
        "ts": int(time.time()),
    }
    message = json.dumps(result_payload, sort_keys=True, separators=(",", ":")).encode()
    signature = SIGNING_KEY.sign(message)

    return jsonify({
        "result": base64.b64encode(message).decode(),
        "signature": base64.b64encode(signature).decode(),
    })


ATTESTATION_TICKET_MAX_AGE = 259200   # 3 ngay — vé attestation cũ hơn mức này bị coi là hết hạn.
# Truoc la 300s (5 phut), buoc client phai tao key attestation moi (generateKeyPair)
# gan nhu moi lan mo app. Tren Android 16 (bat buoc dung RKP, khong con factory
# key), buoc tao key nay co the mat toi ~30s neu kho cert RKP da cap san bi can
# va thiet bi phai xin cert moi qua mang tu server Google. Trang thai root/
# bootloader cua may khong doi nhanh, nen nang TTL len de client cache va tai
# su dung 1 ticket lau dai, chi phai tra gia cham 1 lan hiem hoi thay vi moi
# lan mo app. Client (Android) can luu attestation_ticket_result/signature
# kem timestamp, chi goi lai /api/attestation-challenge + /api/attestation-verify
# khi ticket gan het han.
DEVICE_WHITELIST_FILE = os.path.join(INSTALL_DIR, ".attestation_whitelist.json")


def _is_device_whitelisted(device_id: str) -> bool:
    """
    Whitelist theo Android ID — dùng cho máy dev/tester CỤ THỂ cần bỏ qua
    yêu cầu Key Attestation (vd máy root để debug), KHÔNG áp dụng đại trà.
    Quản lý qua menu 'mtunnel-token' -> Attestation Whitelist.
    """
    if not device_id:
        return False
    try:
        with open(DEVICE_WHITELIST_FILE, "r") as f:
            allowed = json.load(f).get("allowed_device_ids", [])
        return device_id in allowed
    except Exception:
        return False


def _is_device_blacklisted(device_id: str) -> bool:
    """
    Kiem tra device_id co dang bi blacklist do server DA tung phat hien
    bang chung root/mo khoa bootloader that su (khong phai chi package/
    signing-hash khong khop) hay khong. Danh sach nay duoc _record_blocked_
    device() tu dong danh dau "blacklisted": True khi phat hien root, va
    duoc doc lai o day de tu choi MOI request tiep theo cua chinh device_id
    do — cho toi khi admin xoa khoi blacklist hoac them vao whitelist qua
    menu 'mtunnel-token'.
    """
    if not device_id:
        return False
    try:
        with open(DEVICE_BLOCKED_FILE, "r") as f:
            blocked = json.load(f).get("blocked", {})
        entry = blocked.get(device_id)
        return bool(entry) and entry.get("blacklisted", False)
    except Exception:
        return False


def _record_blocked_device(device_id: str, ip: str, pkg: str, verified_boot_state, device_locked,
                            package_ok=None, sig_ok=None):
    """
    Ghi lai (hoac cap nhat) 1 thiet bi bi server tu choi cap config vi
    attestation ticket hop le nhung payload["valid"]==False — co the do
    root/mo khoa bootloader, HOAC do package/signing-hash khong khop (vd
    chua cau hinh menu 9 - Signing Hash Allow-list, hoac dung sai package).
    Danh sach nay dung de xem lai qua menu 'mtunnel-token' -> Attestation
    Whitelist, tien cho viec whitelist nhanh 1 may cu the neu can. Neu ly
    do bi chan la bang chung root/mo khoa bootloader that su (khong phai
    chi package/signing-hash khong khop), device_id se TU DONG duoc danh
    dau "blacklisted": True va bi tu choi thang moi request /api/config
    tiep theo (xem _is_device_blacklisted), cho toi khi admin go blacklist
    hoac them vao whitelist.
    """
    if not device_id:
        return
    reasons = []
    if device_locked is False:
        reasons.append("bootloader_mo_khoa")
    if verified_boot_state is not None and verified_boot_state != 0:
        reasons.append("verified_boot_khong_hop_le")
    if package_ok is False:
        reasons.append("package_khong_khop")
    if sig_ok is False:
        reasons.append("signing_hash_khong_khop_hoac_chua_cau_hinh_menu9")
    if not reasons:
        reasons.append("khong_xac_dinh")
    reason = ",".join(reasons)

    # Chi coi la "root that su" (va tu dong blacklist vinh vien) khi co bang
    # chung ro rang tu Key Attestation ve bootloader/verified-boot — KHONG
    # tu dong blacklist chi vi package/signing-hash khong khop, vi truong
    # hop do co the do admin chua cau hinh menu 9 (Signing Hash Allow-list)
    # hoac client goi sai package, khong phai loi cua thiet bi.
    is_root_evidence = (device_locked is False) or \
        (verified_boot_state is not None and verified_boot_state != 0)

    with _device_blocked_lock:
        try:
            with open(DEVICE_BLOCKED_FILE, "r") as f:
                doc = json.load(f)
        except Exception:
            doc = {"blocked": {}}
        blocked = doc.setdefault("blocked", {})
        entry = blocked.setdefault(device_id, {"first_seen": int(time.time()), "count": 0})
        entry["last_seen"] = int(time.time())
        entry["count"] = entry.get("count", 0) + 1
        entry["last_ip"] = ip
        entry["pkg"] = pkg
        entry["verified_boot_state"] = verified_boot_state
        entry["device_locked"] = device_locked
        entry["package_ok"] = package_ok
        entry["sig_ok"] = sig_ok
        entry["reason"] = reason
        if is_root_evidence and not entry.get("blacklisted"):
            entry["blacklisted"] = True
            entry["blacklisted_at"] = int(time.time())
            entry["blacklisted_reason"] = reason
            app.logger.warning(
                f"[attestation-block] BLACKLIST device_id={device_id} | reason={reason} | ip={ip}")
        try:
            tmp = DEVICE_BLOCKED_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(doc, f, indent=2)
            os.replace(tmp, DEVICE_BLOCKED_FILE)
        except Exception as e:
            app.logger.error(f"[attestation-block] Loi ghi {DEVICE_BLOCKED_FILE}: {e}")


def _load_resolve_servers():
    """
    Doc toan bo bang server_id -> {ip, port, note, enabled}. KHONG cache trong
    RAM (khac _github_cache) vi bang nay nho va admin co the sua qua menu bat
    ky luc nao — doc thang tu file de luon phan anh thay doi moi nhat.
    """
    try:
        with open(RESOLVE_SERVERS_FILE, "r") as f:
            return json.load(f).get("servers", {})
    except Exception:
        return {}


def _get_resolve_server(server_id: str):
    """
    Tra 1 entry theo server_id, chi tra ve neu ton tai VA dang enabled=true.
    Admin co the tam thoi "rut" 1 IP khoi luu hanh (bi lo/lam dung) bang cach
    set enabled=false qua menu, ma khong can xoa han entry.
    """
    if not server_id:
        return None
    servers = _load_resolve_servers()
    entry = servers.get(server_id)
    if not entry or not entry.get("enabled", True):
        return None
    return entry


def _log_resolve_lookup(server_id: str, device_id: str, ip: str):
    """
    Ghi lai (server_id, device_id, ip nguon) cua tung lan goi /api/resolve
    thanh cong, luu vao chinh RESOLVE_SERVERS_FILE (key rieng "log", gioi han
    50 dong gan nhat) de admin xem qua menu — phat hien som neu co token bi
    danh cap va bi goi /api/resolve tu nhieu IP/device_id la thuong.
    """
    try:
        with _resolve_servers_lock:
            try:
                with open(RESOLVE_SERVERS_FILE, "r") as f:
                    doc = json.load(f)
            except Exception:
                doc = {"servers": {}}
            log = doc.setdefault("log", [])
            log.append({
                "ts": int(time.time()),
                "server_id": server_id,
                "device_id": device_id or "(rong)",
                "client_ip": ip,
            })
            doc["log"] = log[-50:]
            tmp = RESOLVE_SERVERS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(doc, f, indent=2)
            os.replace(tmp, RESOLVE_SERVERS_FILE)
    except Exception as e:
        app.logger.error(f"[resolve] Khong ghi duoc log lookup: {e}")


def _verify_attestation_ticket(ticket_result_b64: str, ticket_signature_b64: str, expected_pkg: str,
                                expected_device_id: str = ""):
    """
    Verify 1 "vé" attestation (payload đã ký từ /api/attestation-verify).
    Trả về (True, None, payload) nếu vé hợp lệ VÀ thiết bị đã attest thành
    công (payload["valid"]==True), ngược lại (False, reason, payload).
    payload chỉ có giá trị (khác None) khi đã giải mã JSON thành công —
    dùng để ghi lại lý do bị chặn (root/bootloader mở khóa) khi cần.

    FIX (lỗ hổng replay ticket giữa nhiều máy): trước bản vá này, payload
    chỉ gắn với "pkg" + "ts" (TTL = ATTESTATION_TICKET_MAX_AGE = 3 NGÀY).
    Một vé mint hợp lệ từ 1 máy sạch (bootloader khoá, không root) là chữ
    ký hợp lệ vĩnh viễn trong 3 ngày CHO BẤT KỲ REQUEST NÀO có cùng pkg —
    copy được sang máy khác (kể cả máy đã root/mở khoá bootloader) và vẫn
    được /api/config, /api/resolve chấp nhận, vì không có gì trong payload
    xác định NÓ THUỘC VỀ MÁY NÀO. Đây chính xác là cách 1 nhóm chia sẻ 1
    vé để dùng chung trên nhiều máy đã bị mở khoá bootloader (ảnh chụp màn
    hình group send cho anh Cipo). Nay bắt buộc device_id nhúng trong vé
    (được ký, không giả mạo được) phải khớp device_id gửi kèm request hiện
    tại — vé mint trên máy A không còn dùng được trên máy B nữa.
    """
    if not ticket_result_b64 or not ticket_signature_b64:
        return False, "thieu_attestation_ticket", None

    try:
        message = base64.b64decode(ticket_result_b64)
        signature = base64.b64decode(ticket_signature_b64)
    except Exception:
        return False, "ticket_base64_sai", None

    try:
        SIGNING_KEY.public_key().verify(signature, message)
    except InvalidSignature:
        return False, "ticket_chu_ky_sai", None
    except Exception as e:
        return False, f"ticket_loi_verify:{e}", None

    try:
        payload = json.loads(message.decode())
    except Exception:
        return False, "ticket_payload_khong_phai_json", None

    if payload.get("pkg") != expected_pkg:
        return False, "ticket_sai_package", payload

    # KHÔNG được bỏ qua check khi 1 trong 2 bên rỗng — nếu làm vậy, 1 client
    # sửa app để gửi device_id="" lúc mint (và cũng gửi "" lúc dùng vé) sẽ
    # lách được toàn bộ phần vá này, dựng lại đúng lỗ hổng replay ban đầu.
    # So sánh CHẶT tuyệt đối: thiếu device_id ở BẤT KỲ đâu (payload cũ mint
    # trước khi vá, hoặc app client chưa build lại) đều bị coi là không
    # khớp và từ chối — chấp nhận việc vé cũ hết dùng được ngay sau khi
    # deploy bản vá này, thay vì để hở đường lách.
    ticket_device_id = payload.get("device_id", "")
    if ticket_device_id != expected_device_id:
        return False, "ticket_sai_device_id", payload

    ticket_age = time.time() - payload.get("ts", 0)
    if ticket_age > ATTESTATION_TICKET_MAX_AGE or ticket_age < -10:
        return False, "ticket_het_han", payload

    if not payload.get("valid", False):
        return False, "device_not_attested", payload

    return True, None, payload


@app.route("/api/config", methods=["POST"])
@limiter.limit("10 per minute")   # chặt hơn /api/verify vì đây là nơi lộ Servers array
def get_config():
    data  = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg   = data.get("pkg",   "")
    ticket_result = data.get("attestation_ticket_result", "")
    ticket_signature = data.get("attestation_ticket_signature", "")
    device_id = data.get("device_id", "")
    ip    = request.remote_addr

    app.logger.info(f"[config] {ip} | pkg={pkg} | token={token[:8]}... | device_id={device_id or '(rong)'}")

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[config] DENIED from {ip}: {reason}")
        return jsonify({"error": reason}), 403

    if _is_device_whitelisted(device_id):
        app.logger.info(f"[config] BYPASS attestation (whitelisted device_id={device_id}) {ip}")
    elif _is_device_blacklisted(device_id):
        # Thiet bi nay da tung bi phat hien bang chung root/mo khoa
        # bootloader that su qua Key Attestation truoc do — tu choi thang,
        # KHONG can verify lai ticket. Chi duoc go blacklist bang cach xoa
        # khoi file .attestation_blocked_devices.json hoac them vao
        # whitelist qua menu 'mtunnel-token'.
        app.logger.warning(f"[config] DENIED (blacklisted) device_id={device_id} {ip}")
        return jsonify({"error": "device_blacklisted_root_detected"}), 403
    else:
        # Config chỉ được trả nếu kèm 1 vé Key Attestation còn hạn, đúng pkg,
        # và server tự verify chữ ký (KHÔNG tin app tự khai báo gì cả) — đây
        # mới là điểm ép buộc thật, không phải 1 check nằm rời rạc trong app.
        ticket_ok, ticket_reason, ticket_payload = _verify_attestation_ticket(
            ticket_result, ticket_signature, pkg, device_id)
        if not ticket_ok:
            if ticket_reason == "device_not_attested" and ticket_payload is not None:
                # Ve ky hop le, server DA verify duoc Key Attestation that,
                # chi la boot_state/device_locked khong dat — day moi la
                # bang chung thuc su may bi root/mo khoa bootloader, khac
                # voi cac loi ve rach/het han/sai chu ky o tren (khong chung
                # minh duoc gi ve tinh trang may).
                _record_blocked_device(
                    device_id, ip, pkg,
                    ticket_payload.get("verified_boot_state"),
                    ticket_payload.get("device_locked"),
                    ticket_payload.get("package_ok"),
                    ticket_payload.get("sig_ok"),
                )
            app.logger.warning(f"[config] DENIED (attestation) from {ip}: {ticket_reason} | device_id={device_id or '(rong)'}")
            return jsonify({"error": ticket_reason}), 403

    config_bytes = _get_config_bytes()
    if config_bytes is None:
        app.logger.error("[config] Khong co config nao kha dung (GitHub loi + chua co cache local)")
        return jsonify({"error": "config_unavailable"}), 500

    signature = SIGNING_KEY.sign(config_bytes)

    app.logger.info(f"[config] served to {ip} | size={len(config_bytes)} bytes")
    return jsonify({
        "data": base64.b64encode(config_bytes).decode(),
        "signature": base64.b64encode(signature).decode()
    })


@app.route("/api/resolve", methods=["POST"])
@limiter.limit("10 per minute")   # cung muc voi /api/config vi day cung la du lieu nhay cam (IP that)
def resolve():
    """
    Tra IP that dang sau 1 "server_id" logic (KHONG phai domain DNS cong
    khai). Dung LAI y het co che xac thuc cua /api/config: token+package,
    roi device whitelist/blacklist, roi attestation ticket — vi day KHONG
    phai "giai ma", chi la tra cuu co dieu kien (xem giai thich da trao doi):
    ai co token/ticket hop le thi server tra IP, khong co buoc toan hoc nao
    dam bao khong the dao nguoc ca. Do do phai bao ve dau vao (token/ticket)
    chat che nhu /api/config, khong duoc long leo hon.
    """
    data   = request.get_json(force=True, silent=True) or {}
    token  = data.get("token", "")
    pkg    = data.get("pkg",   "")
    server_id = data.get("server_id", "")
    ticket_result    = data.get("attestation_ticket_result", "")
    ticket_signature = data.get("attestation_ticket_signature", "")
    device_id = data.get("device_id", "")
    ip     = request.remote_addr

    app.logger.info(f"[resolve] {ip} | pkg={pkg} | server_id={server_id} | device_id={device_id or '(rong)'}")

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[resolve] DENIED from {ip}: {reason}")
        return jsonify({"error": reason}), 403

    if not server_id:
        return jsonify({"error": "thieu_server_id"}), 400

    if _is_device_whitelisted(device_id):
        app.logger.info(f"[resolve] BYPASS attestation (whitelisted device_id={device_id}) {ip}")
    elif _is_device_blacklisted(device_id):
        app.logger.warning(f"[resolve] DENIED (blacklisted) device_id={device_id} {ip}")
        return jsonify({"error": "device_blacklisted_root_detected"}), 403
    else:
        ticket_ok, ticket_reason, ticket_payload = _verify_attestation_ticket(
            ticket_result, ticket_signature, pkg, device_id)
        if not ticket_ok:
            if ticket_reason == "device_not_attested" and ticket_payload is not None:
                _record_blocked_device(
                    device_id, ip, pkg,
                    ticket_payload.get("verified_boot_state"),
                    ticket_payload.get("device_locked"),
                    ticket_payload.get("package_ok"),
                    ticket_payload.get("sig_ok"),
                )
            app.logger.warning(f"[resolve] DENIED (attestation) from {ip}: {ticket_reason} | device_id={device_id or '(rong)'}")
            return jsonify({"error": ticket_reason}), 403

    entry = _get_resolve_server(server_id)
    if entry is None:
        # KHONG phan biet "khong ton tai" voi "bi disable" trong response —
        # tranh lo thong tin cho ke do server_id de tim entry that.
        app.logger.warning(f"[resolve] server_id khong ton tai/disabled: {server_id} ({ip})")
        return jsonify({"error": "server_id_not_found"}), 404

    _log_resolve_lookup(server_id, device_id, ip)

    app.logger.info(f"[resolve] served {server_id} -> {entry['ip']} to {ip}")
    return jsonify({
        "server_id": server_id,
        "ip": entry["ip"],
        "port": entry.get("port"),
        "expires_in": CACHE_TTL,
    })


@app.route("/api/events", methods=["GET"])
def events():
    token = request.args.get("token", "")
    pkg   = request.args.get("pkg",   "")
    ip    = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[events] reject {ip}: {reason}")
        status = 503 if reason == "server_not_configured" else 401
        return jsonify({"error": reason}), status

    app.logger.info(f"[events] {ip} connected | pkg={pkg}")
    q = _sse_add()

    def generate():
        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            _sse_remove(q)
            app.logger.info(f"[events] {ip} disconnected")

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/health", methods=["GET"])
def health():
    token_set  = os.path.exists(TOKEN_FILE) and _read_token() != ""
    gh_set     = os.path.exists(GITHUB_TOKEN_FILE) and os.path.exists(GITHUB_REPO_FILE)
    config_set = os.path.exists(CONFIG_DATA_FILE)
    with _sse_lock:
        connected = len(_sse_clients)
    resolve_servers = _load_resolve_servers()
    return jsonify({
        "status": "ok",
        "token_configured": token_set,
        "github_configured": gh_set,
        "config_cache_exists": config_set,
        "package": _get_package(),
        "cache_ttl_seconds": CACHE_TTL,
        "github_fetch_ttl_seconds": GITHUB_FETCH_TTL,
        "sse_connections": connected,
        "resolve_servers_configured": len(resolve_servers),
        "resolve_servers_enabled": sum(1 for v in resolve_servers.values() if v.get("enabled", True)),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
