#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging, os, time, json, queue, threading, base64, hmac, urllib.request, urllib.error

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
DEX_HASHES_FILE   = os.path.join(INSTALL_DIR, ".dex_hashes.json")


CACHE_TTL        = 3600
GITHUB_FETCH_TTL = 60
DEX_NONCE_TTL    = 60   # nonce phải được dùng trong 60s, dùng 1 lần rồi bỏ
ATTESTATION_NONCE_TTL       = 60
ATTESTATION_ROOT_CACHE_TTL  = 86400   # 24h — danh sách root Google ít khi đổi
                                        # (nhưng CÓ đổi, như đợt rotate 4/2026,
                                        # nên KHÔNG hardcode cứng, luôn fetch lại
                                        # định kỳ thay vì fix 1 lần rồi thôi)
GOOGLE_ATTESTATION_ROOT_URL = "https://android.googleapis.com/attestation/root"

# nonce đang "sống" (đã phát cho app, chưa được app dùng để verify)
# -> chống replay: 1 nonce chỉ đổi lấy được 1 câu trả lời đã ký duy nhất.
_dex_nonces = {}
_dex_nonce_lock = threading.Lock()

_attestation_nonces = {}
_attestation_nonce_lock = threading.Lock()

_attestation_roots_cache = {"certs": [], "fetched_at": 0}
_attestation_roots_lock = threading.Lock()

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
            # KHÔNG validate bằng json.loads() ở đây — nội dung thật là
            # ciphertext (AESCrypt.encrypt() từ Gen tool), không phải JSON
            # thô, nên json.loads() luôn fail dù tải về đúng. Server chỉ
            # cần coi đây là bytes bất kỳ để ký, không quan tâm định dạng.
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
            return f.read()
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


def _load_dex_hashes():
    """
    File .dex_hashes.json chứa danh sách các combined-hash HỢP LỆ hiện tại,
    ví dụ khi đang rollout bản mới thì để cả hash bản cũ + bản mới cùng lúc:
      {"allowed": ["<sha256 hex bản 1.0.3>", "<sha256 hex bản 1.0.4>"]}
    Combined-hash = sha256(nối các sha256 của từng classes*.dex, đã sort tên file),
    tính bằng script build-time (xem compute_dex_hash.py), KHÔNG tính trên server.
    """
    try:
        with open(DEX_HASHES_FILE, "r") as f:
            return json.load(f).get("allowed", [])
    except:
        return []

def _dex_nonce_cleanup():
    now = time.time()
    with _dex_nonce_lock:
        for n in [n for n, exp in _dex_nonces.items() if exp < now]:
            del _dex_nonces[n]

@app.route("/api/dex-challenge", methods=["POST"])
@limiter.limit("30 per minute")
def dex_challenge():
    data  = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg   = data.get("pkg",   "")
    ip    = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        # DEBUG TẠM THỜI — in token rút gọn (an toàn, không lộ toàn bộ) để
        # so sánh trực tiếp với token đang hoạt động ở /api/config. XOÁ
        # dòng debug_token này sau khi tìm ra nguyên nhân.
        debug_token = (token[:8] + "...") if token else "(RỖNG)"
        app.logger.warning(f"[dex-challenge] DENIED {ip}: {reason} | token_nhan_duoc={debug_token} | pkg_nhan_duoc={pkg or '(RỖNG)'}")
        return jsonify({"error": reason}), 403

    _dex_nonce_cleanup()
    nonce = base64.urlsafe_b64encode(os.urandom(24)).decode()
    with _dex_nonce_lock:
        _dex_nonces[nonce] = time.time() + DEX_NONCE_TTL

    return jsonify({"nonce": nonce, "expires_in": DEX_NONCE_TTL})


@app.route("/api/dex-verify", methods=["POST"])
@limiter.limit("30 per minute")
def dex_verify():
    data     = request.get_json(force=True, silent=True) or {}
    token    = data.get("token", "")
    pkg      = data.get("pkg",   "")
    nonce    = data.get("nonce", "")
    dex_hash = data.get("dex_hash", "")
    ip       = request.remote_addr

    ok, reason = _check_auth(token, pkg)
    if not ok:
        app.logger.warning(f"[dex-verify] AUTH FAILED {ip}: {reason}")
        return jsonify({"valid": False, "reason": reason})

    # Nonce phải tồn tại + chưa hết hạn + CHỈ dùng được đúng 1 lần (pop luôn)
    with _dex_nonce_lock:
        expire_at = _dex_nonces.pop(nonce, None)
    if expire_at is None or expire_at < time.time():
        app.logger.warning(f"[dex-verify] REJECT {ip}: bad_or_reused_or_expired_nonce")
        return jsonify({"valid": False, "reason": "bad_or_expired_nonce"})

    allowed  = _load_dex_hashes()
    is_valid = any(hmac.compare_digest(dex_hash, h) for h in allowed) if dex_hash else False

    # Ký kết quả (không chỉ trả true/false thô) — app verify chữ ký bằng
    # đúng public key Ed25519 đã pin sẵn (giống luồng /api/config), nên
    # kẻ tấn công có full quyền trên máy (root) chặn được response ở tầng
    # transport vẫn KHÔNG tự chế được response "valid=true" hợp lệ nếu
    # không có private key trên server. nonce được nhúng lại vào payload
    # để app đối chiếu đúng câu hỏi nó vừa hỏi, chặn replay 1 response cũ.
    result_payload = {"valid": is_valid, "nonce": nonce, "ts": int(time.time())}
    message = json.dumps(result_payload, sort_keys=True, separators=(",", ":")).encode()
    signature = SIGNING_KEY.sign(message)

    if is_valid:
        app.logger.info(f"[dex-verify] OK {ip} | pkg={pkg}")
    else:
        app.logger.warning(f"[dex-verify] MISMATCH {ip} | pkg={pkg} | got={dex_hash[:16] if dex_hash else '(empty)'}...")

    return jsonify({
        "result": base64.b64encode(message).decode(),
        "signature": base64.b64encode(signature).decode()
    })


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


# ══════════════════════════════════════════════════════════════
# MINI DER PARSER — chỉ đủ dùng để đọc cấu trúc KeyDescription
# (extension Key Attestation, OID 1.3.6.1.4.1.11129.2.1.17), KHÔNG phải
# 1 parser ASN.1 tổng quát. Xem cấu trúc đầy đủ tại:
# https://source.android.com/docs/security/features/keystore/attestation
# ══════════════════════════════════════════════════════════════

KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
ROOT_OF_TRUST_TAG   = 704   # context tag [704] EXPLICIT trong AuthorizationList


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

    raw = ext.value.value   # UnrecognizedExtension.value = DER bytes thô của KeyDescription SEQUENCE

    top_items = _der_read_sequence_items(raw)
    # KeyDescription ::= SEQUENCE { attestationVersion, attestationSecurityLevel,
    #   keymasterVersion, keymasterSecurityLevel, attestationChallenge,
    #   uniqueId, softwareEnforced, teeEnforced }
    if len(top_items) < 8:
        raise AttestationParseError("key_description_thieu_truong")

    attestation_challenge = top_items[4][3]
    tee_enforced_content = top_items[7][3]
    tee_items = _der_read_sequence_items(tee_enforced_content)

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
    }


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

    root_der = certs[-1].public_bytes(Encoding.DER)
    is_trusted = any(root_der == g.public_bytes(Encoding.DER) for g in google_roots)
    if not is_trusted:
        return False, "root_khong_khop_google", None

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
    is_valid = (parsed["verified_boot_state"] == 0) and parsed["device_locked"]

    result_payload = {
        "valid": is_valid,
        "pkg": pkg,
        "verified_boot_state": parsed["verified_boot_state"],
        "device_locked": parsed["device_locked"],
        "challenge": challenge_b64,
        "ts": int(time.time()),
    }
    message = json.dumps(result_payload, sort_keys=True, separators=(",", ":")).encode()
    signature = SIGNING_KEY.sign(message)

    if is_valid:
        app.logger.info(f"[attestation-verify] OK {ip} | pkg={pkg}")
    else:
        app.logger.warning(
            f"[attestation-verify] NOT_VERIFIED {ip} | pkg={pkg} | "
            f"boot_state={parsed['verified_boot_state']} | locked={parsed['device_locked']}")

    return jsonify({
        "result": base64.b64encode(message).decode(),
        "signature": base64.b64encode(signature).decode(),
    })


ATTESTATION_TICKET_MAX_AGE = 300   # 5 phút — vé attestation cũ hơn mức này bị coi là hết hạn
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


def _verify_attestation_ticket(ticket_result_b64: str, ticket_signature_b64: str, expected_pkg: str):
    """
    Verify 1 "vé" attestation (payload đã ký từ /api/attestation-verify).
    Trả về (True, None) nếu vé hợp lệ VÀ thiết bị đã attest thành công
    (payload["valid"]==True), ngược lại (False, reason).
    """
    if not ticket_result_b64 or not ticket_signature_b64:
        return False, "thieu_attestation_ticket"

    try:
        message = base64.b64decode(ticket_result_b64)
        signature = base64.b64decode(ticket_signature_b64)
    except Exception:
        return False, "ticket_base64_sai"

    try:
        SIGNING_KEY.public_key().verify(signature, message)
    except InvalidSignature:
        return False, "ticket_chu_ky_sai"
    except Exception as e:
        return False, f"ticket_loi_verify:{e}"

    try:
        payload = json.loads(message.decode())
    except Exception:
        return False, "ticket_payload_khong_phai_json"

    if payload.get("pkg") != expected_pkg:
        return False, "ticket_sai_package"

    ticket_age = time.time() - payload.get("ts", 0)
    if ticket_age > ATTESTATION_TICKET_MAX_AGE or ticket_age < -10:
        return False, "ticket_het_han"

    if not payload.get("valid", False):
        return False, "device_not_attested"

    return True, None


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
    else:
        # Config chỉ được trả nếu kèm 1 vé Key Attestation còn hạn, đúng pkg,
        # và server tự verify chữ ký (KHÔNG tin app tự khai báo gì cả) — đây
        # mới là điểm ép buộc thật, không phải 1 check nằm rời rạc trong app.
        ticket_ok, ticket_reason = _verify_attestation_ticket(ticket_result, ticket_signature, pkg)
        if not ticket_ok:
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
    return jsonify({
        "status": "ok",
        "token_configured": token_set,
        "github_configured": gh_set,
        "config_cache_exists": config_set,
        "package": _get_package(),
        "cache_ttl_seconds": CACHE_TTL,
        "github_fetch_ttl_seconds": GITHUB_FETCH_TTL,
        "sse_connections": connected,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
