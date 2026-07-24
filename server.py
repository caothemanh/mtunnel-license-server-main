#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging, os, time, json, queue, threading, base64, hmac, secrets, urllib.request, urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

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
TOKEN_FILE        = os.path.join(INSTALL_DIR, ".token")          # token admin cũ (giữ lại, xem ghi chú dưới)
TOKENS_DIR        = os.path.join(INSTALL_DIR, ".tokens")         # MỚI: mỗi file = 1 token đã cấp cho 1 lượt cài app
CONFIG_FILE       = os.path.join(INSTALL_DIR, ".config")
CONFIG_DATA_FILE  = os.path.join(INSTALL_DIR, ".config_data.json")
SIGNING_KEY_FILE  = os.path.join(INSTALL_DIR, ".signing_key")
GITHUB_TOKEN_FILE = os.path.join(INSTALL_DIR, ".github_token")
GITHUB_REPO_FILE  = os.path.join(INSTALL_DIR, ".github_repo")

os.makedirs(TOKENS_DIR, exist_ok=True)

CACHE_TTL        = 3600
GITHUB_FETCH_TTL = 60

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
    Kiểm tra package name — vẫn giữ, chặn app khác package gọi vào.
    KHÔNG còn kiểm tra token ở đây nữa — token giờ xử lý riêng bằng
    _is_valid_token()/_issue_new_token() bên dưới, vì cần phân biệt
    "token hợp lệ" (đã cấp trước) và "chưa có token, cần cấp mới"
    (khác với trước đây: không có token = luôn từ chối).
    """
    valid_package = _get_package()
    if not valid_package:
        return False, "server_not_configured"
    if pkg != valid_package:
        return False, "wrong_package"
    return True, None

def _is_valid_token(token):
    """Token hợp lệ = có file tương ứng trong TOKENS_DIR (chưa bị revoke)."""
    if not token:
        return False
    # Chặn path traversal — token chỉ được chứa ký tự an toàn cho tên file
    if "/" in token or ".." in token or len(token) > 128:
        return False
    token_file = os.path.join(TOKENS_DIR, token)
    return os.path.isfile(token_file)

def _issue_new_token():
    """Sinh 1 token ngẫu nhiên thật (không tính từ APK/chữ ký gì cả),
    lưu lại để lần sau app dùng lại đúng token này."""
    new_token = secrets.token_urlsafe(32)   # ~256 bit entropy, không đoán được
    token_file = os.path.join(TOKENS_DIR, new_token)
    with open(token_file, "w") as f:
        f.write(str(int(time.time())))   # lưu thời điểm cấp, tiện audit/dọn dẹp sau này
    return new_token

def _revoke_token(token):
    """Xóa 1 token cụ thể — chỉ thiết bị/lượt cài đó bị ảnh hưởng,
    không như trước đây (đổi 1 token chung = revoke TOÀN BỘ app)."""
    token_file = os.path.join(TOKENS_DIR, token)
    if os.path.isfile(token_file):
        os.remove(token_file)
        return True
    return False

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

    ok, reason = _check_auth(token, pkg)   # chỉ check package, không check token nữa
    if not ok:
        app.logger.warning(f"[verify] FAILED from {ip}: {reason}")
        return jsonify({"valid": False, "reason": reason})

    issued_new_token = None
    if not _is_valid_token(token):
        issued_new_token = _issue_new_token()
        app.logger.info(f"[verify] Cap token moi cho {ip}: {issued_new_token[:8]}...")

    expire_at = int(time.time()) + CACHE_TTL
    app.logger.info(f"[verify] PASS | expire_at={expire_at}")
    response = {"valid": True, "expire_at": expire_at}
    if issued_new_token:
        response["new_token"] = issued_new_token   # app PHẢI lưu lại giá trị này, dùng cho các lần gọi sau
    return jsonify(response)


@app.route("/api/config", methods=["POST"])
@limiter.limit("10 per minute")   # chặt hơn /api/verify vì đây là nơi lộ Servers array
def get_config():
    data  = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg   = data.get("pkg",   "")
    ip    = request.remote_addr

    app.logger.info(f"[config] {ip} | pkg={pkg} | token={token[:8]}...")

    ok, reason = _check_auth(token, pkg)   # chỉ check package, không check token nữa
    if not ok:
        app.logger.warning(f"[config] DENIED from {ip}: {reason}")
        return jsonify({"error": reason}), 403

    issued_new_token = None
    if not _is_valid_token(token):
        # Lần đầu (chưa có token) HOẶC token cũ đã bị revoke — cấp token mới,
        # KHÔNG từ chối request — vẫn trả config luôn trong CÙNG 1 lần gọi,
        # tránh app phải gọi thêm 1 round-trip riêng chỉ để "đăng ký".
        issued_new_token = _issue_new_token()
        app.logger.info(f"[config] Cap token moi cho {ip}: {issued_new_token[:8]}...")

    config_bytes = _get_config_bytes()
    if config_bytes is None:
        app.logger.error("[config] Khong co config nao kha dung (GitHub loi + chua co cache local)")
        return jsonify({"error": "config_unavailable"}), 500

    signature = SIGNING_KEY.sign(config_bytes)

    app.logger.info(f"[config] served to {ip} | size={len(config_bytes)} bytes")
    response = {
        "data": base64.b64encode(config_bytes).decode(),
        "signature": base64.b64encode(signature).decode()
    }
    if issued_new_token:
        response["new_token"] = issued_new_token   # app PHẢI lưu lại giá trị này (Keystore), dùng cho lần gọi sau
    return jsonify(response)


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
    try:
        issued_tokens_count = len(os.listdir(TOKENS_DIR))
    except:
        issued_tokens_count = 0
    gh_set     = os.path.exists(GITHUB_TOKEN_FILE) and os.path.exists(GITHUB_REPO_FILE)
    config_set = os.path.exists(CONFIG_DATA_FILE)
    with _sse_lock:
        connected = len(_sse_clients)
    return jsonify({
        "status": "ok",
        "issued_tokens_count": issued_tokens_count,
        "github_configured": gh_set,
        "config_cache_exists": config_set,
        "package": _get_package(),
        "cache_ttl_seconds": CACHE_TTL,
        "github_fetch_ttl_seconds": GITHUB_FETCH_TTL,
        "sse_connections": connected,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
