#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response, stream_with_context
import logging, os, time, json, queue, threading

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

INSTALL_DIR   = "/opt/mtunnel"
TOKEN_FILE    = os.path.join(INSTALL_DIR, ".token")
CONFIG_FILE   = os.path.join(INSTALL_DIR, ".config")

# Cache expire time tính bằng giây (mặc định 1h)
CACHE_TTL = 3600

# ══════════════════════════════════════════════════════════════
# SSE CLIENT REGISTRY
# token → list of Queue (mỗi kết nối SSE là 1 queue)
# ══════════════════════════════════════════════════════════════
_sse_clients: dict[str, list[queue.Queue]] = {}
_sse_lock = threading.Lock()

def _sse_add(token: str) -> queue.Queue:
    q = queue.Queue(maxsize=10)
    with _sse_lock:
        _sse_clients.setdefault(token, []).append(q)
    return q

def _sse_remove(token: str, q: queue.Queue):
    with _sse_lock:
        buckets = _sse_clients.get(token, [])
        if q in buckets:
            buckets.remove(q)
        if not buckets:
            _sse_clients.pop(token, None)

def sse_push(token: str, action: str, **kwargs):
    """Push 1 event tới tất cả kết nối SSE của token đó."""
    payload = json.dumps({"action": action, **kwargs})
    with _sse_lock:
        buckets = list(_sse_clients.get(token, []))
    for q in buckets:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass  # client chậm, bỏ qua

def sse_push_all(action: str, **kwargs):
    """Push event tới TẤT CẢ token đang kết nối (ví dụ: broadcast update_config)."""
    payload = json.dumps({"action": action, **kwargs})
    with _sse_lock:
        all_queues = [q for buckets in _sse_clients.values() for q in buckets]
    for q in all_queues:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass

# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def get_token():
    try:
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    except:
        return ""

def get_package():
    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                if line.startswith("PACKAGE="):
                    return line.strip().split("=", 1)[1]
    except:
        return ""

def is_valid_request(token: str, pkg: str) -> tuple[bool, str]:
    """Trả về (valid, reason)."""
    valid_token   = get_token()
    valid_package = get_package()
    if not valid_token:
        return False, "server_not_configured"
    if pkg != valid_package:
        return False, "wrong_package"
    if token != valid_token:
        return False, "invalid_token"
    return True, ""

# ══════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.route("/api/verify", methods=["POST"])
def verify():
    data  = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    pkg   = data.get("pkg",   "")
    ip    = request.remote_addr

    app.logger.info(f"[verify] {ip} | pkg={pkg} | token={token[:8]}...")

    valid, reason = is_valid_request(token, pkg)
    if not valid:
        app.logger.warning(f"[verify] FAIL reason={reason}")
        return jsonify({"valid": False, "reason": reason})

    expire_at = int(time.time()) + CACHE_TTL
    app.logger.info(f"[verify] PASS expire_at={expire_at}")
    return jsonify({"valid": True, "expire_at": expire_at})


@app.route("/api/events", methods=["GET"])
def events():
    """
    SSE endpoint — app Android giữ kết nối tại đây để nhận push từ server.
    GET /api/events?token=xxx&pkg=com.xxx
    """
    token = request.args.get("token", "")
    pkg   = request.args.get("pkg",   "")
    ip    = request.remote_addr

    # Xác thực trước khi cho kết nối SSE
    valid, reason = is_valid_request(token, pkg)
    if not valid:
        app.logger.warning(f"[events] reject {ip} reason={reason}")
        return jsonify({"error": reason}), 401

    app.logger.info(f"[events] {ip} connected | pkg={pkg}")
    q = _sse_add(token)

    def generate():
        try:
            while True:
                try:
                    # Chờ event tối đa 25s, sau đó gửi heartbeat
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Heartbeat — giữ kết nối qua NAT/firewall/nginx proxy
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            _sse_remove(token, q)
            app.logger.info(f"[events] {ip} disconnected")

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Tắt buffer Nginx — quan trọng!
        }
    )


@app.route("/api/admin/revoke", methods=["POST"])
def admin_revoke():
    """
    Admin push lệnh revoke tới app đang kết nối.
    POST /api/admin/revoke
    Body: { "admin_key": "...", "token": "..." }  (token để revoke; bỏ trống = tất cả)
    """
    data      = request.get_json(force=True, silent=True) or {}
    admin_key = data.get("admin_key", "")
    target    = data.get("token", "")  # rỗng = broadcast

    # Dùng chính server token làm admin key (đơn giản, không cần file riêng)
    if admin_key != get_token():
        return jsonify({"ok": False, "reason": "forbidden"}), 403

    if target:
        sse_push(target, "revoke")
        app.logger.info(f"[admin] revoke → token={target[:8]}...")
    else:
        sse_push_all("revoke")
        app.logger.info("[admin] revoke → ALL clients")

    return jsonify({"ok": True})


@app.route("/api/admin/extend", methods=["POST"])
def admin_extend():
    """
    Admin gia hạn license cho 1 token.
    Body: { "admin_key": "...", "token": "...", "seconds": 86400 }
    """
    data      = request.get_json(force=True, silent=True) or {}
    admin_key = data.get("admin_key", "")
    target    = data.get("token", "")
    seconds   = int(data.get("seconds", CACHE_TTL))

    if admin_key != get_token():
        return jsonify({"ok": False, "reason": "forbidden"}), 403

    new_expire = int(time.time()) + seconds
    sse_push(target, "extend", expire_at=new_expire)
    app.logger.info(f"[admin] extend → token={target[:8]}... expire_at={new_expire}")
    return jsonify({"ok": True, "expire_at": new_expire})


@app.route("/api/admin/config", methods=["POST"])
def admin_config():
    """
    Admin push config mới tới toàn bộ app đang kết nối.
    Body: { "admin_key": "...", "config": { "base_url": "...", "verify_url": "..." } }
    """
    data      = request.get_json(force=True, silent=True) or {}
    admin_key = data.get("admin_key", "")
    config    = data.get("config", {})

    if admin_key != get_token():
        return jsonify({"ok": False, "reason": "forbidden"}), 403

    sse_push_all("update_config", config=json.dumps(config))
    app.logger.info(f"[admin] update_config → {config}")
    return jsonify({"ok": True})


@app.route("/health", methods=["GET"])
def health():
    token_set = os.path.exists(TOKEN_FILE) and get_token() != ""
    with _sse_lock:
        connected = sum(len(v) for v in _sse_clients.values())
    return jsonify({
        "status": "ok",
        "token_configured": token_set,
        "package": get_package(),
        "cache_ttl_seconds": CACHE_TTL,
        "sse_connections": connected,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
