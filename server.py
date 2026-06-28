#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response, stream_with_context
import logging, os, time, json, queue, threading

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

INSTALL_DIR  = "/opt/mtunnel"
TOKEN_FILE   = os.path.join(INSTALL_DIR, ".token")
CONFIG_FILE  = os.path.join(INSTALL_DIR, ".config")

CACHE_TTL = 3600

# ══════════════════════════════════════════════════════════════
# SSE CLIENT REGISTRY
# ══════════════════════════════════════════════════════════════
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()

def _sse_add() -> queue.Queue:
    q = queue.Queue(maxsize=10)
    with _sse_lock:
        _sse_clients.append(q)
    return q

def _sse_remove(q: queue.Queue):
    with _sse_lock:
        if q in _sse_clients:
            _sse_clients.remove(q)

def _sse_push_all(action: str, **kwargs):
    payload = json.dumps({"action": action, **kwargs})
    with _sse_lock:
        clients = list(_sse_clients)
    for q in clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass

# ══════════════════════════════════════════════════════════════
# TOKEN FILE WATCHER
# Tự động push "revoke" khi admin đổi token qua mtunnel-token
# ══════════════════════════════════════════════════════════════
_last_token = ""

def _watch_token():
    global _last_token
    _last_token = _read_token()
    app.logger.info(f"[watcher] started, token={_last_token[:8]}...")

    while True:
        time.sleep(2)  # check mỗi 2 giây
        try:
            current = _read_token()
            if current and current != _last_token:
                app.logger.info(f"[watcher] token changed → pushing revoke to all clients")
                _last_token = current
                _sse_push_all("revoke")
        except Exception as e:
            app.logger.error(f"[watcher] error: {e}")

# Khởi động watcher thread khi server start
_watcher = threading.Thread(target=_watch_token, daemon=True, name="token-watcher")
_watcher.start()

# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    except:
        return ""

def _get_package() -> str:
    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                if line.startswith("PACKAGE="):
                    return line.strip().split("=", 1)[1]
    except:
        return ""

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

    valid_token   = _read_token()
    valid_package = _get_package()

    if not valid_token:
        return jsonify({"valid": False, "reason": "server_not_configured"})

    if pkg != valid_package:
        app.logger.warning(f"[verify] wrong package: {pkg}")
        return jsonify({"valid": False, "reason": "wrong_package"})

    if token != valid_token:
        app.logger.warning(f"[verify] invalid token from {ip}")
        return jsonify({"valid": False, "reason": "invalid_token"})

    expire_at = int(time.time()) + CACHE_TTL
    app.logger.info(f"[verify] PASS | expire_at={expire_at}")
    return jsonify({"valid": True, "expire_at": expire_at})


@app.route("/api/events", methods=["GET"])
def events():
    """
    SSE endpoint — app giữ kết nối tại đây.
    Khi admin đổi token qua mtunnel-token → tất cả app nhận "revoke" ngay.
    """
    token = request.args.get("token", "")
    pkg   = request.args.get("pkg",   "")
    ip    = request.remote_addr

    # Xác thực trước khi cho kết nối SSE
    valid_token   = _read_token()
    valid_package = _get_package()

    if not valid_token:
        return jsonify({"error": "server_not_configured"}), 503

    if pkg != valid_package or token != valid_token:
        app.logger.warning(f"[events] reject {ip}")
        return jsonify({"error": "unauthorized"}), 401

    app.logger.info(f"[events] {ip} connected | pkg={pkg}")
    q = _sse_add()

    def generate():
        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Heartbeat — giữ kết nối qua NAT/firewall
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
            "X-Accel-Buffering": "no",  # Tắt buffer Nginx
        }
    )


@app.route("/health", methods=["GET"])
def health():
    token_set = os.path.exists(TOKEN_FILE) and _read_token() != ""
    with _sse_lock:
        connected = len(_sse_clients)
    return jsonify({
        "status": "ok",
        "token_configured": token_set,
        "package": _get_package(),
        "cache_ttl_seconds": CACHE_TTL,
        "sse_connections": connected,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
