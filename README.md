# MTunnel License Server

Server xác thực bản quyền cho app MTunnel Android.  
Hỗ trợ **SSE (Server-Sent Events)** — server push lệnh `revoke`, `extend`, `update_config` xuống app theo thời gian thực mà không tốn tài nguyên.

## Cài đặt nhanh (1 lệnh)

```bash
bash <(curl -s https://raw.githubusercontent.com/caothemanh/mtunnel-license-server-main/main/install.sh)
```

Script tự động:
- Cài Python, Nginx, Gunicorn + Gevent
- Cấp SSL miễn phí (Let's Encrypt)
- Tạo systemd service (tự khởi động cùng server)
- Mở giao diện nhập token ngay sau khi cài

## Yêu cầu

- Ubuntu 20.04 / 22.04
- Domain đã trỏ A record về IP server
- Cổng 80 và 443 mở

## Đổi token sau khi cài

```bash
mtunnel-token
```

## Lệnh quản lý

```bash
# Xem trạng thái
systemctl status mtunnel-license

# Xem log realtime
journalctl -u mtunnel-license -f

# Restart service
systemctl restart mtunnel-license

# Kiểm tra server + số app đang kết nối SSE
curl https://your-domain.com/health
```

## Endpoints

| Method | Path | Mô tả |
|--------|------|--------|
| POST | `/api/verify` | App gọi khi khởi động để xác thực license |
| GET  | `/api/events` | App giữ kết nối SSE để nhận push từ server |
| POST | `/api/admin/revoke` | Admin thu hồi license → app bị kill ngay |
| POST | `/api/admin/extend` | Admin gia hạn license |
| POST | `/api/admin/config` | Admin push config mới (URL, ...) |
| GET  | `/health` | Kiểm tra trạng thái server |

## Admin API

Tất cả admin API dùng `admin_key` = server token (xem trong `/opt/mtunnel/.token`).

### Thu hồi license (kill app ngay)

```bash
# Revoke 1 app cụ thể
curl -X POST https://your-domain.com/api/admin/revoke \
  -H "Content-Type: application/json" \
  -d '{"admin_key":"TOKEN_SERVER","token":"TOKEN_APP"}'

# Revoke tất cả app đang kết nối
curl -X POST https://your-domain.com/api/admin/revoke \
  -H "Content-Type: application/json" \
  -d '{"admin_key":"TOKEN_SERVER","token":""}'
```

### Gia hạn license

```bash
curl -X POST https://your-domain.com/api/admin/extend \
  -H "Content-Type: application/json" \
  -d '{"admin_key":"TOKEN_SERVER","token":"TOKEN_APP","seconds":86400}'
```

### Push config mới

```bash
curl -X POST https://your-domain.com/api/admin/config \
  -H "Content-Type: application/json" \
  -d '{"admin_key":"TOKEN_SERVER","config":{"verify_url":"https://new-domain.com/api/verify"}}'
```

## Cập nhật app Android

Sau khi cài, cập nhật `getVerifyUrl()` trong native layer trỏ về:

```
https://your-domain.com/api/verify
```

SSE endpoint (app tự build từ verify URL):

```
https://your-domain.com/api/events
```

## Kiến trúc SSE

```
App khởi động
  │
  ├─► POST /api/verify        → xác thực, nhận expire_at
  │
  └─► GET  /api/events        → giữ kết nối (daemon thread)
          │
          ◄── : ping           (heartbeat 25s, giữ NAT)
          ◄── data: {"action":"revoke"}
          ◄── data: {"action":"extend","expire_at":...}
          ◄── data: {"action":"update_config","config":...}
```

Kết nối SSE idle gần như không tốn CPU/pin — chỉ 1 TCP connection duy trì.  
Tự reconnect với exponential backoff (5s → 10s → ... → 5 phút) khi mất mạng.
