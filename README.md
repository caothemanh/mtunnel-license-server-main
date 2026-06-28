# MTunnel License Server

Server xác thực bản quyền cho app MTunnel Android.  
Hỗ trợ **SSE (Server-Sent Events)** — khi admin đổi token, tất cả app nhận lệnh `revoke` và bị kill ngay lập tức.

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

## Cách hoạt động

```
App khởi động
  │
  ├─► POST /api/verify   → xác thực token, nhận expire_at
  │
  └─► GET  /api/events   → giữ kết nối SSE (daemon thread)
            │
            ◄── : ping               (heartbeat 25s)
            ◄── data: {"action":"revoke"}   ← khi admin đổi token
```

Khi admin chạy `mtunnel-token` để đổi token mới:
- Server detect thay đổi trong vòng 2 giây
- Push `revoke` tới **tất cả app** đang kết nối
- App bị kill ngay lập tức
- App dùng token mới vẫn hoạt động bình thường

## Thu hồi toàn bộ app

```bash
mtunnel-token
# Nhập token mới → tất cả app bị kill ngay
```

## Lệnh quản lý

```bash
# Đổi token (thu hồi tất cả app ngay lập tức)
mtunnel-token

# Xem trạng thái + số app đang kết nối SSE
curl https://your-domain.com/health

# Xem log realtime
journalctl -u mtunnel-license -f

# Restart service
systemctl restart mtunnel-license
```

## Endpoints

| Method | Path | Mô tả |
|--------|------|--------|
| POST | `/api/verify` | App gọi khi khởi động để xác thực |
| GET  | `/api/events` | App giữ kết nối SSE để nhận push |
| GET  | `/health` | Trạng thái server + số kết nối SSE |
