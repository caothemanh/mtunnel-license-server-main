# MTunnel License Server

Server xác thực bản quyền cho app MTunnel Android.
Hỗ trợ **SSE (Server-Sent Events)** — khi admin đổi token, tất cả app nhận lệnh `revoke` và bị kill ngay lập tức.
Hỗ trợ **đồng bộ file config từ GitHub**, được ký bằng **Ed25519** để app verify tính toàn vẹn trước khi dùng.

## Cài đặt nhanh (1 lệnh)

```bash
bash <(curl -s https://raw.githubusercontent.com/caothemanh/mtunnel-license-server-main/main/install.sh)
```

Script tự động:
- Cài Python, Nginx, Gunicorn + Gevent, cryptography
- Cấp SSL miễn phí (Let's Encrypt), tự chuyển sang port **8443** nếu port 443 đã bị chiếm (vd bởi `psiphond`)
- Tạo systemd service (tự khởi động cùng server)
- Hỏi (tùy chọn) thông tin GitHub repo + Personal Access Token để bật `/api/config`
- Tạo signing key Ed25519, in ra `SERVER_PUBLIC_KEY_B64` và `PINNED_PUBKEY_SHA256` để nhúng vào app Android
- Mở giao diện nhập token ngay sau khi cài

## Yêu cầu

- Ubuntu 20.04 / 22.04
- Domain đã trỏ A record về IP server
- Cổng 80 mở (dùng cho challenge SSL); nếu port 443 bị chiếm, script tự đổi HTTPS sang port 8443
- (Tùy chọn) Một GitHub repo chứa file config đã mã hoá + Personal Access Token có quyền đọc repo, nếu muốn dùng `/api/config`

## Cách hoạt động

```
App khởi động
  │
  ├─► POST /api/verify   → xác thực token, nhận expire_at
  │
  ├─► POST /api/config   → tải config đã mã hoá từ GitHub, kèm chữ ký Ed25519
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

> Lưu ý: server hiện chỉ lưu **một token dùng chung** cho toàn bộ app (không phải mỗi user một token riêng), nên revoke luôn áp dụng cho tất cả kết nối cùng lúc.

## Đồng bộ config từ GitHub (`/api/config`)

Khi cài đặt, script sẽ hỏi (có thể bỏ trống để cấu hình sau):

- **GitHub owner** — chủ sở hữu repo
- **GitHub repo** — tên repo chứa file config
- **Branch** — mặc định `main`
- **Đường dẫn file** trong repo (vd `config.enc`)
- **Personal Access Token (PAT)** — cần quyền đọc nội dung repo

Các giá trị này được lưu vào:

```
/opt/mtunnel/.github_repo    (OWNER=... / REPO=... / BRANCH=... / PATH=...)
/opt/mtunnel/.github_token   (PAT)
```

Nếu bỏ trống lúc cài, `/api/config` sẽ trả lỗi `config_unavailable` (500) cho tới khi bạn tạo thủ công 2 file trên (mỗi file `chmod 600`, chủ sở hữu `www-data`) rồi `systemctl restart mtunnel-license`.

Server tải file này (dạng bytes bất kỳ, không cần là JSON — vì bản thân file là ciphertext đã mã hoá sẵn), cache 60 giây, sau đó ký bằng khoá Ed25519 riêng của server và trả về cho app dạng:

```json
{
  "data": "<base64 ciphertext>",
  "signature": "<base64 signature>"
}
```

## Hai loại key CẦN PHÂN BIỆT RÕ — nhầm 2 cái này là nguyên nhân phổ biến nhất khiến app không tải được config

Server dùng **2 loại key hoàn toàn khác nhau**, phục vụ 2 mục đích khác nhau. Trộn lẫn chúng (dùng nhầm giá trị của cái này cho cái kia) sẽ khiến app luôn từ chối kết nối hoặc từ chối config dù server hoạt động bình thường:

| | Mục đích | Lệnh xem | Dán vào đâu (Android) |
|---|---|---|---|
| **Ed25519 signing key** | Ký nội dung config (`/api/config`) để app verify tính toàn vẹn | `mtunnel-pubkey` | `SERVER_PUBLIC_KEYS_B64[]` |
| **TLS certificate pin** | Pin chứng chỉ HTTPS khi app mở kết nối tới server | `mtunnel-tlspin` | `PINNED_PUBKEYS_SHA256[]` |

**Lưu ý quan trọng nếu domain đang bật Cloudflare Proxy (orange cloud):**
`mtunnel-tlspin` sẽ **không thể tự tính pin** trên chính VPS, vì client (app) sẽ bắt tay TLS với chứng chỉ của **Cloudflare edge**, không phải chứng chỉ trên VPS. Trong trường hợp này, phải chạy lệnh sau **từ một máy khác** (không phải VPS này, để tránh NAT hairpin cho kết quả sai) sau khi cài xong:

```bash
openssl s_client -connect <domain>:<port> </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Vì chứng chỉ này do Cloudflare quản lý (có thể dùng chung cho nhiều domain trong cùng zone và tự đổi theo chu kỳ renew), nên cần kiểm tra lại định kỳ nếu app đột ngột báo lỗi tải config sau một thời gian hoạt động ổn định.

> Khoá riêng (private key) của signing key nằm ở `/opt/mtunnel/.signing_key`, chỉ `www-data` đọc được (chmod 600) — **không** chia sẻ file này.

## Lệnh quản lý

```bash
# Đổi token (thu hồi tất cả app ngay lập tức)
mtunnel-token

# Xem lại Server Public Key (Ed25519) + pinned SHA256
mtunnel-pubkey

# Xem trạng thái + số app đang kết nối SSE
curl https://your-domain.com:8443/health

# Xem log realtime
journalctl -u mtunnel-license -f

# Restart service
systemctl restart mtunnel-license
```

## Endpoints

| Method | Path | Mô tả |
|--------|------|--------|
| POST | `/api/verify` | App gọi khi khởi động để xác thực |
| POST | `/api/config` | App tải file config đã mã hoá từ GitHub, kèm chữ ký Ed25519 |
| GET  | `/api/events` | App giữ kết nối SSE để nhận push |
| GET  | `/health` | Trạng thái server + số kết nối SSE |

## Giới hạn hiện tại (chưa hỗ trợ)

- Không có API revoke chọn lọc theo từng token — chỉ có thể đổi token dùng chung (thu hồi tất cả).
- `admin_key` (nếu dùng trong tương lai) hiện chưa tách biệt khỏi token app.
