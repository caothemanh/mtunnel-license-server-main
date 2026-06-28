# MTunnel License Server

Server xác thực bản quyền cho app MTunnel Android.

## Cài đặt nhanh (1 lệnh)

```bash
bash <(curl -s https://raw.githubusercontent.com/caothemanh/mtunnel-license-server/main/install.sh)
```

Script sẽ tự động:
- Cài Python, Nginx, Gunicorn
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

# Kiểm tra server
curl https://your-domain.com/health
```

## Cập nhật LicenseChecker.java trong app

```java
private static final String VERIFY_URL = "https://your-domain.com/api/verify";
```
