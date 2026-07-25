#!/usr/bin/env python3
"""
Chạy trên máy build SAU KHI ký APK release (v2 signing xong hẳn).

  python3 compute_dex_hash.py app-release.apk

In ra combined SHA-256 hex — dán giá trị này vào .dex_hashes.json trên
server (mảng "allowed"). Trong lúc rollout bản mới, giữ CẢ hash bản cũ
và bản mới trong "allowed" cho tới khi user cũ đã update hết, rồi mới
xoá hash bản cũ đi để thu hồi các APK cài từ bản đó (kể cả bản build
gốc, không bị patch gì) nếu bạn muốn buộc mọi người lên bản mới.

Thuật toán PHẢI khớp 100% với native code (DexIntegrity.cpp):
  1. Liệt kê mọi entry tên "classes.dex", "classes2.dex", ... ở ROOT của APK
  2. Với mỗi entry: SHA-256 trên nội dung đã giải nén (raw dex bytes)
  3. Sort các hash đó theo thứ tự alphabet của TÊN FILE (không phải theo hash)
  4. Nối các hash (dạng bytes, không phải hex) lại theo thứ tự đó
  5. SHA-256 trên chuỗi bytes đã nối -> đây là combined hash cuối cùng
"""
import sys
import zipfile
import hashlib
import re
import json

DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")

def compute_combined_hash(apk_path: str) -> str:
    with zipfile.ZipFile(apk_path, "r") as z:
        dex_entries = [n for n in z.namelist() if DEX_NAME_RE.match(n)]
        if not dex_entries:
            raise SystemExit("Khong tim thay classes*.dex nao trong APK")

        dex_entries.sort()  # sort theo TÊN, phải khớp thứ tự bên native
        per_file_hashes = []
        for name in dex_entries:
            data = z.read(name)
            h = hashlib.sha256(data).digest()
            per_file_hashes.append(h)
            print(f"  {name}: {h.hex()}  ({len(data)} bytes)", file=sys.stderr)

        combined = hashlib.sha256(b"".join(per_file_hashes)).hexdigest()
        return combined

def main():
    if len(sys.argv) < 2:
        print("Usage: compute_dex_hash.py <app-release.apk> [--add-to hashes.json]", file=sys.stderr)
        sys.exit(1)

    apk_path = sys.argv[1]
    combined = compute_combined_hash(apk_path)
    print(combined)

    if "--add-to" in sys.argv:
        idx = sys.argv.index("--add-to")
        hashes_file = sys.argv[idx + 1]
        try:
            with open(hashes_file, "r") as f:
                doc = json.load(f)
        except FileNotFoundError:
            doc = {"allowed": []}

        if combined not in doc.get("allowed", []):
            doc.setdefault("allowed", []).append(combined)
            with open(hashes_file, "w") as f:
                json.dump(doc, f, indent=2)
            print(f"Da them vao {hashes_file}", file=sys.stderr)
        else:
            print(f"Hash da co san trong {hashes_file}", file=sys.stderr)

if __name__ == "__main__":
    main()
