import argparse, json, secrets
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Buat token USB dongle SecureVault")
    parser.add_argument("--path", required=True, help="Root flashdisk/mount point, contoh E:/ atau /media/user/USB")
    args = parser.parse_args()
    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Mount point tidak ditemukan: {root}")
    target = root / "dongle.json"
    if target.exists():
        raise SystemExit(f"{target} sudah ada. Hapus manual jika memang ingin membuat token baru.")
    payload = {"app": "SecureVault", "version": 1, "token": secrets.token_urlsafe(48)}
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Dongle SecureVault berhasil dibuat: {target}")
    print("Jangan membagikan atau menyalin dongle.json.")

if __name__ == "__main__":
    main()
