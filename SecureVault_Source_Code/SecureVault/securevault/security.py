import os, json, hashlib, secrets, base64, string
from pathlib import Path
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        return False

def derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())

def dongle_candidates():
    # Search common mounted volumes; no arbitrary filesystem-wide scan.
    roots = []
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            p = Path(f"{letter}:/")
            if p.exists():
                roots.append(p)
    else:
        for parent in (Path("/media"), Path("/mnt"), Path("/run/media")):
            if parent.exists():
                try:
                    roots.extend(x for x in parent.iterdir() if x.is_dir())
                except PermissionError:
                    pass
        roots.extend([Path("/Volumes") / x.name for x in Path("/Volumes").glob("*")] if Path("/Volumes").exists() else [])
    for root in roots:
        f = root / "dongle.json"
        if f.is_file():
            try:
                obj = json.loads(f.read_text(encoding="utf-8"))
                if obj.get("app") == "SecureVault" and obj.get("token"):
                    yield str(f), obj["token"]
            except Exception:
                continue

def find_dongle():
    return next(dongle_candidates(), (None, None))

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def encrypt_aes_gcm(data: bytes, key: bytes, aad: bytes = b"SecureVault-v1"):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, aad)
    return nonce, ciphertext

def decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"SecureVault-v1"):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

def vigenere_encrypt(text: str, key: str) -> str:
    key = "".join(c for c in key.upper() if c in string.ascii_uppercase)
    if not key:
        raise ValueError("Kunci Vigenere harus memiliki huruf A-Z.")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[j % len(key)]) - ord('A')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)

def vigenere_decrypt(text: str, key: str) -> str:
    key = "".join(c for c in key.upper() if c in string.ascii_uppercase)
    if not key:
        raise ValueError("Kunci Vigenere harus memiliki huruf A-Z.")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[j % len(key)]) - ord('A')
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)

def encrypt_text(plaintext: str, password: str):
    salt = os.urandom(16)
    aes_key = derive_key(password, salt)
    vig_key = secrets.token_hex(8).upper()
    classical = vigenere_encrypt(plaintext, vig_key)
    package = json.dumps({"vigenere": classical, "key": vig_key},
                         ensure_ascii=False).encode("utf-8")
    nonce, ciphertext = encrypt_aes_gcm(package, aes_key, b"SecureVault-text-v1")
    return salt, nonce, ciphertext

def decrypt_text(salt: bytes, nonce: bytes, ciphertext: bytes, password: str):
    aes_key = derive_key(password, salt)
    package = json.loads(decrypt_aes_gcm(nonce, ciphertext, aes_key,
                                         b"SecureVault-text-v1").decode("utf-8"))
    return vigenere_decrypt(package["vigenere"], package["key"])

def encrypt_file(file_bytes: bytes, password: str) -> bytes:
    if isinstance(file_bytes, tuple):
        file_bytes = file_bytes[0]
    if not isinstance(file_bytes, (bytes, bytearray)):
        file_bytes = bytes(file_bytes)

    salt = os.urandom(16)
    raw_key = derive_key(password, salt)
    fernet_key = base64.urlsafe_b64encode(raw_key)
    fernet = Fernet(fernet_key)
    ciphertext = fernet.encrypt(bytes(file_bytes))
    return b"SVFILE1" + salt + ciphertext

def decrypt_file(encrypted_bytes: bytes, password: str) -> bytes:
    if isinstance(encrypted_bytes, tuple):
        encrypted_bytes = encrypted_bytes[0]
    if not isinstance(encrypted_bytes, (bytes, bytearray)):
        encrypted_bytes = bytes(encrypted_bytes)

    if not encrypted_bytes.startswith(b"SVFILE1") or len(encrypted_bytes) < 23:
        raise ValueError("Format file SecureVault tidak valid.")
    salt = encrypted_bytes[7:23]
    ciphertext = encrypted_bytes[23:]
    raw_key = derive_key(password, salt)
    fernet_key = base64.urlsafe_b64encode(raw_key)
    fernet = Fernet(fernet_key)
    return fernet.decrypt(ciphertext)
