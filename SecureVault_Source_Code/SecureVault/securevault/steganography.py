from PIL import Image
import io, struct
from .security import derive_key, encrypt_aes_gcm, decrypt_aes_gcm

MAGIC = b"SVLT"

def hide_message(image_bytes: bytes, message: str, password: str) -> bytes:
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = bytearray(image.tobytes())
    salt = __import__("os").urandom(16)
    key = derive_key(password, salt)
    nonce, ciphertext = encrypt_aes_gcm(message.encode("utf-8"), key, b"SecureVault-stego-v1")
    payload = MAGIC + salt + nonce + struct.pack(">I", len(ciphertext)) + ciphertext
    bits = []
    for byte in payload:
        bits.extend((byte >> i) & 1 for i in range(7, -1, -1))
    if len(bits) > len(pixels):
        raise ValueError(f"Gambar terlalu kecil. Kapasitas bit tidak cukup; perlu sekitar {len(bits)} kanal piksel.")
    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & 0xFE) | bit
    out = Image.frombytes("RGB", image.size, bytes(pixels))
    buffer = io.BytesIO()
    out.save(buffer, format="PNG")
    return buffer.getvalue()

def extract_message(image_bytes: bytes, password: str) -> str:
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = image.tobytes()
    def read_bytes(start, count):
        out = bytearray()
        for n in range(count):
            value = 0
            for bit in range(8):
                value = (value << 1) | (pixels[(start+n*8+bit)] & 1)
            out.append(value)
        return bytes(out)
    header = read_bytes(0, 4+16+12+4)
    if header[:4] != MAGIC:
        raise ValueError("Penanda SecureVault tidak ditemukan pada gambar.")
    salt, nonce = header[4:20], header[20:32]
    length = struct.unpack(">I", header[32:36])[0]
    total = 36 + length
    if total * 8 > len(pixels):
        raise ValueError("Payload gambar tidak lengkap atau rusak.")
    payload = read_bytes(0, total)
    key = derive_key(password, salt)
    plaintext = decrypt_aes_gcm(nonce, payload[36:], key, b"SecureVault-stego-v1")
    return plaintext.decode("utf-8")
