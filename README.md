# ProjekKriptografi

# SecureVault
Aplikasi demonstrasi pengamanan pesan dan dokumen untuk tugas akhir Kriptografi.
Dibangun dengan Python, Streamlit, SQLite, AES-GCM, Vigenere, LSB steganography,
bcrypt, OpenCV LBPH, USB dongle berbasis file-token, dan hash-chain blockchain sederhana.

## Fitur
- USB dongle: hanya drive removable yang dipindai; token diikat ke serial number flashdisk, jadi salinan `dongle.json` di flashdisk lain ditolak.
- Autentikasi dua tahap: (1) wajah via OpenCV LBPH, (2) password bcrypt.
- Password: hash bcrypt untuk verifikasi; Scrypt untuk derivasi kunci enkripsi.
- Pesan teks: Vigenere (klasik) lalu AES-256-GCM (modern).
- File: ChaCha20-Poly1305 (kunci dari Scrypt); algoritma berbeda dari enkripsi teks.
- Gambar: LSB steganography untuk menyisipkan payload pesan terenkripsi ke PNG.
- Blockchain: ledger lokal berantai SHA-256 untuk memeriksa integritas catatan aset.
- Database SQLite: akun, pesan teks, dan catatan blockchain.

## Persyaratan
- Python 3.10–3.12 disarankan.
- Webcam untuk autentikasi wajah.
- Flashdisk untuk USB dongle.
- Windows/macOS/Linux. Webcam dan deteksi mount USB bergantung izin sistem operasi.

## Instalasi di VS Code
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Menyiapkan USB dongle
1. Colokkan flashdisk.
2. Temukan huruf drive (Windows, misalnya `E:`) atau mount point (Linux/macOS).
3. Jalankan:
```bash
python setup_dongle.py --path E:/
```
Ganti `E:/` dengan mount point flashdisk. Skrip membuat `dongle.json` di root flashdisk.
4. Simpan flashdisk tersebut. Saat aplikasi berjalan, SecureVault mencari `dongle.json`
   pada drive yang terpasang. Saat pendaftaran pertama, token dongle didaftarkan ke database.

**Catatan keamanan:** dongle ini adalah mekanisme demonstrasi berbasis token pada USB, bukan
secure element atau kunci hardware yang anti-kloning. Salinan file token dapat meniru dongle.
Untuk produksi, gunakan FIDO2/security key atau smartcard dengan kunci non-exportable.

## Menjalankan
```bash
python -m streamlit run app.
```
Buka alamat lokal yang ditampilkan Streamlit.

## Alur pertama kali
1. Pasang USB dongle.
2. Buka menu **Daftar akun**.
3. Buat username dan password.
4. Daftarkan wajah dengan mengunggah 3–5 foto wajah yang jelas (bisa diambil dari webcam/ponsel).
5. Login menggunakan username, password, dan verifikasi wajah melalui kamera.
6. Setelah login, gunakan menu Pesan Teks, File, Steganografi, dan Blockchain.

## Penjelasan implementasi keamanan
- bcrypt hanya menyimpan verifier password (salt ada di dalam hash); password asli tidak disimpan.
- Kunci AES diturunkan dari password menggunakan Scrypt dengan salt unik per akun.
- Teks: Vigenere menghasilkan lapisan klasik, kemudian AES-GCM mengenkripsi paket yang berisi
  ciphertext Vigenere dan kuncinya. AES-GCM memberikan kerahasiaan dan autentikasi integritas.
- File: ChaCha20-Poly1305 langsung mengenkripsi byte file, dengan salt dan nonce tersimpan bersama ciphertext.
- Steganografi: payload terenkripsi disisipkan pada bit paling rendah kanal RGB gambar. Gunakan PNG
  agar data tidak rusak oleh kompresi JPEG.
- Blockchain: setiap blok mengandung hash blok sebelumnya dan hash data. Ini adalah simulasi
  hash-chain terpusat, bukan blockchain terdistribusi dengan konsensus.

## Keterbatasan dan pengujian
- LBPH adalah biometrik wajah berbasis komputer visi sederhana, bukan sistem identitas bersertifikasi.
  Hasil dipengaruhi pencahayaan, sudut, kualitas kamera, dan ambang confidence.
- Wajah bukan pengganti password. Keduanya diwajibkan saat login.
- Jangan gunakan data pribadi/sensitif sungguhan untuk demonstrasi kelas.
- Database lokal dan file model wajah perlu dilindungi oleh keamanan akun sistem operasi.
- Dongle diperiksa pada setiap interaksi (Streamlit menjalankan ulang skrip); jika USB dicabut,
  aplikasi berhenti pada halaman pemeriksaan dongle.
