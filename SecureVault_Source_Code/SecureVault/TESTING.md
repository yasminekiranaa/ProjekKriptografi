# Skenario Pengujian SecureVault

| ID | Pengujian | Langkah | Hasil yang diharapkan |
|---|---|---|---|
| TC-01 | Dongle tidak terpasang | Jalankan aplikasi tanpa flashdisk | Aplikasi berhenti pada halaman pemeriksaan dongle |
| TC-02 | Dongle valid | Pasang flashdisk terdaftar | Halaman login tampil |
| TC-03 | Password salah | Login dengan password salah | Login ditolak |
| TC-04 | Wajah tidak cocok | Masukkan foto orang berbeda | Login ditolak |
| TC-05 | Enkripsi teks | Simpan teks lalu dekripsi | Teks kembali sama |
| TC-06 | Password dekripsi salah | Dekripsi dengan password salah | Gagal autentikasi AES-GCM |
| TC-07 | Enkripsi file | Enkripsi file uji lalu dekripsi | Byte file hasil sama dengan file awal |
| TC-08 | Steganografi | Sisipkan pesan pada PNG lalu ekstrak | Pesan kembali sama |
| TC-09 | Blockchain | Tambahkan aset lalu verifikasi | Semua blok valid |
| TC-10 | Integritas blockchain | Ubah satu nilai blok di DB uji | Verifikasi mendeteksi perubahan |

## Catatan
Pengujian wajah memerlukan minimal tiga foto enrollment yang konsisten. Uji threshold LBPH
dengan beberapa variasi pencahayaan; threshold 75 adalah nilai awal demonstrasi dan perlu
disesuaikan berdasarkan hasil uji dataset sendiri.
