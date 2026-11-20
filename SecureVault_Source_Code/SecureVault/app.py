import streamlit as st
import hashlib, os, io
from pathlib import Path
from securevault import db
from securevault.config import BIOMETRIC_DIR
from securevault.security import (find_dongle, token_digest, hash_password, verify_password,
                                  encrypt_text, decrypt_text, encrypt_file, decrypt_file)
from securevault.biometric import train_face_model, verify_face
from securevault.steganography import hide_message, extract_message

st.set_page_config(page_title="SecureVault", page_icon="🔐", layout="wide")
db.init_db()

st.markdown("""
<style>
.stApp {background: #0b1220; color: #e8eef8;}
[data-testid="stSidebar"] {background: #111c30;}
.hero {padding: 1.4rem 1.6rem; border: 1px solid #263b5c; border-radius: 18px;
background: linear-gradient(120deg,#142744,#172033); margin-bottom: 1rem;}
.hero h1 {color:#f4f8ff; margin:0;} .hero p {color:#a9bdd8; margin:.3rem 0 0;}
div.stButton>button {border-radius:10px;}
.small-muted {color:#9db0c9;font-size:.9rem;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🔐 SecureVault</h1><p>Secure document & message protection · Cryptography final project</p></div>', unsafe_allow_html=True)

dongle_path, dongle_token = find_dongle()
if not dongle_token:
    st.error("USB dongle tidak ditemukan. Colokkan flashdisk SecureVault yang berisi dongle.json, lalu muat ulang aplikasi.")
    st.info("Jika belum memiliki dongle, lihat petunjuk di README.md dan jalankan setup_dongle.py.")
    st.stop()

if "user" not in st.session_state:
    st.session_state.user = None
if "password_for_session" not in st.session_state:
    st.session_state.password_for_session = None
if "reg_cam_photos" not in st.session_state:
    st.session_state.reg_cam_photos = []

def register_page():
    st.subheader("Daftar akun SecureVault")
    st.caption(f"Dongle terdeteksi: {Path(dongle_path).parent}")

    st.markdown("#### Ambil foto wajah lewat kamera (minimal 3 foto)")
    cam_shot = st.camera_input("Ambil foto wajah", key="reg_camera")
    c_add, c_clear = st.columns(2)
    with c_add:
        if st.button("Simpan foto dari kamera", use_container_width=True, disabled=(cam_shot is None)):
            if cam_shot is not None:
                st.session_state.reg_cam_photos.append(cam_shot.getvalue())
                st.rerun()
    with c_clear:
        if st.button("Hapus foto kamera", use_container_width=True, disabled=(len(st.session_state.reg_cam_photos) == 0)):
            st.session_state.reg_cam_photos = []
            st.rerun()

    st.caption(f"Jumlah foto kamera tersimpan: {len(st.session_state.reg_cam_photos)} / minimal 3")
    if st.session_state.reg_cam_photos:
        st.image(
            st.session_state.reg_cam_photos,
            width=120,
            caption=[f"Foto #{i+1}" for i in range(len(st.session_state.reg_cam_photos))],
        )

    with st.form("register"):
        username = st.text_input("Username", max_chars=32)
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Konfirmasi password", type="password")
        uploaded_photos = st.file_uploader(
            "Atau unggah file foto wajah tambahan (opsional jika sudah cukup dari kamera)",
            type=["jpg", "jpeg", "png"],
            accept_multiple_files=True,
        )
        submit = st.form_submit_button("Daftar akun", use_container_width=True)

    if submit:
        all_photo_bytes = list(st.session_state.reg_cam_photos)
        for p in (uploaded_photos or []):
            all_photo_bytes.append(p.getvalue())

        if not username.strip() or len(password) < 8:
            st.error("Username wajib diisi dan password minimal 8 karakter.")
        elif password != confirm:
            st.error("Konfirmasi password tidak sama.")
        elif len(all_photo_bytes) < 3:
            st.error("Minimal 3 foto wajah diperlukan (dari kamera dan/atau unggahan).")
        elif db.get_user(username.strip()):
            st.error("Username sudah digunakan.")
        else:
            model_path = BIOMETRIC_DIR / (hashlib.sha256(username.strip().encode()).hexdigest() + ".yml")
            try:
                train_face_model(all_photo_bytes, model_path)
                db.create_user(
                    username.strip(),
                    hash_password(password),
                    os.urandom(16),
                    token_digest(dongle_token),
                    str(model_path),
                )
                st.session_state.reg_cam_photos = []
                st.success("Pendaftaran berhasil. Silakan masuk menggunakan verifikasi wajah dan password.")
            except Exception as e:
                if model_path.exists():
                    model_path.unlink()
                st.error(f"Pendaftaran gagal: {e}")

def login_page():
    st.subheader("Login dua tahap")
    st.caption("Tahap 1: verifikasi biometrik wajah · Tahap 2: password hash")
    username = st.text_input("Username", key="login_user")
    face_photo = st.camera_input("Ambil foto wajah untuk verifikasi")
    password = st.text_input("Password", type="password", key="login_pass")
    if st.button("Login", type="primary", use_container_width=True):
        user = db.get_user(username.strip())
        if not user:
            st.error("Username tidak ditemukan atau kredensial salah.")
            return
        if token_digest(dongle_token) != user["dongle_hash"]:
            st.error("USB dongle tidak sesuai dengan dongle saat pendaftaran.")
            return
        if face_photo is None:
            st.warning("Ambil foto wajah terlebih dahulu.")
            return
        # Tahap 1: Verifikasi biometrik wajah terlebih dahulu
        try:
            ok, detail = verify_face(face_photo.getvalue(), Path(user["face_model"]))
            if not ok:
                st.error("Verifikasi wajah gagal. " + detail)
                return
        except Exception as e:
            st.error(f"Verifikasi biometrik gagal: {e}")
            return
        # Tahap 2: Verifikasi password hash setelah wajah valid
        if not verify_password(password, user["password_hash"]):
            st.error("Password salah.")
            return
        st.session_state.user = {"id": user["id"], "username": user["username"]}
        st.session_state.password_for_session = password
        st.success("Login berhasil.")
        st.rerun()

if not st.session_state.user:
    t1, t2 = st.tabs(["Login", "Daftar akun"])
    with t1: login_page()
    with t2: register_page()
    st.stop()

user = st.session_state.user
password = st.session_state.password_for_session
with st.sidebar:
    st.markdown(f"### 👤 {user['username']}")
    st.caption("USB dongle aktif")
    page = st.radio("Navigasi", ["Dashboard", "Pesan Teks", "Enkripsi File", "Steganografi Gambar", "Blockchain", "Riwayat Pesan"])
    if st.button("Keluar", use_container_width=True):
        st.session_state.user = None
        st.session_state.password_for_session = None
        st.rerun()

if page == "Dashboard":
    st.subheader("Dashboard")
    messages = db.list_messages(user["id"])
    blocks = db.get_blocks(user["id"])
    c1, c2, c3 = st.columns(3)
    c1.metric("Pesan terenkripsi", len(messages))
    c2.metric("Blok blockchain", len(blocks))
    c3.metric("Status USB", "Aktif")
    st.markdown("#### Modul keamanan")
    cols = st.columns(2)
    modules = [("🔤", "Super Enkripsi Teks", "Vigenere + AES-256-GCM"),
               ("📁", "Enkripsi File", "Fernet (AES-128-CBC + HMAC)"),
               ("🖼️", "Steganografi", "LSB + AES-256-GCM"),
               ("⛓️", "Blockchain", "SHA-256 hash chain")]
    for col, item in zip(cols * 2, modules):
        with col:
            st.info(f"{item[0]} **{item[1]}**\n\n{item[2]}")
    st.caption("Gunakan data uji. Jangan menyimpan dokumen pribadi atau rahasia sungguhan pada versi demonstrasi.")

elif page == "Pesan Teks":
    st.subheader("Super Enkripsi Pesan Teks")
    st.write("Lapisan 1: Vigenere (klasik). Lapisan 2: AES-256-GCM (modern).")
    with st.form("text_encrypt"):
        label = st.text_input("Judul pesan", "Pesan rahasia")
        plaintext = st.text_area("Pesan yang akan dienkripsi", height=150)
        go = st.form_submit_button("Enkripsi dan simpan")
    if go:
        if plaintext.strip():
            salt, nonce, ciphertext = encrypt_text(plaintext, password)
            db.save_message(user["id"], label.strip() or "Pesan", "Vigenere + AES-256-GCM", salt, nonce, ciphertext)
            st.success("Pesan berhasil dienkripsi dan disimpan ke SQLite.")
        else:
            st.warning("Pesan tidak boleh kosong.")
    st.divider()
    st.markdown("#### Dekripsi pesan tersimpan")
    rows = db.list_messages(user["id"])
    if rows:
        choices = {f"#{r['id']} · {r['label']} · {r['created_at']}": r["id"] for r in rows}
        selected = st.selectbox("Pilih pesan", list(choices))
        if st.button("Dekripsi pesan"):
            row = db.get_message(choices[selected], user["id"])
            try:
                plain = decrypt_text(row["salt"], row["nonce"], row["ciphertext"], password)
                st.text_area("Hasil dekripsi", plain, height=150)
            except Exception:
                st.error("Dekripsi gagal. Password salah atau data telah berubah.")
    else:
        st.info("Belum ada pesan tersimpan.")

elif page == "Enkripsi File":
    st.subheader("Enkripsi dan Dekripsi File")
    st.write("File dienkripsi dengan Fernet (berbeda dari skema super enkripsi teks).")
    uploaded = st.file_uploader("Pilih file untuk dienkripsi")
    if uploaded and st.button("Enkripsi file"):
        try:
            package = encrypt_file(uploaded.getvalue(), password)
            st.download_button(
                "Unduh file terenkripsi",
                package,
                file_name=uploaded.name + ".svault",
                mime="application/octet-stream",
            )
            st.success("File berhasil dienkripsi. Simpan file .svault dan jangan lupa password.")
        except Exception as e:
            st.error(f"Gagal mengenkripsi file: {e}")

    st.divider()
    encrypted = st.file_uploader("Pilih file .svault untuk dekripsi", type=None, key="decrypt_file")
    if encrypted and st.button("Dekripsi file"):
        blob = encrypted.getvalue()
        try:
            plain = decrypt_file(blob, password)
            original = encrypted.name[:-7] if encrypted.name.endswith(".svault") else "hasil_dekripsi.bin"
            st.download_button("Unduh file asli", plain, file_name=original)
            st.success("File berhasil didekripsi.")
        except Exception:
            st.error("Dekripsi gagal. Password salah atau file rusak.")

elif page == "Steganografi Gambar":
    st.subheader("Steganografi Gambar (LSB)")
    st.write("Pesan dienkripsi AES-GCM terlebih dahulu, lalu disisipkan pada bit paling rendah kanal RGB. Gunakan PNG.")
    mode = st.radio("Pilih proses", ["Sisipkan pesan", "Ekstrak pesan"], horizontal=True)
    image_file = st.file_uploader("Unggah gambar PNG/JPG", type=["png", "jpg", "jpeg"], key="stego_image")
    if image_file and mode == "Sisipkan pesan":
        message = st.text_area("Pesan rahasia")
        if st.button("Sisipkan dan buat PNG"):
            try:
                result = hide_message(image_file.getvalue(), message, password)
                st.image(result, caption="Gambar dengan pesan tersembunyi")
                st.download_button("Unduh gambar PNG", result, "securevault_stego.png", "image/png")
            except Exception as e:
                st.error(f"Gagal: {e}")
    elif image_file and mode == "Ekstrak pesan":
        if st.button("Ekstrak pesan"):
            try:
                st.success("Pesan berhasil diekstrak.")
                st.text_area("Pesan hasil ekstraksi", extract_message(image_file.getvalue(), password), height=140)
            except Exception as e:
                st.error(f"Gagal mengekstrak: {e}")

elif page == "Blockchain":
    st.subheader("Blockchain Sederhana untuk Aset Penting")
    st.write("Aplikasi menyimpan hash aset dan menghubungkan setiap blok dengan hash blok sebelumnya.")
    asset = st.file_uploader("Pilih aset/file untuk dicatat")
    if asset and st.button("Catat aset ke blockchain"):
        digest = hashlib.sha256(asset.getvalue()).hexdigest()
        block_hash = db.add_block(user["id"], asset.name, digest)
        st.success(f"Aset tercatat. Hash blok: {block_hash}")
    if st.button("Verifikasi integritas blockchain"):
        ok, detail = db.verify_chain(user["id"])
        (st.success if ok else st.error)(detail)
    blocks = db.get_blocks(user["id"])
    if blocks:
        st.markdown("#### Ledger")
        for b in blocks:
            with st.expander(f"Blok #{b['id']} · {b['asset_name']}"):
                st.code(f"Asset SHA-256: {b['asset_digest']}\nPrevious hash: {b['previous_hash']}\nBlock hash: {b['block_hash']}")

elif page == "Riwayat Pesan":
    st.subheader("Riwayat Pesan Terenkripsi")
    rows = db.list_messages(user["id"])
    if rows:
        st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
    else:
        st.info("Belum ada riwayat pesan.")
