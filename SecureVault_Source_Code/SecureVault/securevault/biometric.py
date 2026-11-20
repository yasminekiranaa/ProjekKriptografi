from pathlib import Path
import cv2
import numpy as np

def _detector():
    local_cascade = Path(__file__).parent / "haarcascade_frontalface_default.xml"
    if local_cascade.exists():
        cascade_path = str(local_cascade)
    else:
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        
    detector = cv2.CascadeClassifier(cascade_path)
    if detector.empty():
        raise RuntimeError("Model Haar Cascade tidak dapat dimuat.")
    return detector

def _face_array(image_bytes):
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Gambar tidak dapat dibaca.")
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    faces = _detector().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(80,80))
    if len(faces) == 0:
        raise ValueError("Wajah tidak terdeteksi. Coba foto dengan pencahayaan cukup dan wajah menghadap kamera.")
    x,y,w,h = max(faces, key=lambda r: r[2]*r[3])
    crop = gray[y:y+h, x:x+w]
    return cv2.resize(crop, (160,160))

def train_face_model(image_bytes_list, model_path: Path):
    if not hasattr(cv2, "face"):
        raise RuntimeError("Modul cv2.face tidak tersedia. Pastikan opencv-contrib-python terpasang, bukan opencv-python.")
    faces = [_face_array(b) for b in image_bytes_list]
    if len(faces) < 3:
        raise ValueError("Unggah minimal 3 foto wajah untuk pendaftaran.")
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.train(faces, np.array([1] * len(faces), dtype=np.int32))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    recognizer.write(str(model_path))

def verify_face(image_bytes, model_path: Path, threshold=75.0):
    if not hasattr(cv2, "face"):
        raise RuntimeError("Modul cv2.face tidak tersedia. Instal opencv-contrib-python.")
    if not model_path.exists():
        return False, "Data biometrik belum terdaftar."
    face = _face_array(image_bytes)
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.read(str(model_path))
    label, confidence = recognizer.predict(face)
    ok = label == 1 and confidence <= threshold
    return ok, f"Skor kecocokan: {confidence:.1f} (ambang {threshold:.1f})"