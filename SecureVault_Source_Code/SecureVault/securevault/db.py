import sqlite3, json, hashlib, time
from .config import DB_PATH

def connect():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          password_salt BLOB NOT NULL,
          dongle_hash TEXT NOT NULL,
          face_model TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS encrypted_messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          label TEXT NOT NULL,
          algorithm TEXT NOT NULL,
          salt BLOB NOT NULL,
          nonce BLOB NOT NULL,
          ciphertext BLOB NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS blockchain(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          asset_name TEXT NOT NULL,
          asset_digest TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          block_hash TEXT NOT NULL,
          timestamp REAL NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        con.commit()

def create_user(username, password_hash, password_salt, dongle_hash, face_model):
    with connect() as con:
        con.execute("""INSERT INTO users(username,password_hash,password_salt,dongle_hash,face_model)
                       VALUES(?,?,?,?,?)""",
                    (username, password_hash, password_salt, dongle_hash, face_model))
        con.commit()

def get_user(username):
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def save_message(user_id, label, algorithm, salt, nonce, ciphertext):
    with connect() as con:
        con.execute("""INSERT INTO encrypted_messages(user_id,label,algorithm,salt,nonce,ciphertext)
                       VALUES(?,?,?,?,?,?)""",
                    (user_id, label, algorithm, salt, nonce, ciphertext))
        con.commit()

def list_messages(user_id):
    with connect() as con:
        return con.execute("""SELECT id,label,algorithm,created_at FROM encrypted_messages
                              WHERE user_id=? ORDER BY id DESC""", (user_id,)).fetchall()

def get_message(message_id, user_id):
    with connect() as con:
        return con.execute("""SELECT * FROM encrypted_messages WHERE id=? AND user_id=?""",
                           (message_id, user_id)).fetchone()

def add_block(user_id, asset_name, asset_digest):
    with connect() as con:
        last = con.execute("SELECT block_hash FROM blockchain WHERE user_id=? ORDER BY id DESC LIMIT 1",
                           (user_id,)).fetchone()
        previous = last["block_hash"] if last else "0" * 64
        ts = time.time()
        payload = json.dumps({"user_id": user_id, "asset_name": asset_name,
                              "asset_digest": asset_digest, "previous_hash": previous,
                              "timestamp": ts}, sort_keys=True, separators=(",", ":"))
        block_hash = hashlib.sha256(payload.encode()).hexdigest()
        con.execute("""INSERT INTO blockchain(user_id,asset_name,asset_digest,previous_hash,block_hash,timestamp)
                       VALUES(?,?,?,?,?,?)""",
                    (user_id, asset_name, asset_digest, previous, block_hash, ts))
        con.commit()
        return block_hash

def get_blocks(user_id):
    with connect() as con:
        return con.execute("SELECT * FROM blockchain WHERE user_id=? ORDER BY id",
                           (user_id,)).fetchall()

def verify_chain(user_id):
    blocks = get_blocks(user_id)
    previous = "0" * 64
    for b in blocks:
        payload = json.dumps({"user_id": user_id, "asset_name": b["asset_name"],
                              "asset_digest": b["asset_digest"], "previous_hash": previous,
                              "timestamp": b["timestamp"]}, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if b["previous_hash"] != previous or b["block_hash"] != expected:
            return False, f"Blok #{b['id']} tidak valid"
        previous = b["block_hash"]
    return True, f"{len(blocks)} blok valid"
