import os, hashlib, uuid, threading, io
from flask import Blueprint, request, jsonify, send_file
from database.db import get_db
from crypto.encryption import encrypt_file, decrypt_file
from blockchain.web3_client import store_hash, is_blockchain_available
from routes.auth_routes import get_current_user

file_bp = Blueprint('files', __name__)
STORAGE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'storage')
os.makedirs(STORAGE_DIR, exist_ok=True)

def _require_login():
    u = get_current_user()
    if not u: return jsonify({'success':False,'message':'Authentication required.'}),401
    return None

def _sha256(data): return hashlib.sha256(data).hexdigest()

def _store_bg(file_id, file_hash):
    try:
        tx = store_hash(file_hash)
        db = get_db()
        db.execute('UPDATE files SET tx_hash=? WHERE id=?',(tx,file_id))
        db.commit(); db.close()
        print(f'TX stored: {tx}')
    except Exception as e: print(f'Blockchain error: {e}')

@file_bp.route('/upload', methods=['POST'])
def upload():
    err = _require_login()
    if err: return err
    if 'file' not in request.files: return jsonify({'success':False,'message':'No file.'}),400
    f = request.files['file']
    if not f.filename: return jsonify({'success':False,'message':'Empty filename.'}),400
    raw = f.read()
    enc, key = encrypt_file(raw)
    fhash = _sha256(enc)
    sname = f'{uuid.uuid4().hex}_{f.filename}.enc'
    fpath = os.path.join(STORAGE_DIR, sname)
    open(fpath,'wb').write(enc)
    user = get_current_user()
    db = get_db()
    cur = db.execute('INSERT INTO files (owner_username,original_name,stored_name,file_path,blockchain_hash,aes_key_hex) VALUES (?,?,?,?,?,?)',(user,f.filename,sname,fpath,fhash,key))
    fid = cur.lastrowid; db.commit(); db.close()
    if is_blockchain_available():
        threading.Thread(target=_store_bg,args=(fid,fhash),daemon=True).start()
        tx = 'PENDING - storing on Sepolia...'
    else: tx = 'BLOCKCHAIN_OFFLINE'
    return jsonify({'success':True,'message':'File uploaded, encrypted and stored on blockchain.','file_hash':fhash,'tx_hash':tx,'blockchain':True})

@file_bp.route('/list', methods=['GET'])
def list_files():
    err = _require_login()
    if err: return err
    user = get_current_user(); db = get_db()
    owned = db.execute('SELECT id,original_name,blockchain_hash,uploaded_at FROM files WHERE owner_username=?',(user,)).fetchall()
    shared = db.execute('SELECT f.id,f.original_name,f.blockchain_hash,f.uploaded_at,fp.granted_by FROM files f JOIN file_permissions fp ON f.id=fp.file_id WHERE fp.granted_to=?',(user,)).fetchall()
    db.close()
    return jsonify({'success':True,'owned':[dict(r) for r in owned],'shared':[dict(r) for r in shared]})

@file_bp.route('/download/<int:file_id>', methods=['GET'])
def download(file_id):
    err = _require_login()
    if err: return err
    user = get_current_user(); db = get_db()
    row = db.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone(); db.close()
    if not row: return jsonify({'success':False,'message':'File not found.'}),404
    if row['owner_username'] != user:
        db = get_db()
        perm = db.execute('SELECT 1 FROM file_permissions WHERE file_id=? AND granted_to=?',(file_id,user)).fetchone(); db.close()
        if not perm: return jsonify({'success':False,'message':'Access denied.'}),403
    try:
        enc = open(row['file_path'],'rb').read()
        from crypto.encryption import decrypt_file
        orig = decrypt_file(enc, row['aes_key_hex'])
    except FileNotFoundError: return jsonify({'success':False,'message':'File missing.'}),500
    except ValueError as e: return jsonify({'success':False,'message':str(e)}),500
    return send_file(io.BytesIO(orig),as_attachment=True,download_name=row['original_name'],mimetype='application/octet-stream')

@file_bp.route('/verify/<int:file_id>', methods=['GET'])
def verify(file_id):
    err = _require_login()
    if err: return err
    user = get_current_user(); db = get_db()
    row = db.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone(); db.close()
    if not row: return jsonify({'success':False,'message':'File not found.'}),404
    try: cur = _sha256(open(row['file_path'],'rb').read())
    except FileNotFoundError: return jsonify({'success':False,'message':'File missing.'}),500
    return jsonify({'success':True,'integrity_ok':cur==row['blockchain_hash'],'stored_hash':row['blockchain_hash'],'current_hash':cur,'message':'File verified.' if cur==row['blockchain_hash'] else 'File tampered!'})

@file_bp.route('/share', methods=['POST'])
def share():
    err = _require_login()
    if err: return err
    data = request.get_json(silent=True) or {}
    fid = data.get('file_id'); to = data.get('share_to','').strip()
    if not fid or not to: return jsonify({'success':False,'message':'file_id and share_to required.'}),400
    user = get_current_user(); db = get_db()
    row = db.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone()
    if not row: db.close(); return jsonify({'success':False,'message':'File not found.'}),404
    if row['owner_username']!=user: db.close(); return jsonify({'success':False,'message':'Only owner can share.'}),403
    if not db.execute('SELECT 1 FROM users WHERE username=?',(to,)).fetchone(): db.close(); return jsonify({'success':False,'message':f'User not found.'}),404
    try: db.execute('INSERT INTO file_permissions(file_id,granted_to,granted_by) VALUES(?,?,?)',(fid,to,user)); db.commit()
    except: db.close(); return jsonify({'success':False,'message':'Already shared.'}),409
    db.close(); return jsonify({'success':True,'message':f'Shared with {to}.'})

@file_bp.route('/revoke', methods=['DELETE'])
def revoke():
    err = _require_login()
    if err: return err
    data = request.get_json(silent=True) or {}
    fid = data.get('file_id'); rfrom = data.get('revoke_from','').strip()
    if not fid or not rfrom: return jsonify({'success':False,'message':'file_id and revoke_from required.'}),400
    user = get_current_user(); db = get_db()
    row = db.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone()
    if not row: db.close(); return jsonify({'success':False,'message':'File not found.'}),404
    if row['owner_username']!=user: db.close(); return jsonify({'success':False,'message':'Only owner can revoke.'}),403
    db.execute('DELETE FROM file_permissions WHERE file_id=? AND granted_to=?',(fid,rfrom)); db.commit(); db.close()
    return jsonify({'success':True,'message':f'Access revoked for {rfrom}.'})
