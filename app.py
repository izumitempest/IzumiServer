from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import os
import json
import jwt
from functools import wraps

SECRET_KEY = os.getenv('SECRET_KEY', 'FromThe104WeSurveyTheOtherSideOfTheSea')

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
    data = request.get_json(force=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d, %H-%M-%S')
    filename = f'dump-{timestamp}.json'
    filepath = os.path.join(DUMP_DIR, filename)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
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