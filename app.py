from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import os
import json

app = Flask(__name__)
DUMP_DIR  = 'dumps'
os.makedirs(DUMP_DIR, exist_ok=True)

@app.route('/')
def index():
    return 'Izumi.exe is online...'

@app.route('/dump', methods=['POST', 'PUT'])
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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))