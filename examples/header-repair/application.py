"""Controlled qualification fixture, intentionally missing the nosniff header."""
import os
from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/')
def index():
    return jsonify(status='ok')


@app.route('/health')
def health():
    return jsonify(status='healthy')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.getenv('FIXTURE_PORT', '5066')), debug=False)
